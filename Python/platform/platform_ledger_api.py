from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from origin_protocol.manifest import Manifest, ORIGIN_VERSION
from origin_protocol.registry import read_registry, is_key_active
from origin_protocol.revocation import read_revocation_list, find_revocations
from origin_protocol.reasons import format_reasons


APP_DIR = Path.home() / ".origin_protocol"
DEFAULT_POLICY_DIR = Path(__file__).resolve().parent / "policies"
DEFAULT_POLICY_INDEX = Path(__file__).resolve().parent / "platform_policies.json"
DEFAULT_PLATFORM_LEDGER = APP_DIR / "platform_ledger.json"
DEFAULT_REGISTRY = APP_DIR / "key_registry.json"
DEFAULT_REVOCATION = APP_DIR / "revocation_list.json"
_BOOTSTRAP_ENV = os.environ.get("ORIGIN_BOOTSTRAP_PATH", "").strip()
DEFAULT_BOOTSTRAP = Path(_BOOTSTRAP_ENV) if _BOOTSTRAP_ENV else Path(__file__).resolve().parent / "bootstrap_v1.json"
DEFAULT_GOVERNANCE_CONFIG = Path(os.environ.get("ORIGIN_GOVERNANCE_CONFIG", str(APP_DIR / "governance_config.json")))
RATE_LIMIT_PER_MIN = int(os.environ.get("ORIGIN_RATE_LIMIT_PER_MIN", "120"))
RATE_LIMIT_WINDOW_SECONDS = 60
API_KEYS_ENV = "ORIGIN_API_KEYS"
API_KEYS_PATH_ENV = "ORIGIN_API_KEYS_PATH"

_RATE_LIMIT_LOCK = threading.Lock()
_RATE_LIMIT_BUCKETS: dict[str, list[float]] = {}


class VerifyRequest(BaseModel):
    creator_id: str = Field(..., min_length=1)
    key_id: str = Field(..., min_length=1)
    asset_id: str = Field(..., min_length=1)
    content_hash: str = Field(..., min_length=1)
    platform_id: str = Field(..., min_length=1)


class ReasonPayload(BaseModel):
    code: str
    message: str
    severity: str
    platform_action: str
    creator_action: str


class VerifyResponse(BaseModel):
    ok: bool
    reasons: list[ReasonPayload]


class KeyStatusResponse(BaseModel):
    ok: bool
    reasons: list[ReasonPayload]
    key_status: str | None = None


class RevocationStatusResponse(BaseModel):
    ok: bool
    reasons: list[ReasonPayload]
    revoked: bool


class PlatformPolicyResponse(BaseModel):
    ok: bool
    policy: dict[str, Any]
    governance: dict[str, Any] | None = None


@dataclass(frozen=True)
class AssetRecord:
    creator_id: str
    key_id: str
    asset_id: str
    content_hash: str
    intended_platforms: tuple[str, ...]
    status: str
    updated_at: str
    origin_version: str = ORIGIN_VERSION


app = FastAPI(title="Origin Platform Ledger API", version="1.0.0")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _reasons_payload(codes: Iterable[str]) -> list[ReasonPayload]:
    formatted = format_reasons(tuple(codes))
    return [
        ReasonPayload(
            code=item.code,
            message=item.message,
            severity=item.severity,
            platform_action=item.platform_action,
            creator_action=item.creator_action,
        )
        for item in formatted
    ]


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_api_keys() -> set[str] | None:
    raw = os.environ.get(API_KEYS_ENV, "").strip()
    keys: set[str] = set()
    if raw:
        keys.update({item.strip() for item in raw.split(",") if item.strip()})
    path_value = os.environ.get(API_KEYS_PATH_ENV, "").strip()
    if path_value:
        path = Path(path_value)
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                value = line.strip()
                if value:
                    keys.add(value)
    return keys or None


def _rate_limit_key(api_key: str | None, request: Request) -> str:
    if api_key:
        return f"key:{api_key}"
    host = request.client.host if request.client else "anonymous"
    return f"ip:{host}"


def _enforce_rate_limit(api_key: str | None, request: Request) -> None:
    if RATE_LIMIT_PER_MIN <= 0:
        return
    now = time.time()
    key = _rate_limit_key(api_key, request)
    with _RATE_LIMIT_LOCK:
        bucket = _RATE_LIMIT_BUCKETS.setdefault(key, [])
        cutoff = now - RATE_LIMIT_WINDOW_SECONDS
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if len(bucket) >= RATE_LIMIT_PER_MIN:
            raise HTTPException(status_code=429, detail="rate_limit_exceeded")
        bucket.append(now)


def _auth_and_rate_limit(
    request: Request,
    api_key: str | None = Header(None, alias="X-Origin-API-Key"),
) -> None:
    keys = _load_api_keys()
    if keys is not None:
        if not api_key or api_key not in keys:
            raise HTTPException(status_code=401, detail="invalid_api_key")
    _enforce_rate_limit(api_key, request)


def _load_asset_records(path: Path) -> tuple[AssetRecord, ...]:
    if not path.exists():
        return tuple()
    payload = _read_json(path)
    records = []
    for item in payload.get("records", []):
        records.append(
            AssetRecord(
                creator_id=item["creator_id"],
                key_id=item["key_id"],
                asset_id=item["asset_id"],
                content_hash=item["content_hash"],
                intended_platforms=tuple(item.get("intended_platforms", [])),
                status=item.get("status", "active"),
                updated_at=item.get("updated_at", payload.get("updated_at", _now_iso())),
                origin_version=item.get("origin_version", ORIGIN_VERSION),
            )
        )
    return tuple(records)


def _find_asset_record(records: tuple[AssetRecord, ...], creator_id: str, asset_id: str) -> AssetRecord | None:
    if not records:
        return None
    for record in records:
        if record.creator_id == creator_id and record.asset_id == asset_id:
            return record
    for record in records:
        if record.asset_id == asset_id:
            return record
    return None


def _load_policy_index() -> dict[str, Any]:
    path = Path(os.environ.get("ORIGIN_PLATFORM_POLICY_PATH", str(DEFAULT_POLICY_INDEX)))
    if not path.exists():
        return {"default_profile": "standard", "platforms": {}}
    return _read_json(path)


def _load_policy_profile(profile: str) -> dict[str, Any]:
    profile_path = Path(os.environ.get("ORIGIN_PLATFORM_POLICY_DIR", str(DEFAULT_POLICY_DIR))) / f"{profile}.json"
    if not profile_path.exists():
        return {
            "profile": profile,
            "require_key_registry": True,
            "require_revocation_check": True,
            "require_platform_match": True,
            "require_key_id_match": True,
            "require_asset_record": True,
        }
    return _read_json(profile_path)


def _resolve_policy(platform_id: str | None) -> dict[str, Any]:
    index = _load_policy_index()
    platforms = index.get("platforms", {})
    default_profile = index.get("default_profile", "standard")
    profile_name = default_profile
    overrides: dict[str, Any] = {}
    if platform_id and platform_id in platforms:
        entry = platforms[platform_id]
        profile_name = entry.get("profile", profile_name)
        overrides = entry.get("overrides", {})
    policy = _load_policy_profile(profile_name)
    policy.update(overrides)
    policy.setdefault("profile", profile_name)
    return policy


def _read_governance_config() -> dict[str, Any] | None:
    config_path = Path(os.environ.get("ORIGIN_GOVERNANCE_CONFIG", str(DEFAULT_GOVERNANCE_CONFIG)))
    if not config_path.exists():
        return None
    payload = _read_json(config_path)
    return {
        "nodes": payload.get("nodes", []),
        "gateways": payload.get("gateways", []),
    }


def _read_bootstrap() -> dict[str, Any] | None:
    bootstrap_path = Path(DEFAULT_BOOTSTRAP)
    if not bootstrap_path.exists():
        return None
    try:
        return _read_json(bootstrap_path)
    except Exception:
        return None


def _build_manifest_from_request(request: VerifyRequest, intended_platforms: tuple[str, ...]) -> Manifest:
    return Manifest(
        manifest_id="platform-check",
        origin_schema="1.0",
        creator_id=request.creator_id,
        asset_id=request.asset_id,
        created_at=_now_iso(),
        content_hash=request.content_hash,
        intended_platforms=intended_platforms,
        key_id=request.key_id,
        origin_version=ORIGIN_VERSION,
    )


def _evaluate_registry(request: VerifyRequest, policy: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if not policy.get("require_key_registry", False):
        return reasons
    registry_path = Path(os.environ.get("ORIGIN_KEY_REGISTRY_PATH", str(DEFAULT_REGISTRY)))
    if not registry_path.exists():
        return ["key_registry_missing"]
    registry = read_registry(registry_path)
    if not is_key_active(registry, request.creator_id, request.key_id):
        reasons.append("key_untrusted")
    return reasons


def _evaluate_revocations(request: VerifyRequest, policy: dict[str, Any], intended_platforms: tuple[str, ...]) -> list[str]:
    reasons: list[str] = []
    if not policy.get("require_revocation_check", False):
        return reasons
    revocation_path = Path(os.environ.get("ORIGIN_REVOCATION_LIST_PATH", str(DEFAULT_REVOCATION)))
    if not revocation_path.exists():
        return ["revocation_list_missing"]
    listing = read_revocation_list(revocation_path)
    manifest = _build_manifest_from_request(request, intended_platforms)
    matches = find_revocations(manifest, listing, platform=request.platform_id)
    if matches:
        reasons.append("revoked")
    return reasons


def _evaluate_asset_record(request: VerifyRequest, policy: dict[str, Any]) -> tuple[list[str], tuple[str, ...]]:
    reasons: list[str] = []
    intended_platforms: tuple[str, ...] = ()
    ledger_path = Path(os.environ.get("ORIGIN_PLATFORM_LEDGER_PATH", str(DEFAULT_PLATFORM_LEDGER)))
    records = _load_asset_records(ledger_path)
    record = _find_asset_record(records, request.creator_id, request.asset_id)
    if record is None:
        if policy.get("require_asset_record", False):
            reasons.append("asset_record_missing")
        return reasons, intended_platforms

    if record.creator_id != request.creator_id:
        reasons.append("creator_mismatch")
    if policy.get("require_key_id_match", False) and record.key_id != request.key_id:
        reasons.append("key_id_mismatch")
    if record.content_hash and record.content_hash != request.content_hash:
        reasons.append("content_hash_mismatch")

    intended_platforms = record.intended_platforms
    if policy.get("require_platform_match", False):
        if not request.platform_id:
            reasons.append("platform_missing")
        elif intended_platforms and request.platform_id not in intended_platforms:
            reasons.append("platform_mismatch")

    if record.status != "active":
        reasons.append("key_untrusted")

    return reasons, intended_platforms


@app.post("/v1/ledger/verify", response_model=VerifyResponse, dependencies=[Depends(_auth_and_rate_limit)])
def verify(request: VerifyRequest) -> VerifyResponse:
    policy = _resolve_policy(request.platform_id)
    reasons: list[str] = []

    asset_reasons, intended_platforms = _evaluate_asset_record(request, policy)
    reasons.extend(asset_reasons)

    reasons.extend(_evaluate_registry(request, policy))
    reasons.extend(_evaluate_revocations(request, policy, intended_platforms))

    return VerifyResponse(ok=len(reasons) == 0, reasons=_reasons_payload(reasons))


@app.get("/v1/ledger/key-status", response_model=KeyStatusResponse, dependencies=[Depends(_auth_and_rate_limit)])
def key_status(creator_id: str, key_id: str) -> KeyStatusResponse:
    policy = _resolve_policy(None)
    reasons: list[str] = []
    key_status_value: str | None = None

    registry_path = Path(os.environ.get("ORIGIN_KEY_REGISTRY_PATH", str(DEFAULT_REGISTRY)))
    if not registry_path.exists():
        reasons.append("key_registry_missing")
    else:
        registry = read_registry(registry_path)
        if is_key_active(registry, creator_id, key_id):
            key_status_value = "active"
        else:
            key_status_value = "inactive"
            if policy.get("require_key_registry", False):
                reasons.append("key_untrusted")

    return KeyStatusResponse(ok=len(reasons) == 0, reasons=_reasons_payload(reasons), key_status=key_status_value)


@app.get("/v1/ledger/revocation-status", response_model=RevocationStatusResponse, dependencies=[Depends(_auth_and_rate_limit)])
def revocation_status(
    creator_id: str,
    key_id: str,
    asset_id: str,
    content_hash: str,
    platform_id: str,
) -> RevocationStatusResponse:
    policy = _resolve_policy(platform_id)
    request = VerifyRequest(
        creator_id=creator_id,
        key_id=key_id,
        asset_id=asset_id,
        content_hash=content_hash,
        platform_id=platform_id,
    )
    reasons, intended_platforms = _evaluate_asset_record(request, policy)
    revocation_reasons = _evaluate_revocations(request, policy, intended_platforms)
    reasons.extend(revocation_reasons)
    revoked = "revoked" in reasons
    return RevocationStatusResponse(ok=len(reasons) == 0, reasons=_reasons_payload(reasons), revoked=revoked)


@app.get("/v1/ledger/platform-policy", response_model=PlatformPolicyResponse, dependencies=[Depends(_auth_and_rate_limit)])
def platform_policy(platform_id: str | None = None) -> PlatformPolicyResponse:
    policy = _resolve_policy(platform_id)
    governance: dict[str, Any] | None = None

    bootstrap = _read_bootstrap()
    if bootstrap:
        governance = {
            "ledger_cid": bootstrap.get("governance_ledger_cid"),
            "node_endpoints": bootstrap.get("governance_node_endpoints", []),
            "ipfs_gateways": bootstrap.get("governance_ipfs_gateways", []),
        }
    else:
        governance = _read_governance_config()

    return PlatformPolicyResponse(ok=True, policy=policy, governance=governance)
