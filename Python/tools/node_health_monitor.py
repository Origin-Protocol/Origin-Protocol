from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, request as urlrequest

from origin_protocol.keys import load_private_key, load_public_key, public_key_fingerprint
from origin_protocol.nodes import (
    NodeAuthoritySignature,
    NodeDemotionCertificate,
    add_demotion_signature,
    add_node_ledger_entry,
    build_demotion_certificate,
    build_demotion_entry,
    read_node_ledger_file,
    sign_demotion_certificate_payload,
    sign_node_ledger,
    write_node_ledger_file,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _fetch_json(url: str, timeout: int = 6) -> dict[str, Any] | None:
    try:
        response = urlrequest.urlopen(url, timeout=timeout)
        return json.loads(response.read().decode("utf-8"))
    except Exception:
        return None


def _fetch_bytes(url: str, timeout: int = 6) -> bytes | None:
    try:
        response = urlrequest.urlopen(url, timeout=timeout)
        return response.read()
    except Exception:
        return None


def _matches_cid(ledger_cid: str | None, ledger_hash: str | None) -> bool:
    if not ledger_cid or not ledger_hash:
        return True
    value = ledger_cid.strip().lower()
    if value.startswith("sha256:"):
        value = value.split(":", 1)[1]
    if len(value) != 64:
        return True
    return ledger_hash.strip().lower() == value


def _hash_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _build_demotion_certificate(
    node_key: str,
    reason: str,
    approvals_required: int,
    authority_private_key: str | None,
    authority_public_key: str | None,
) -> NodeDemotionCertificate:
    certificate = build_demotion_certificate(
        node_key=node_key,
        reason=reason,
        approvals_required=approvals_required,
    )
    if authority_private_key and authority_public_key:
        signature = sign_demotion_certificate_payload(
            certificate,
            load_private_key(Path(authority_private_key)),
        )
        authority_key = public_key_fingerprint(load_public_key(Path(authority_public_key)))
        certificate = add_demotion_signature(certificate, authority_key, signature)
    return certificate


def _apply_demotion_to_ledger(
    ledger_path: str,
    certificate: NodeDemotionCertificate,
    authority_private_key: str,
    authority_public_key: str,
) -> None:
    ledger, _, _ = read_node_ledger_file(ledger_path)
    entry = build_demotion_entry(certificate)
    ledger = add_node_ledger_entry(ledger, entry)
    signature = sign_node_ledger(ledger, load_private_key(Path(authority_private_key)))
    write_node_ledger_file(ledger, signature, Path(authority_public_key).read_bytes(), ledger_path)


def run_monitor(config_path: Path) -> int:
    config = _load_json(config_path)
    state_path = Path(config.get("state_path") or Path.home() / ".origin_protocol" / "node_health.json")
    state = {}
    if state_path.exists():
        try:
            state = _load_json(state_path)
        except Exception:
            state = {}

    nodes = config.get("nodes", [])
    failure_threshold = int(config.get("failure_threshold", 3))
    expected_cid = config.get("expected_ledger_cid")
    demotion_reason = config.get("demotion_reason", "health_check_failed")
    approvals_required = int(config.get("approvals_required", 3))
    authority_private_key = config.get("authority_private_key")
    authority_public_key = config.get("authority_public_key")
    apply_demotion = bool(config.get("apply_demotion"))
    ledger_path = config.get("node_ledger_path", "")

    state.setdefault("nodes", {})
    state.setdefault("demoted_nodes", [])

    for node in nodes:
        node_key = node.get("node_key")
        if not node_key:
            continue
        node_state = state["nodes"].get(node_key, {})
        health_url = node.get("health_url")
        ledger_url = node.get("ledger_url")
        ok = True
        reason = ""

        payload = _fetch_json(health_url) if health_url else None
        if payload is None:
            ok = False
            reason = "health_unreachable"
        else:
            ledger_hash = payload.get("ledger_hash")
            if expected_cid and not _matches_cid(expected_cid, ledger_hash):
                ok = False
                reason = "ledger_hash_mismatch"

        if ok and expected_cid and ledger_url:
            url = ledger_url.replace("{cid}", expected_cid)
            data = _fetch_bytes(url)
            if data is None:
                ok = False
                reason = "ledger_fetch_failed"
            else:
                if _hash_bytes(data) != expected_cid.replace("sha256:", ""):
                    ok = False
                    reason = "ledger_cid_mismatch"

        if ok:
            node_state["consecutive_failures"] = 0
            node_state["last_ok_at"] = _now_iso()
            node_state["last_status"] = "ok"
            node_state["last_reason"] = None
        else:
            node_state["consecutive_failures"] = int(node_state.get("consecutive_failures", 0)) + 1
            node_state["last_status"] = "fail"
            node_state["last_reason"] = reason

        if (
            not ok
            and node_state["consecutive_failures"] >= failure_threshold
            and node_key not in state["demoted_nodes"]
        ):
            certificate = _build_demotion_certificate(
                node_key=node_key,
                reason=demotion_reason,
                approvals_required=approvals_required,
                authority_private_key=authority_private_key,
                authority_public_key=authority_public_key,
            )
            cert_path = config_path.parent / f"demotion_{node_key}_{int(time.time())}.json"
            _write_json(cert_path, asdict(certificate))
            node_state["demotion_certificate"] = str(cert_path)
            state["demoted_nodes"].append(node_key)

            if apply_demotion and ledger_path and authority_private_key and authority_public_key:
                _apply_demotion_to_ledger(ledger_path, certificate, authority_private_key, authority_public_key)

        state["nodes"][node_key] = node_state

    _write_json(state_path, state)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Monitor full nodes and emit demotion certificates")
    parser.add_argument("--config", required=True, help="Path to JSON config")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return run_monitor(Path(args.config))


if __name__ == "__main__":
    raise SystemExit(main())
