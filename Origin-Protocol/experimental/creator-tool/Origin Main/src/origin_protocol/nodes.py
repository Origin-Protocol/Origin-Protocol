from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .manifest import ORIGIN_VERSION


@dataclass(frozen=True)
class NodePromotionRequest:
    node_key: str
    uptime_score: float
    ledger_hash: str
    cid_history: tuple[str, ...]
    pinned_cids: tuple[str, ...]
    request_timestamp: str
    origin_schema: str = "1.0"
    signature_algorithm: str = "ed25519"
    origin_version: str = ORIGIN_VERSION


@dataclass(frozen=True)
class NodeAuthoritySignature:
    authority_key: str
    signature: str
    signed_at: str


@dataclass(frozen=True)
class NodePromotionCertificate:
    node_key: str
    request_hash: str
    approvals_required: int
    approvals: tuple[NodeAuthoritySignature, ...]
    issued_at: str
    origin_schema: str = "1.0"
    signature_algorithm: str = "ed25519"
    origin_version: str = ORIGIN_VERSION


@dataclass(frozen=True)
class NodeDemotionCertificate:
    node_key: str
    reason: str
    request_hash: str | None
    approvals_required: int
    approvals: tuple[NodeAuthoritySignature, ...]
    issued_at: str
    origin_schema: str = "1.0"
    signature_algorithm: str = "ed25519"
    origin_version: str = ORIGIN_VERSION


@dataclass(frozen=True)
class NodeLedgerEntry:
    entry_type: str
    node_key: str
    issued_at: str
    request_hash: str | None = None
    reason: str | None = None
    approvals_required: int | None = None
    approvals: tuple[NodeAuthoritySignature, ...] | None = None


@dataclass(frozen=True)
class NodeGovernanceLedger:
    ledger_id: str
    issuer_id: str
    created_at: str
    entries: tuple[NodeLedgerEntry, ...]
    origin_schema: str = "1.0"
    signature_algorithm: str = "ed25519"
    origin_version: str = ORIGIN_VERSION


def _canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _drop_nones(payload: dict) -> dict:
    return {key: value for key, value in payload.items() if value is not None}


def build_promotion_request(
    node_key: str,
    uptime_score: float,
    ledger_hash: str,
    cid_history: Iterable[str],
    pinned_cids: Iterable[str],
) -> NodePromotionRequest:
    return NodePromotionRequest(
        node_key=node_key,
        uptime_score=uptime_score,
        ledger_hash=ledger_hash,
        cid_history=tuple(cid_history),
        pinned_cids=tuple(pinned_cids),
        request_timestamp=datetime.now(timezone.utc).isoformat(),
    )


def promotion_request_to_bytes(request: NodePromotionRequest) -> bytes:
    return _canonical_bytes(_drop_nones(asdict(request)))


def promotion_request_hash(request: NodePromotionRequest) -> str:
    return hashlib.sha256(promotion_request_to_bytes(request)).hexdigest()


def sign_promotion_request(request: NodePromotionRequest, private_key: Ed25519PrivateKey) -> bytes:
    return private_key.sign(promotion_request_to_bytes(request))


def verify_promotion_request(
    request: NodePromotionRequest,
    signature: bytes,
    public_key: Ed25519PublicKey,
) -> bool:
    try:
        public_key.verify(signature, promotion_request_to_bytes(request))
    except Exception:
        return False
    return True


def write_promotion_request_file(
    request: NodePromotionRequest,
    signature: bytes,
    public_key_pem: bytes,
    path: str,
) -> None:
    payload = {
        "request": json.loads(promotion_request_to_bytes(request).decode("utf-8")),
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key": public_key_pem.decode("utf-8"),
    }
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True))


def read_promotion_request_file(path: str) -> tuple[NodePromotionRequest, bytes, str]:
    payload = json.loads(open(path, "r", encoding="utf-8").read())
    request = NodePromotionRequest(
        node_key=payload["request"]["node_key"],
        uptime_score=float(payload["request"]["uptime_score"]),
        ledger_hash=payload["request"]["ledger_hash"],
        cid_history=tuple(payload["request"].get("cid_history", [])),
        pinned_cids=tuple(payload["request"].get("pinned_cids", [])),
        request_timestamp=payload["request"]["request_timestamp"],
        origin_schema=payload["request"].get("origin_schema", "1.0"),
        signature_algorithm=payload["request"].get("signature_algorithm", "ed25519"),
        origin_version=payload["request"].get("origin_version", ORIGIN_VERSION),
    )
    signature = base64.b64decode(payload["signature"])
    public_key = payload["public_key"]
    return request, signature, public_key


def build_promotion_certificate(
    node_key: str,
    request_hash: str,
    approvals_required: int,
    approvals: Iterable[NodeAuthoritySignature] | None = None,
    issued_at: str | None = None,
) -> NodePromotionCertificate:
    return NodePromotionCertificate(
        node_key=node_key,
        request_hash=request_hash,
        approvals_required=approvals_required,
        approvals=tuple(approvals or ()),
        issued_at=issued_at or datetime.now(timezone.utc).isoformat(),
    )


def promotion_certificate_payload_bytes(certificate: NodePromotionCertificate) -> bytes:
    payload = _drop_nones(asdict(replace(certificate, approvals=())))
    return _canonical_bytes(payload)


def sign_promotion_certificate_payload(
    certificate: NodePromotionCertificate,
    private_key: Ed25519PrivateKey,
) -> bytes:
    return private_key.sign(promotion_certificate_payload_bytes(certificate))


def add_authority_signature(
    certificate: NodePromotionCertificate,
    authority_key: str,
    signature: bytes,
    signed_at: str | None = None,
) -> NodePromotionCertificate:
    entry = NodeAuthoritySignature(
        authority_key=authority_key,
        signature=base64.b64encode(signature).decode("ascii"),
        signed_at=signed_at or datetime.now(timezone.utc).isoformat(),
    )
    return replace(certificate, approvals=certificate.approvals + (entry,))


def verify_authority_signature(
    certificate: NodePromotionCertificate,
    authority_signature: NodeAuthoritySignature,
    public_key: Ed25519PublicKey,
) -> bool:
    try:
        signature = base64.b64decode(authority_signature.signature)
        public_key.verify(signature, promotion_certificate_payload_bytes(certificate))
    except Exception:
        return False
    return True


def build_demotion_certificate(
    node_key: str,
    reason: str,
    approvals_required: int,
    request_hash: str | None = None,
    approvals: Iterable[NodeAuthoritySignature] | None = None,
    issued_at: str | None = None,
) -> NodeDemotionCertificate:
    return NodeDemotionCertificate(
        node_key=node_key,
        reason=reason,
        request_hash=request_hash,
        approvals_required=approvals_required,
        approvals=tuple(approvals or ()),
        issued_at=issued_at or datetime.now(timezone.utc).isoformat(),
    )


def demotion_certificate_payload_bytes(certificate: NodeDemotionCertificate) -> bytes:
    payload = _drop_nones(asdict(replace(certificate, approvals=())))
    return _canonical_bytes(payload)


def sign_demotion_certificate_payload(
    certificate: NodeDemotionCertificate,
    private_key: Ed25519PrivateKey,
) -> bytes:
    return private_key.sign(demotion_certificate_payload_bytes(certificate))


def add_demotion_signature(
    certificate: NodeDemotionCertificate,
    authority_key: str,
    signature: bytes,
    signed_at: str | None = None,
) -> NodeDemotionCertificate:
    entry = NodeAuthoritySignature(
        authority_key=authority_key,
        signature=base64.b64encode(signature).decode("ascii"),
        signed_at=signed_at or datetime.now(timezone.utc).isoformat(),
    )
    return replace(certificate, approvals=certificate.approvals + (entry,))


def verify_demotion_signature(
    certificate: NodeDemotionCertificate,
    authority_signature: NodeAuthoritySignature,
    public_key: Ed25519PublicKey,
) -> bool:
    try:
        signature = base64.b64decode(authority_signature.signature)
        public_key.verify(signature, demotion_certificate_payload_bytes(certificate))
    except Exception:
        return False
    return True


def build_node_ledger(issuer_id: str) -> NodeGovernanceLedger:
    return NodeGovernanceLedger(
        ledger_id=str(hashlib.sha256(issuer_id.encode("utf-8")).hexdigest()),
        issuer_id=issuer_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        entries=(),
    )


def add_node_ledger_entry(ledger: NodeGovernanceLedger, entry: NodeLedgerEntry) -> NodeGovernanceLedger:
    return NodeGovernanceLedger(
        ledger_id=ledger.ledger_id,
        issuer_id=ledger.issuer_id,
        created_at=ledger.created_at,
        entries=ledger.entries + (entry,),
        origin_schema=ledger.origin_schema,
        signature_algorithm=ledger.signature_algorithm,
        origin_version=ledger.origin_version,
    )


def build_promotion_entry(certificate: NodePromotionCertificate) -> NodeLedgerEntry:
    return NodeLedgerEntry(
        entry_type="promotion",
        node_key=certificate.node_key,
        issued_at=certificate.issued_at,
        request_hash=certificate.request_hash,
        approvals_required=certificate.approvals_required,
        approvals=certificate.approvals,
    )


def build_demotion_entry(certificate: NodeDemotionCertificate) -> NodeLedgerEntry:
    return NodeLedgerEntry(
        entry_type="demotion",
        node_key=certificate.node_key,
        issued_at=certificate.issued_at,
        request_hash=certificate.request_hash,
        reason=certificate.reason,
        approvals_required=certificate.approvals_required,
        approvals=certificate.approvals,
    )


def build_revocation_entry(node_key: str, reason: str | None = None) -> NodeLedgerEntry:
    return NodeLedgerEntry(
        entry_type="revocation",
        node_key=node_key,
        issued_at=datetime.now(timezone.utc).isoformat(),
        reason=reason,
    )


def node_ledger_to_bytes(ledger: NodeGovernanceLedger) -> bytes:
    payload = asdict(ledger)
    payload["entries"] = [
        _drop_nones({
            **{key: value for key, value in asdict(item).items() if value is not None},
            "approvals": [
                {key: value for key, value in asdict(signature).items() if value is not None}
                for signature in (item.approvals or ())
            ]
            if item.approvals is not None
            else None,
        })
        for item in ledger.entries
    ]
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def node_ledger_from_bytes(data: bytes) -> NodeGovernanceLedger:
    payload = json.loads(data)
    entries = []
    for item in payload.get("entries", []):
        approvals_raw = item.get("approvals")
        approvals: tuple[NodeAuthoritySignature, ...] | None = None
        if isinstance(approvals_raw, list):
            approvals = tuple(
                NodeAuthoritySignature(
                    authority_key=entry["authority_key"],
                    signature=entry["signature"],
                    signed_at=entry["signed_at"],
                )
                for entry in approvals_raw
            )
        entries.append(
            NodeLedgerEntry(
                entry_type=item["entry_type"],
                node_key=item["node_key"],
                issued_at=item["issued_at"],
                request_hash=item.get("request_hash"),
                reason=item.get("reason"),
                approvals_required=item.get("approvals_required"),
                approvals=approvals,
            )
        )
    return NodeGovernanceLedger(
        ledger_id=payload.get("ledger_id", ""),
        issuer_id=payload["issuer_id"],
        created_at=payload["created_at"],
        entries=tuple(entries),
        origin_schema=payload.get("origin_schema", "1.0"),
        signature_algorithm=payload.get("signature_algorithm", "ed25519"),
        origin_version=payload.get("origin_version", ORIGIN_VERSION),
    )


def sign_node_ledger(ledger: NodeGovernanceLedger, private_key: Ed25519PrivateKey) -> bytes:
    return private_key.sign(node_ledger_to_bytes(ledger))


def verify_node_ledger(
    ledger: NodeGovernanceLedger,
    signature: bytes,
    public_key: Ed25519PublicKey,
) -> bool:
    try:
        public_key.verify(signature, node_ledger_to_bytes(ledger))
    except Exception:
        return False
    return True


def write_node_ledger_file(
    ledger: NodeGovernanceLedger,
    signature: bytes,
    public_key_pem: bytes,
    path: str,
) -> None:
    payload = {
        "ledger": json.loads(node_ledger_to_bytes(ledger).decode("utf-8")),
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key": public_key_pem.decode("utf-8"),
    }
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True))


def read_node_ledger_file(path: str) -> tuple[NodeGovernanceLedger, bytes, str]:
    payload = json.loads(open(path, "r", encoding="utf-8").read())
    ledger = node_ledger_from_bytes(json.dumps(payload["ledger"]).encode("utf-8"))
    signature = base64.b64decode(payload["signature"])
    public_key = payload["public_key"]
    return ledger, signature, public_key


def compute_authority_set(ledger: NodeGovernanceLedger) -> set[str]:
    authorities: set[str] = set()
    for entry in ledger.entries:
        if entry.entry_type == "promotion":
            authorities.add(entry.node_key)
        elif entry.entry_type in {"demotion", "revocation"}:
            authorities.discard(entry.node_key)
    return authorities
