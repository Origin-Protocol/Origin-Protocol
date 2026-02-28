from __future__ import annotations

import argparse
import base64
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from origin_protocol.keys import load_private_key, load_public_key, public_key_fingerprint
from origin_protocol.manifest import ORIGIN_VERSION
from origin_protocol.nodes import (
    NodeAuthoritySignature,
    NodePromotionCertificate,
    NodePromotionRequest,
    add_authority_signature,
    build_promotion_certificate,
    build_promotion_request,
    promotion_request_hash,
    promotion_request_to_bytes,
    sign_promotion_certificate_payload,
    sign_promotion_request,
)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _load_request_payload(path: Path) -> dict[str, Any]:
    payload = _load_json(path)
    if "request" in payload:
        return payload["request"]
    return payload


def _request_from_payload(payload: dict[str, Any]) -> NodePromotionRequest:
    return NodePromotionRequest(
        node_key=payload["node_key"],
        uptime_score=float(payload["uptime_score"]),
        ledger_hash=payload["ledger_hash"],
        cid_history=tuple(payload.get("cid_history", [])),
        pinned_cids=tuple(payload.get("pinned_cids", [])),
        request_timestamp=payload["request_timestamp"],
        origin_schema=payload.get("origin_schema", "1.0"),
        signature_algorithm=payload.get("signature_algorithm", "ed25519"),
        origin_version=payload.get("origin_version", ORIGIN_VERSION),
    )


def _certificate_from_payload(payload: dict[str, Any]) -> NodePromotionCertificate:
    approvals = tuple(
        NodeAuthoritySignature(
            authority_key=item["authority_key"],
            signature=item["signature"],
            signed_at=item["signed_at"],
        )
        for item in payload.get("approvals", [])
    )
    return NodePromotionCertificate(
        node_key=payload["node_key"],
        request_hash=payload["request_hash"],
        approvals_required=int(payload["approvals_required"]),
        approvals=approvals,
        issued_at=payload["issued_at"],
        origin_schema=payload.get("origin_schema", "1.0"),
        signature_algorithm=payload.get("signature_algorithm", "ed25519"),
        origin_version=payload.get("origin_version"),
    )


def build_request(args: argparse.Namespace) -> int:
    ledger_hash = args.ledger_hash
    if args.ledger_path:
        ledger_path = Path(args.ledger_path)
        if not ledger_path.exists():
            raise SystemExit("ledger_path does not exist")
        data = ledger_path.read_bytes()
        ledger_hash = hashlib.sha256(data).hexdigest()

    if not ledger_hash:
        raise SystemExit("ledger_hash is required (use --ledger-hash or --ledger-path)")

    request = build_promotion_request(
        node_key=args.node_key,
        uptime_score=args.uptime_score,
        ledger_hash=ledger_hash,
        cid_history=args.cid_history or [],
        pinned_cids=args.pinned_cids or [],
    )

    payload: dict[str, Any] = {"request": json.loads(promotion_request_to_bytes(request).decode("utf-8"))}

    if args.private_key and args.public_key:
        signature = sign_promotion_request(request, load_private_key(Path(args.private_key)))
        payload["signature"] = base64.b64encode(signature).decode("ascii")
        payload["public_key"] = Path(args.public_key).read_text(encoding="utf-8")

    _write_json(Path(args.output), payload)
    return 0


def sign_request(args: argparse.Namespace) -> int:
    payload = _load_request_payload(Path(args.request))
    request = _request_from_payload(payload)
    signature = sign_promotion_request(request, load_private_key(Path(args.private_key)))
    signed_payload = {
        "request": json.loads(promotion_request_to_bytes(request).decode("utf-8")),
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key": Path(args.public_key).read_text(encoding="utf-8"),
    }
    _write_json(Path(args.output), signed_payload)
    return 0


def build_certificate(args: argparse.Namespace) -> int:
    cert = build_promotion_certificate(
        node_key=args.node_key,
        request_hash=args.request_hash,
        approvals_required=args.approvals_required,
    )
    payload = asdict(cert)
    _write_json(Path(args.output), payload)
    return 0


def add_approval(args: argparse.Namespace) -> int:
    payload = _load_json(Path(args.certificate))
    cert = _certificate_from_payload(payload)
    signature = sign_promotion_certificate_payload(cert, load_private_key(Path(args.private_key)))
    public_key = load_public_key(Path(args.public_key))
    authority_key = args.authority_key or public_key_fingerprint(public_key)
    cert = add_authority_signature(cert, authority_key, signature)
    _write_json(Path(args.output), asdict(cert))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Origin node promotion workflow")
    sub = parser.add_subparsers(dest="command", required=True)

    build_req = sub.add_parser("build-request", help="Create a promotion request")
    build_req.add_argument("--node-key", required=True)
    build_req.add_argument("--uptime-score", type=float, required=True)
    build_req.add_argument("--ledger-hash", default="")
    build_req.add_argument("--ledger-path", default="")
    build_req.add_argument("--cid-history", nargs="*", default=[])
    build_req.add_argument("--pinned-cids", nargs="*", default=[])
    build_req.add_argument("--private-key", default="")
    build_req.add_argument("--public-key", default="")
    build_req.add_argument("--output", default="promotion_request.json")
    build_req.set_defaults(func=build_request)

    sign_req = sub.add_parser("sign-request", help="Sign an existing request")
    sign_req.add_argument("--request", required=True)
    sign_req.add_argument("--private-key", required=True)
    sign_req.add_argument("--public-key", required=True)
    sign_req.add_argument("--output", default="promotion_request.signed.json")
    sign_req.set_defaults(func=sign_request)

    build_cert = sub.add_parser("build-certificate", help="Create a promotion certificate shell")
    build_cert.add_argument("--node-key", required=True)
    build_cert.add_argument("--request-hash", required=True)
    build_cert.add_argument("--approvals-required", type=int, required=True)
    build_cert.add_argument("--output", default="promotion_certificate.json")
    build_cert.set_defaults(func=build_certificate)

    add_sig = sub.add_parser("add-approval", help="Add authority signature to certificate")
    add_sig.add_argument("--certificate", required=True)
    add_sig.add_argument("--private-key", required=True)
    add_sig.add_argument("--public-key", required=True)
    add_sig.add_argument("--authority-key", default="")
    add_sig.add_argument("--output", default="promotion_certificate.signed.json")
    add_sig.set_defaults(func=add_approval)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
