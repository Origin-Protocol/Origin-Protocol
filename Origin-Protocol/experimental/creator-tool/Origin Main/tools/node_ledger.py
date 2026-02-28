from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from origin_protocol.keys import load_private_key, load_public_key_bytes
from origin_protocol.nodes import (
    NodeAuthoritySignature,
    NodeDemotionCertificate,
    NodePromotionCertificate,
    add_node_ledger_entry,
    build_demotion_entry,
    build_node_ledger,
    build_promotion_entry,
    build_revocation_entry,
    read_node_ledger_file,
    sign_node_ledger,
    verify_node_ledger,
    write_node_ledger_file,
)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _promotion_certificate_from_payload(payload: dict[str, Any]) -> NodePromotionCertificate:
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


def _demotion_certificate_from_payload(payload: dict[str, Any]) -> NodeDemotionCertificate:
    approvals = tuple(
        NodeAuthoritySignature(
            authority_key=item["authority_key"],
            signature=item["signature"],
            signed_at=item["signed_at"],
        )
        for item in payload.get("approvals", [])
    )
    return NodeDemotionCertificate(
        node_key=payload["node_key"],
        reason=payload["reason"],
        request_hash=payload.get("request_hash"),
        approvals_required=int(payload["approvals_required"]),
        approvals=approvals,
        issued_at=payload["issued_at"],
        origin_schema=payload.get("origin_schema", "1.0"),
        signature_algorithm=payload.get("signature_algorithm", "ed25519"),
        origin_version=payload.get("origin_version"),
    )


def init_ledger(args: argparse.Namespace) -> int:
    ledger = build_node_ledger(args.issuer_id)
    signature = sign_node_ledger(ledger, load_private_key(Path(args.private_key)))
    write_node_ledger_file(ledger, signature, Path(args.public_key).read_bytes(), args.output)
    return 0


def add_promotion(args: argparse.Namespace) -> int:
    ledger, _, _ = read_node_ledger_file(args.ledger)
    payload = _load_json(Path(args.certificate))
    certificate = _promotion_certificate_from_payload(payload)
    entry = build_promotion_entry(certificate)
    ledger = add_node_ledger_entry(ledger, entry)
    signature = sign_node_ledger(ledger, load_private_key(Path(args.private_key)))
    write_node_ledger_file(ledger, signature, Path(args.public_key).read_bytes(), args.output)
    return 0


def add_demotion(args: argparse.Namespace) -> int:
    ledger, _, _ = read_node_ledger_file(args.ledger)
    payload = _load_json(Path(args.certificate))
    certificate = _demotion_certificate_from_payload(payload)
    entry = build_demotion_entry(certificate)
    ledger = add_node_ledger_entry(ledger, entry)
    signature = sign_node_ledger(ledger, load_private_key(Path(args.private_key)))
    write_node_ledger_file(ledger, signature, Path(args.public_key).read_bytes(), args.output)
    return 0


def add_revocation(args: argparse.Namespace) -> int:
    ledger, _, _ = read_node_ledger_file(args.ledger)
    entry = build_revocation_entry(args.node_key, args.reason)
    ledger = add_node_ledger_entry(ledger, entry)
    signature = sign_node_ledger(ledger, load_private_key(Path(args.private_key)))
    write_node_ledger_file(ledger, signature, Path(args.public_key).read_bytes(), args.output)
    return 0


def verify(args: argparse.Namespace) -> int:
    ledger, signature, public_key_pem = read_node_ledger_file(args.ledger)
    public_key = load_public_key_bytes(public_key_pem.encode("utf-8"))
    ok = verify_node_ledger(ledger, signature, public_key)
    if ok:
        return 0
    raise SystemExit("Node ledger signature invalid")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Origin node governance ledger")
    sub = parser.add_subparsers(dest="command", required=True)

    init_cmd = sub.add_parser("init", help="Create a node governance ledger")
    init_cmd.add_argument("--issuer-id", required=True)
    init_cmd.add_argument("--private-key", required=True)
    init_cmd.add_argument("--public-key", required=True)
    init_cmd.add_argument("--output", default="node_ledger.json")
    init_cmd.set_defaults(func=init_ledger)

    add_promo = sub.add_parser("add-promotion", help="Add promotion certificate")
    add_promo.add_argument("--ledger", required=True)
    add_promo.add_argument("--certificate", required=True)
    add_promo.add_argument("--private-key", required=True)
    add_promo.add_argument("--public-key", required=True)
    add_promo.add_argument("--output", default="node_ledger.json")
    add_promo.set_defaults(func=add_promotion)

    add_demo = sub.add_parser("add-demotion", help="Add demotion certificate")
    add_demo.add_argument("--ledger", required=True)
    add_demo.add_argument("--certificate", required=True)
    add_demo.add_argument("--private-key", required=True)
    add_demo.add_argument("--public-key", required=True)
    add_demo.add_argument("--output", default="node_ledger.json")
    add_demo.set_defaults(func=add_demotion)

    add_revoke = sub.add_parser("add-revocation", help="Add revocation entry")
    add_revoke.add_argument("--ledger", required=True)
    add_revoke.add_argument("--node-key", required=True)
    add_revoke.add_argument("--reason", default="")
    add_revoke.add_argument("--private-key", required=True)
    add_revoke.add_argument("--public-key", required=True)
    add_revoke.add_argument("--output", default="node_ledger.json")
    add_revoke.set_defaults(func=add_revocation)

    verify_cmd = sub.add_parser("verify", help="Verify node ledger")
    verify_cmd.add_argument("--ledger", required=True)
    verify_cmd.set_defaults(func=verify)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
