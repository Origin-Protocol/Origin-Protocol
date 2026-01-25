from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from origin_protocol.keys import load_public_key_bytes
from origin_protocol.nodes import compute_authority_set, read_node_ledger_file, verify_node_ledger


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_ledger_bytes(path: Path) -> bytes | None:
    if not path.exists():
        return None
    return path.read_bytes()


def _load_state(path: Path, public_key_override: str | None) -> dict:
    raw = _read_ledger_bytes(path)
    if raw is None:
        return {
            "exists": False,
            "ledger": None,
            "signature": None,
            "public_key": None,
            "valid_signature": False,
            "authorities": [],
            "ledger_hash": None,
        }

    ledger, signature, public_key = read_node_ledger_file(str(path))
    public_key_pem = public_key_override or public_key
    valid_signature = False
    if public_key_pem:
        try:
            key = load_public_key_bytes(public_key_pem.encode("utf-8"))
            valid_signature = verify_node_ledger(ledger, signature, key)
        except Exception:
            valid_signature = False

    return {
        "exists": True,
        "ledger": ledger,
        "signature": signature,
        "public_key": public_key_pem,
        "valid_signature": valid_signature,
        "authorities": sorted(compute_authority_set(ledger)),
        "ledger_hash": _hash_bytes(raw),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Origin node registry reference service")
    parser.add_argument("--listen", default="0.0.0.0:9030", help="Host:port to bind")
    parser.add_argument("--ledger-path", required=True, help="Path to node ledger JSON")
    parser.add_argument("--public-key", default="", help="Public key PEM to verify ledger signature")
    parser.add_argument(
        "--require-valid",
        action="store_true",
        help="Return 503 unless the ledger signature is valid",
    )
    return parser


class RegistryService:
    def __init__(self, ledger_path: Path, public_key_override: str | None, require_valid: bool) -> None:
        self.ledger_path = ledger_path
        self.public_key_override = public_key_override
        self.require_valid = require_valid
        self.started_at = datetime.now(timezone.utc)

    def load_state(self) -> dict:
        return _load_state(self.ledger_path, self.public_key_override)

    def uptime_seconds(self) -> int:
        return int((datetime.now(timezone.utc) - self.started_at).total_seconds())


class RegistryRequestHandler(BaseHTTPRequestHandler):
    server_version = "OriginNodeRegistry/0.1"

    def do_GET(self) -> None:  # noqa: N802
        service: RegistryService = self.server.service  # type: ignore[attr-defined]
        state = service.load_state()

        if self.path.startswith("/health"):
            payload = {
                "status": "ok" if state["exists"] else "missing",
                "valid_signature": state["valid_signature"],
                "ledger_hash": state["ledger_hash"],
                "authorities": len(state["authorities"]),
                "uptime_seconds": service.uptime_seconds(),
            }
            self._send_json(payload)
            return

        if service.require_valid and not state["valid_signature"]:
            self.send_response(503)
            self.end_headers()
            return

        if self.path.startswith("/ledger"):
            raw = _read_ledger_bytes(service.ledger_path)
            if raw is None:
                self._send_not_found()
                return
            self._send_bytes(raw, content_type="application/json")
            return

        if self.path.startswith("/nodes"):
            ledger = state["ledger"]
            if ledger is None:
                self._send_not_found()
                return
            payload = {
                "ledger_id": ledger.ledger_id,
                "issuer_id": ledger.issuer_id,
                "entries": len(ledger.entries),
                "authorities": state["authorities"],
            }
            self._send_json(payload)
            return

        if self.path.startswith("/authority/"):
            key = self.path.split("/", 2)[2]
            payload = {
                "node_key": key,
                "is_authority": key in state["authorities"],
            }
            self._send_json(payload)
            return

        self._send_not_found()

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _send_not_found(self) -> None:
        self.send_response(404)
        self.end_headers()

    def _send_json(self, payload: dict) -> None:
        data = json.dumps(payload, indent=2).encode("utf-8")
        self._send_bytes(data, content_type="application/json")

    def _send_bytes(self, data: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class RegistryHTTPServer(HTTPServer):
    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler], service: RegistryService):
        super().__init__(server_address, handler)
        self.service = service


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    host, _, port_str = args.listen.rpartition(":")
    host = host or "0.0.0.0"
    port = int(port_str) if port_str else 9030

    service = RegistryService(
        ledger_path=Path(args.ledger_path),
        public_key_override=args.public_key or None,
        require_valid=args.require_valid,
    )

    server = RegistryHTTPServer((host, port), RegistryRequestHandler, service)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
