from __future__ import annotations

import argparse
import hashlib
import json
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Iterable
from urllib import request as urlrequest


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _matches_cid(ledger_cid: str | None, data: bytes) -> bool:
    if not ledger_cid:
        return True
    value = ledger_cid.strip().lower()
    if value.startswith("sha256:"):
        value = value.split(":", 1)[1]
    if len(value) != 64:
        return True
    return _hash_bytes(data) == value


def _build_urls(ledger_cid: str, upstreams: Iterable[str]) -> list[str]:
    urls: list[str] = []
    for upstream in upstreams:
        if "{cid}" in upstream:
            urls.append(upstream.replace("{cid}", ledger_cid))
        else:
            base = upstream.rstrip("/")
            urls.append(f"{base}/ledger/{ledger_cid}")
            urls.append(f"{base}/ipfs/{ledger_cid}")
    return urls


def fetch_ledger(
    ledger_path: Path,
    ledger_cid: str | None,
    upstreams: Iterable[str],
) -> tuple[bool, str | None]:
    if ledger_cid:
        urls = _build_urls(ledger_cid, upstreams)
    else:
        urls = list(upstreams)

    for url in urls:
        try:
            response = urlrequest.urlopen(url, timeout=8)
            data = response.read()
        except Exception:
            continue
        if not _matches_cid(ledger_cid, data):
            continue
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        ledger_path.write_bytes(data)
        return True, url
    return False, None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Origin full node ledger service")
    parser.add_argument("--listen", default="0.0.0.0:9020", help="Host:port to bind")
    parser.add_argument(
        "--ledger-path",
        default=str(Path.home() / ".origin_protocol" / "license_ledger.json"),
        help="Path to ledger file",
    )
    parser.add_argument("--ledger-cid", default="", help="Expected ledger CID (sha256 or cid)")
    parser.add_argument(
        "--upstream",
        action="append",
        default=[],
        help="Upstream ledger URL or base (repeatable)",
    )
    parser.add_argument("--sync-interval", type=int, default=900, help="Sync interval in seconds")
    return parser


class LedgerService:
    def __init__(self, ledger_path: Path, ledger_cid: str | None, upstreams: list[str]) -> None:
        self.ledger_path = ledger_path
        self.ledger_cid = ledger_cid or None
        self.upstreams = upstreams
        self.last_sync: str | None = None
        self.last_source: str | None = None
        self.start_time = datetime.now(timezone.utc)
        self.lock = threading.Lock()

    def sync_once(self) -> bool:
        if not self.upstreams:
            return False
        ok, source = fetch_ledger(self.ledger_path, self.ledger_cid, self.upstreams)
        if ok:
            with self.lock:
                self.last_sync = datetime.now(timezone.utc).isoformat()
                self.last_source = source
        return ok

    def ledger_hash(self) -> str | None:
        if not self.ledger_path.exists():
            return None
        return _hash_bytes(self.ledger_path.read_bytes())

    def uptime_seconds(self) -> int:
        return int((datetime.now(timezone.utc) - self.start_time).total_seconds())


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "OriginFullNode/0.1"

    def do_GET(self) -> None:  # noqa: N802
        service: LedgerService = self.server.service  # type: ignore[attr-defined]
        if self.path.startswith("/health"):
            payload = {
                "status": "ok",
                "ledger_cid": service.ledger_cid,
                "ledger_hash": service.ledger_hash(),
                "last_sync": service.last_sync,
                "last_source": service.last_source,
                "uptime_seconds": service.uptime_seconds(),
            }
            self._send_json(payload)
            return

        if self.path.startswith("/ledger/") or self.path.startswith("/ipfs/"):
            parts = self.path.split("/")
            if len(parts) < 3:
                self._send_not_found()
                return
            cid = parts[2]
            if service.ledger_cid and cid != service.ledger_cid and not cid.endswith(service.ledger_cid):
                self._send_not_found()
                return
            if not service.ledger_path.exists():
                self._send_not_found()
                return
            data = service.ledger_path.read_bytes()
            if not _matches_cid(service.ledger_cid, data):
                self._send_not_found()
                return
            self._send_bytes(data, content_type="application/json")
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


class ServiceHTTPServer(HTTPServer):
    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler], service: LedgerService):
        super().__init__(server_address, handler)
        self.service = service


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    host, _, port_str = args.listen.rpartition(":")
    host = host or "0.0.0.0"
    port = int(port_str) if port_str else 9020

    ledger_path = Path(args.ledger_path)
    ledger_cid = args.ledger_cid.strip() or None
    upstreams = [value for value in args.upstream if value]

    service = LedgerService(ledger_path=ledger_path, ledger_cid=ledger_cid, upstreams=upstreams)

    if upstreams:
        service.sync_once()

    server = ServiceHTTPServer((host, port), RequestHandler, service)

    def sync_loop() -> None:
        while True:
            time.sleep(max(60, int(args.sync_interval)))
            service.sync_once()

    if upstreams:
        thread = threading.Thread(target=sync_loop, daemon=True)
        thread.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
