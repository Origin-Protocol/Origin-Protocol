from __future__ import annotations

import json
import os
import smtplib
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Sequence
from urllib.parse import parse_qs
from urllib.request import Request, urlopen
import subprocess

DEFAULT_VERIFY_URL = "https://ipnpb.paypal.com/cgi-bin/webscr"

APP_DIR = Path.home() / ".origin_protocol"
LICENSE_OUTPUT_DIR = Path(os.environ.get("ORIGIN_LICENSE_OUTPUT", "."))
LICENSE_INDEX_PATH = Path(os.environ.get("ORIGIN_LICENSE_INDEX", "license_index.jsonl"))
LEDGER_PATH = Path(os.environ.get("ORIGIN_LICENSE_LEDGER", "license_ledger.json"))
LEDGER_PRIVATE_KEY = os.environ.get("ORIGIN_LEDGER_PRIVATE_KEY", "issuer_private.pem")
LEDGER_PUBLIC_KEY = os.environ.get("ORIGIN_LEDGER_PUBLIC_KEY", "issuer_public.pem")
LICENSE_PRIVATE_KEY = os.environ.get("ORIGIN_LICENSE_PRIVATE_KEY", "issuer_private.pem")
LICENSE_PUBLIC_KEY = os.environ.get("ORIGIN_LICENSE_PUBLIC_KEY", "issuer_public.pem")
PLAN_NAME = os.environ.get("ORIGIN_PLAN_NAME", "pro")
PLAN_DURATION_DAYS = int(os.environ.get("ORIGIN_PLAN_DAYS", "30"))

SMTP_HOST = os.environ.get("ORIGIN_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("ORIGIN_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("ORIGIN_SMTP_USER", "")
SMTP_PASS = os.environ.get("ORIGIN_SMTP_PASS", "")
SMTP_FROM = os.environ.get("ORIGIN_SMTP_FROM", SMTP_USER)
AUTH_STATE_PATH = Path(os.environ.get("ORIGIN_AUTH_STATE", str(APP_DIR / "authority_state.json")))
EVENT_LOG_PATH = Path(os.environ.get("ORIGIN_EVENT_LOG", str(APP_DIR / "ipn_events.jsonl")))


@dataclass(frozen=True)
class IPNEvent:
    raw: dict[str, str]

    @property
    def payer_email(self) -> str:
        return self.raw.get("payer_email") or self.raw.get("subscriber_email") or ""

    @property
    def user_id(self) -> str:
        return self.raw.get("custom") or self.payer_email

    @property
    def payment_status(self) -> str:
        return self.raw.get("payment_status", "").lower()

    @property
    def txn_type(self) -> str:
        return self.raw.get("txn_type", "").lower()


def _post_ipn_verify(payload: bytes) -> bool:
    verify_url = os.environ.get("PAYPAL_VERIFY_URL", DEFAULT_VERIFY_URL)
    data = b"cmd=_notify-validate&" + payload
    request = Request(verify_url, data=data, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urlopen(request, timeout=10) as response:
        return response.read().decode("utf-8").strip() == "VERIFIED"


def _iso_in(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _run_cli(args: Sequence[str]) -> None:
    result = subprocess.run(list(args), check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())


def _log_event(event: dict[str, object]) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    event["logged_at"] = datetime.now(timezone.utc).isoformat()
    with EVENT_LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event) + "\n")


def _load_authority_state() -> dict[str, object]:
    if not AUTH_STATE_PATH.exists():
        return {"banned_users": [], "coupons": []}
    try:
        return json.loads(AUTH_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"banned_users": [], "coupons": []}


def _issue_license(user_id: str) -> Path:
    LICENSE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    license_path = LICENSE_OUTPUT_DIR / f"{user_id.replace('@', '_')}.originlicense"
    _run_cli(
        [
            "origin",
            "license-issue",
            "--user-id",
            user_id,
            "--plan",
            PLAN_NAME,
            "--expires-at",
            _iso_in(PLAN_DURATION_DAYS),
            "--private-key",
            LICENSE_PRIVATE_KEY,
            "--public-key",
            LICENSE_PUBLIC_KEY,
            "--output",
            str(license_path),
            "--force",
        ]
    )
    return license_path


def _record_license(user_id: str, license_id: str, license_path: Path) -> None:
    entry = {
        "user_id": user_id,
        "license_id": license_id,
        "license_path": str(license_path),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    LICENSE_INDEX_PATH.write_text(
        (LICENSE_INDEX_PATH.read_text(encoding="utf-8") if LICENSE_INDEX_PATH.exists() else "")
        + json.dumps(entry)
        + "\n",
        encoding="utf-8",
    )


def _latest_license_id(user_id: str) -> str | None:
    if not LICENSE_INDEX_PATH.exists():
        return None
    lines = LICENSE_INDEX_PATH.read_text(encoding="utf-8").splitlines()
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("user_id") == user_id:
            return entry.get("license_id")
    return None


def _extract_license_id(path: Path) -> str:
    payload = json.loads(path.read_text(encoding="utf-8"))
    license_obj = payload.get("license", {})
    return license_obj.get("license_id", "")


def _update_ledger(license_id: str, reason: str) -> None:
    _run_cli(
        [
            "origin",
            "license-ledger-add",
            "--ledger",
            str(LEDGER_PATH),
            "--license-id",
            license_id,
            "--revoked-at",
            datetime.now(timezone.utc).isoformat(),
            "--reason",
            reason,
            "--private-key",
            LEDGER_PRIVATE_KEY,
            "--public-key",
            LEDGER_PUBLIC_KEY,
            "--output",
            str(LEDGER_PATH),
        ]
    )


def _send_email(to_address: str, license_path: Path) -> None:
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        return
    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = to_address
    msg["Subject"] = "Your Origin membership license"
    msg.set_content("Attached is your Origin membership license file.")
    msg.add_attachment(
        license_path.read_bytes(),
        maintype="application",
        subtype="octet-stream",
        filename=license_path.name,
    )
    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls(context=context)
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)


def _is_payment_event(event: IPNEvent) -> bool:
    if event.payment_status == "completed":
        return True
    return event.txn_type in {"subscr_payment", "recurring_payment"}


def _is_cancel_event(event: IPNEvent) -> bool:
    return event.txn_type in {
        "subscr_cancel",
        "subscr_eot",
        "recurring_payment_profile_cancel",
    } or event.payment_status in {"refunded", "reversed"}


class IPNHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if not _post_ipn_verify(body):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"INVALID")
            _log_event({"event_type": "error", "error": "invalid_ipn"})
            return

        payload = {key: value[0] for key, value in parse_qs(body.decode("utf-8")).items()}
        event = IPNEvent(payload)
        user_id = event.user_id
        auth_state = _load_authority_state()
        banned_users = {entry.get("user_id") for entry in auth_state.get("banned_users", []) if entry}
        if user_id in banned_users:
            _log_event({
                "event_type": "error",
                "error": "user_banned",
                "user_id": user_id,
                "payer_email": event.payer_email,
            })
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"BANNED")
            return

        try:
            if _is_payment_event(event):
                amount_raw = payload.get("mc_gross") or payload.get("payment_gross")
                try:
                    amount_value = float(amount_raw) if amount_raw is not None else None
                except (TypeError, ValueError):
                    amount_value = None
                license_path = _issue_license(user_id)
                license_id = _extract_license_id(license_path)
                if license_id:
                    _record_license(user_id, license_id, license_path)
                if event.payer_email:
                    _send_email(event.payer_email, license_path)
                _log_event(
                    {
                        "event_type": "payment",
                        "user_id": user_id,
                        "payer_email": event.payer_email,
                        "license_id": license_id,
                        "txn_type": event.txn_type,
                        "amount": amount_value,
                        "currency": payload.get("mc_currency"),
                    }
                )

            if _is_cancel_event(event):
                license_id = _latest_license_id(user_id)
                if license_id:
                    _update_ledger(license_id, "Canceled subscription")
                _log_event(
                    {
                        "event_type": "cancel",
                        "user_id": user_id,
                        "payer_email": event.payer_email,
                        "license_id": license_id,
                        "txn_type": event.txn_type,
                    }
                )
        except Exception as exc:
            _log_event(
                {
                    "event_type": "error",
                    "user_id": user_id,
                    "payer_email": event.payer_email,
                    "error": str(exc),
                }
            )
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"ERROR: {exc}".encode("utf-8"))
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")


def run() -> None:
    host = os.environ.get("ORIGIN_IPN_HOST", "0.0.0.0")
    port = int(os.environ.get("ORIGIN_IPN_PORT", "8080"))
    server = HTTPServer((host, port), IPNHandler)
    print(f"Origin IPN listener running on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
