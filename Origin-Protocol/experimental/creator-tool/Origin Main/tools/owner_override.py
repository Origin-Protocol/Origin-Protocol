from __future__ import annotations

import argparse
import sys
import base64
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import platform
import uuid

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from origin_protocol.keys import generate_keypair, save_keypair, load_private_key

APP_DIR = Path.home() / ".origin_protocol"
OWNER_KEYS_DIR = APP_DIR / "owner_keys"
OWNER_PRIVATE_KEY_PATH = OWNER_KEYS_DIR / "private_key.ed25519"
OWNER_PUBLIC_KEY_PATH = APP_DIR / "owner_public_key.ed25519"
OWNER_TOKEN_PATH = APP_DIR / "owner_token.json"


def device_fingerprint() -> str:
    raw = "|".join(
        [
            platform.system(),
            platform.release(),
            platform.machine(),
            platform.node(),
            str(uuid.getnode()),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class OwnerToken:
    token_id: str
    issued_at: str
    owner_id: str
    device_fingerprint: str | None = None
    expires_at: str | None = None


def _write_token(token: OwnerToken, signature: bytes) -> None:
    payload = {
        "token": {key: value for key, value in asdict(token).items() if value is not None},
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    OWNER_TOKEN_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def init_keys() -> None:
    OWNER_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    keypair = generate_keypair()
    private_path, public_path = save_keypair(keypair, OWNER_KEYS_DIR)
    OWNER_PUBLIC_KEY_PATH.write_bytes(public_path.read_bytes())
    print(f"Owner private key: {private_path}")
    print(f"Owner public key: {OWNER_PUBLIC_KEY_PATH}")


def issue_token(owner_id: str, bind_device: bool, days: int | None) -> None:
    if not OWNER_PRIVATE_KEY_PATH.exists():
        raise SystemExit("Owner private key not found. Run init-keys first.")
    private_key = load_private_key(OWNER_PRIVATE_KEY_PATH)
    expires_at = None
    if days is not None:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    token = OwnerToken(
        token_id=str(uuid.uuid4()),
        issued_at=datetime.now(timezone.utc).isoformat(),
        owner_id=owner_id,
        device_fingerprint=device_fingerprint() if bind_device else None,
        expires_at=expires_at,
    )
    token_dict = {key: value for key, value in asdict(token).items() if value is not None}
    token_bytes = json.dumps(token_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = private_key.sign(token_bytes)
    _write_token(token, signature)
    print(f"Owner token written: {OWNER_TOKEN_PATH}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Owner override tooling")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init-keys", help="Create owner override keys")
    init.set_defaults(func=lambda _args: init_keys())

    token = sub.add_parser("issue-token", help="Issue owner override token")
    token.add_argument("--owner-id", required=True)
    token.add_argument("--bind-device", action="store_true")
    token.add_argument("--expires-days", type=int)
    token.set_defaults(func=lambda args: issue_token(args.owner_id, args.bind_device, args.expires_days))

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
