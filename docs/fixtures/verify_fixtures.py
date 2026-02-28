import json
from pathlib import Path

from origin_protocol.bundle import bundle_manifest_from_bytes
from origin_protocol.manifest import hash_bytes
from origin_protocol.mkv import extract_origin_payloads
from origin_protocol.mp4 import extract_uuid_payloads

FIXTURE_DIR = Path(__file__).parent


def _pretty_payload(payload: bytes) -> str:
    try:
        return json.dumps(json.loads(payload.decode("utf-8")), indent=2, sort_keys=True)
    except Exception:
        return payload.decode("utf-8", errors="replace")


def _validate_payload(payload_bytes: bytes) -> list[str]:
    reasons: list[str] = []
    try:
        payload_json = json.loads(payload_bytes.decode("utf-8"))
    except json.JSONDecodeError:
        return ["payload_invalid_json"]

    payload = payload_json.get("payload", {})
    required = {
        "bundle.json",
        "bundle.sig",
        "manifest.json",
        "signature.ed25519",
        "seal.json",
        "seal.ed25519",
        "public_key.ed25519",
    }
    missing = required - set(payload.keys())
    if missing:
        reasons.append("payload_missing_keys")
        return reasons

    bundle_manifest_bytes = base64.b64decode(payload["bundle.json"])
    bundle_manifest = bundle_manifest_from_bytes(bundle_manifest_bytes)
    entries = {entry.path: entry.sha256 for entry in bundle_manifest.entries}

    for key in required - {"bundle.sig"}:
        if key not in entries:
            reasons.append("bundle_manifest_missing_entry")
            continue
        data = base64.b64decode(payload[key])
        if hash_bytes(data) != entries[key]:
            reasons.append("bundle_manifest_hash_mismatch")

    return reasons


def verify_mp4() -> None:
    path = FIXTURE_DIR / "origin_fixture.mp4"
    payloads = extract_uuid_payloads(path)
    if not payloads:
        print("MP4: no Origin payloads found")
        return
    print("MP4: Origin payload found")
    print(_pretty_payload(payloads[0].payload))
    reasons = _validate_payload(payloads[0].payload)
    if reasons:
        print(f"MP4: payload validation issues: {reasons}")


def verify_mkv() -> None:
    path = FIXTURE_DIR / "origin_fixture.mkv"
    payloads = extract_origin_payloads(path)
    if not payloads:
        print("MKV: no Origin payloads found")
        return
    print("MKV: Origin payload found")
    print(_pretty_payload(payloads[0].payload))
    reasons = _validate_payload(payloads[0].payload)
    if reasons:
        print(f"MKV: payload validation issues: {reasons}")


def main() -> None:
    verify_mp4()
    verify_mkv()


if __name__ == "__main__":
    main()
