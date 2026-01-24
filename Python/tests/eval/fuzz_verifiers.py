from __future__ import annotations

import json
import random
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from origin_protocol.container import validate_origin_payload
from origin_protocol.mkv import extract_origin_payloads
from origin_protocol.mp4 import extract_uuid_payloads

FIXTURES = ROOT / "tests" / "eval" / "fixtures"
OUT_PATH = ROOT / "tests" / "eval" / "fuzz_report.json"


@dataclass
class FuzzCase:
    name: str
    payload: bytes


def mutate_truncate(data: bytes) -> bytes:
    if not data:
        return data
    cut = max(1, len(data) // 3)
    return data[:cut]


def mutate_flip_byte(data: bytes) -> bytes:
    if not data:
        return data
    idx = random.randint(0, len(data) - 1)
    flipped = data[:idx] + bytes([data[idx] ^ 0xFF]) + data[idx + 1 :]
    return flipped


def mutate_remove_payload_field(data: bytes) -> bytes:
    try:
        payload = json.loads(data)
    except Exception:
        return data
    if not isinstance(payload, dict):
        return data
    payload.pop("payload", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def mutate_invalid_base64(data: bytes) -> bytes:
    try:
        payload = json.loads(data)
    except Exception:
        return data
    if not isinstance(payload, dict):
        return data
    inner = payload.get("payload")
    if not isinstance(inner, dict):
        return data
    if "manifest.json" in inner:
        inner["manifest.json"] = "not-base64!!"
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_payloads() -> list[FuzzCase]:
    cases: list[FuzzCase] = []
    sidecar = FIXTURES / "sidecar" / "valid_sidecar.json"
    if sidecar.exists():
        cases.append(FuzzCase("sidecar_valid", sidecar.read_bytes()))

    mp4 = FIXTURES / "mp4" / "mp4_with_valid_uuid_payload.mp4"
    if mp4.exists():
        payloads = extract_uuid_payloads(mp4)
        if payloads:
            cases.append(FuzzCase("mp4_payload", payloads[0].payload))

    mkv = FIXTURES / "mkv" / "mkv_with_valid_origin_tag.mkv"
    if mkv.exists():
        payloads = extract_origin_payloads(mkv)
        if payloads:
            cases.append(FuzzCase("mkv_payload", payloads[0].payload))

    return cases


def run_mutations(payload: bytes) -> list[tuple[str, bytes]]:
    return [
        ("truncate", mutate_truncate(payload)),
        ("flip_byte", mutate_flip_byte(payload)),
        ("remove_payload", mutate_remove_payload_field(payload)),
        ("invalid_base64", mutate_invalid_base64(payload)),
    ]


def evaluate_case(case: FuzzCase) -> dict[str, object]:
    results: list[dict[str, object]] = []
    for name, mutated in run_mutations(case.payload):
        try:
            errors = validate_origin_payload(mutated)
            results.append({"mutation": name, "errors": errors})
        except Exception as exc:
            results.append({"mutation": name, "errors": ["exception"], "exception": str(exc)})
    return {"case": case.name, "mutations": results}


def run() -> None:
    random.seed(42)
    cases = load_payloads()
    report = {
        "cases": [evaluate_case(case) for case in cases],
        "total_cases": len(cases),
    }
    OUT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True))
    print(f"Fuzz report saved to {OUT_PATH}")


if __name__ == "__main__":
    run()
