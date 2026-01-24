from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from origin_protocol.container import validate_origin_payload
from origin_protocol.mkv import extract_origin_payloads
from origin_protocol.mp4 import extract_uuid_payloads
from origin_protocol.verify import verify_sealed_bundle_detailed

FIXTURES = ROOT / "tests" / "eval" / "fixtures"
OUT_PATH = ROOT / "tests" / "eval" / "perf_report.json"


@dataclass
class BenchResult:
    name: str
    iterations: int
    avg_ms: float
    min_ms: float
    max_ms: float


def bench(fn, iterations: int = 50) -> BenchResult:
    durations = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        durations.append((time.perf_counter() - start) * 1000.0)
    return BenchResult(
        name=fn.__name__,
        iterations=iterations,
        avg_ms=sum(durations) / iterations,
        min_ms=min(durations),
        max_ms=max(durations),
    )


def run() -> None:
    results: list[BenchResult] = []

    sidecar = FIXTURES / "sidecar" / "valid_sidecar.json"
    if sidecar.exists():
        payload = sidecar.read_bytes()
        results.append(bench(lambda: validate_origin_payload(payload)))

    mp4 = FIXTURES / "mp4" / "mp4_with_valid_uuid_payload.mp4"
    if mp4.exists():
        payloads = extract_uuid_payloads(mp4)
        if payloads:
            payload = payloads[0].payload
            results.append(bench(lambda: validate_origin_payload(payload)))

    mkv = FIXTURES / "mkv" / "mkv_with_valid_origin_tag.mkv"
    if mkv.exists():
        payloads = extract_origin_payloads(mkv)
        if payloads:
            payload = payloads[0].payload
            results.append(bench(lambda: validate_origin_payload(payload)))

    bundle = FIXTURES / "bundles" / "sealed_bundle_valid.zip"
    if bundle.exists():
        results.append(bench(lambda: verify_sealed_bundle_detailed(bundle)))

    output = {
        "results": [result.__dict__ for result in results],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    OUT_PATH.write_text(json.dumps(output, indent=2, sort_keys=True))
    print(f"Performance report saved to {OUT_PATH}")


if __name__ == "__main__":
    run()
