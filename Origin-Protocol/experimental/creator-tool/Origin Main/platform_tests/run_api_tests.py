from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path


def _post_json(url: str, payload: dict[str, object]) -> dict[str, object]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _extract_reason_codes(response: dict[str, object]) -> list[str]:
    reasons = response.get("reasons", [])
    if not isinstance(reasons, list):
        return []
    codes: list[str] = []
    for item in reasons:
        if isinstance(item, dict) and "code" in item:
            codes.append(str(item["code"]))
    return codes


def main() -> int:
    base_url = os.environ.get("ORIGIN_PLATFORM_TEST_URL", "http://127.0.0.1:9050")
    cases_path = Path(__file__).parent / "cases.json"
    payload = json.loads(cases_path.read_text(encoding="utf-8"))
    failures = 0

    for case in payload:
        case_id = case.get("id", "unknown")
        request_payload = case["request"]
        expected_ok = case["expected_ok"]
        expected_reasons = case.get("expected_reasons", [])

        response = _post_json(f"{base_url}/v1/ledger/verify", request_payload)
        ok = response.get("ok")
        reason_codes = _extract_reason_codes(response)

        ok_match = ok == expected_ok
        reason_match = set(reason_codes) == set(expected_reasons)
        if not ok_match or not reason_match:
            failures += 1
            print(
                f"FAIL {case_id}: ok={ok} expected={expected_ok} reasons={reason_codes} expected={expected_reasons}"
            )
        else:
            print(f"PASS {case_id}")

    if failures:
        print(f"{failures} failures")
        return 1
    print("All platform API tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
