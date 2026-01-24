from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib import request as urlrequest


def _post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    api_key = os.environ.get("ORIGIN_API_KEY", "").strip()
    if api_key:
        headers["X-Origin-API-Key"] = api_key
    req = urlrequest.Request(url, data=data, headers=headers)
    with urlrequest.urlopen(req, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9040"
    cases_path = Path(__file__).with_name("cases.json")
    cases = json.loads(cases_path.read_text(encoding="utf-8"))

    failures = 0
    for case in cases:
        response = _post_json(f"{base_url}/v1/ledger/verify", case["request"])
        ok = response.get("ok")
        reasons = [item.get("code") for item in response.get("reasons", [])]
        expected_ok = case["expected_ok"]
        expected_reasons = case.get("expected_reasons", [])
        if ok != expected_ok or sorted(reasons) != sorted(expected_reasons):
            failures += 1
            print(f"FAIL {case['id']}: ok={ok} reasons={reasons} expected_ok={expected_ok} expected_reasons={expected_reasons}")
        else:
            print(f"PASS {case['id']}")

    if failures:
        print(f"{failures} failures")
        return 1
    print("All cases passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
