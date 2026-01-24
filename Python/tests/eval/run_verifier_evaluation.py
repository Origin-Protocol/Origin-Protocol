from __future__ import annotations

import json
import os
import shutil
import subprocess
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
from origin_protocol.verify import verify_sealed_bundle_detailed
from origin_protocol.policy import VerificationPolicy, verify_sealed_bundle_with_policy, apply_policy_profile

CASES_PATH = Path(__file__).resolve().parent / "eval_cases.json"
GO_ROOT = ROOT / "sdks" / "go"


@dataclass
class EvalResult:
    ok: bool
    reason: str | None
    raw: str | None = None


def load_cases() -> list[dict[str, object]]:
    payload = json.loads(CASES_PATH.read_text())
    return payload.get("cases", [])


def python_verify(case: dict[str, object]) -> EvalResult:
    case_type = case["type"]
    base = CASES_PATH.parent
    if case_type == "sidecar":
        sidecar_path = base / str(case["sidecar"])
        errors = validate_origin_payload(sidecar_path.read_bytes())
        if errors:
            reason = errors[0]
            if reason == "payload_missing_field":
                reason = "payload_missing_keys"
            return EvalResult(False, reason)
        return EvalResult(True, None)
    if case_type == "mp4":
        media_path = base / str(case["media"])
        payloads = extract_uuid_payloads(media_path)
        if not payloads:
            return EvalResult(False, "payload_missing_keys")
        errors = validate_origin_payload(payloads[0].payload)
        if errors:
            reason = errors[0]
            if reason == "payload_missing_field":
                reason = "payload_missing_keys"
            return EvalResult(False, reason)
        return EvalResult(True, None)
    if case_type == "mkv":
        media_path = base / str(case["media"])
        payloads = extract_origin_payloads(media_path)
        if not payloads:
            return EvalResult(False, "payload_missing_keys")
        errors = validate_origin_payload(payloads[0].payload)
        if errors:
            reason = errors[0]
            if reason == "payload_missing_field":
                reason = "payload_missing_keys"
            return EvalResult(False, reason)
        return EvalResult(True, None)
    if case_type == "sealed_bundle":
        bundle_path = base / str(case["bundle"])
        ok, _, reason = verify_sealed_bundle_detailed(bundle_path)
        return EvalResult(ok, reason)
    if case_type == "policy":
        bundle_path = base / str(case["bundle"])
        policy_payload = case.get("policy", {})
        if not isinstance(policy_payload, dict):
            return EvalResult(False, "policy_invalid")
        policy = VerificationPolicy(
            platform=policy_payload.get("platform"),
            region=policy_payload.get("region"),
            usage_context=policy_payload.get("usage_context"),
            attestation_purpose=policy_payload.get("attestation_purpose"),
            require_platform_match=policy_payload.get("require_platform_match", False),
            require_creator_id=policy_payload.get("require_creator_id"),
            require_content_hash_match=policy_payload.get("require_content_hash_match", True),
            require_seal=policy_payload.get("require_seal", False),
            revocation_list_path=(base / policy_payload["revocation_list_path"]) if policy_payload.get("revocation_list_path") else None,
            require_revocation_check=policy_payload.get("require_revocation_check", False),
            key_registry_path=(base / policy_payload["key_registry_path"]) if policy_payload.get("key_registry_path") else None,
            require_key_registry=policy_payload.get("require_key_registry", False),
            require_key_id_match=policy_payload.get("require_key_id_match", False),
            attestation_path=(base / policy_payload["attestation_path"]) if policy_payload.get("attestation_path") else None,
            attestation_signature_path=(base / policy_payload["attestation_signature_path"]) if policy_payload.get("attestation_signature_path") else None,
            trust_store_path=(base / policy_payload["trust_store_path"]) if policy_payload.get("trust_store_path") else None,
            require_attestation=policy_payload.get("require_attestation", False),
        )
        profile = policy_payload.get("profile")
        if isinstance(profile, str):
            policy = apply_policy_profile(policy, profile)
        result = verify_sealed_bundle_with_policy(bundle_path, policy)
        return EvalResult(result.ok, result.reasons[0] if result.reasons else None)
    return EvalResult(False, "unsupported_case")


def parse_go_output(stdout: str) -> EvalResult:
    text = stdout.strip()
    if "exit status" in text:
        text = text.split("exit status", 1)[0].strip()
    if "Origin payload verified" in text:
        return EvalResult(True, None, raw=text)
    if "Origin payload invalid:" in text:
        reason = text.split("Origin payload invalid:", 1)[1].strip()
        return EvalResult(False, reason, raw=text)
    if "Sidecar verified" in text:
        return EvalResult(True, None, raw=text)
    if "Sidecar verification failed:" in text:
        reason = text.split("Sidecar verification failed:", 1)[1].strip()
        return EvalResult(False, reason, raw=text)
    if "Sealed bundle verified" in text:
        return EvalResult(True, None, raw=text)
    if "Sealed bundle invalid:" in text:
        reason = text.split("Sealed bundle invalid:", 1)[1].strip()
        return EvalResult(False, reason, raw=text)
    if "No Origin payload found" in text:
        return EvalResult(False, "payload_missing_keys", raw=text)
    return EvalResult(False, "execution_error", raw=text)


def go_verify(case: dict[str, object]) -> EvalResult | None:
    if not GO_ROOT.exists():
        return None
    if not shutil.which("go"):
        return None
    case_type = case["type"]
    base = CASES_PATH.parent
    if case_type == "sidecar":
        media = base / str(case["media"])
        sidecar = base / str(case["sidecar"])
        cmd = ["go", "run", "sidecar_verifier.go", str(media), str(sidecar)]
    elif case_type == "mp4":
        media = base / str(case["media"])
        cmd = ["go", "run", "./cmd/mp4_verifier", str(media)]
    elif case_type == "mkv":
        media = base / str(case["media"])
        cmd = ["go", "run", "./cmd/mkv_verifier", str(media)]
    elif case_type == "sealed_bundle":
        bundle = base / str(case["bundle"])
        cmd = ["go", "run", "./cmd/sealed_bundle_verifier", str(bundle)]
    elif case_type == "policy":
        return None
    else:
        return None

    try:
        result = subprocess.run(
            cmd,
            cwd=GO_ROOT,
            capture_output=True,
            text=True,
            env={**os.environ},
        )
    except Exception as exc:
        return EvalResult(False, "execution_error", raw=str(exc))
    output = (result.stdout or "") + (result.stderr or "")
    return parse_go_output(output)


def score_results(results: list[dict[str, object]]) -> dict[str, object]:
    total = len(results)
    correct = sum(1 for r in results if r["match_expected"])
    invalid_cases = [r for r in results if not r["expected_ok"]]
    correct_reason = sum(1 for r in invalid_cases if r["match_reason"])
    robustness = sum(1 for r in results if r["python_status"] != "error")
    return {
        "total": total,
        "accuracy": correct / total if total else 0.0,
        "reason_accuracy": correct_reason / len(invalid_cases) if invalid_cases else 0.0,
        "parsing_robustness": robustness / total if total else 0.0,
    }


def run() -> None:
    cases = load_cases()
    report: list[dict[str, object]] = []
    mismatches: list[dict[str, object]] = []

    for case in cases:
        expected_ok = bool(case.get("expected_ok"))
        expected_reason = case.get("expected_reason")

        python_result = python_verify(case)
        python_match = python_result.ok == expected_ok
        python_reason_match = True
        if not expected_ok:
            python_reason_match = python_result.reason == expected_reason

        go_result = go_verify(case)
        go_match = None
        go_reason_match = None
        if go_result is not None:
            go_match = go_result.ok == expected_ok
            go_reason_match = True
            if not expected_ok:
                go_reason_match = go_result.reason == expected_reason
            if (python_result.ok, python_result.reason) != (go_result.ok, go_result.reason):
                mismatches.append(
                    {
                        "id": case["id"],
                        "python": {"ok": python_result.ok, "reason": python_result.reason},
                        "go": {"ok": go_result.ok, "reason": go_result.reason},
                    }
                )

        report.append(
            {
                "id": case["id"],
                "type": case["type"],
                "expected_ok": expected_ok,
                "expected_reason": expected_reason,
                "python_ok": python_result.ok,
                "python_reason": python_result.reason,
                "python_status": "ok" if python_result.ok or python_result.reason else "error",
                "match_expected": python_match,
                "match_reason": python_reason_match,
                "go_ok": go_result.ok if go_result else None,
                "go_reason": go_result.reason if go_result else None,
                "go_match_expected": go_match,
                "go_match_reason": go_reason_match,
            }
        )

    summary = score_results(report)
    output = {
        "summary": summary,
        "cases": report,
        "mismatches": mismatches,
    }

    output_path = CASES_PATH.parent / "evaluation_report.json"
    output_path.write_text(json.dumps(output, indent=2, sort_keys=True))
    print(f"Evaluation report saved to {output_path}")


if __name__ == "__main__":
    run()
