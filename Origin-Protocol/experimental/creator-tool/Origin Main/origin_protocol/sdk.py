from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Mapping

from .policy import VerificationPolicy, verify_bundle_with_policy, verify_sealed_bundle_with_policy
from .reasons import format_reasons


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    reasons: tuple[str, ...]
    reason_details: tuple[tuple[str, str], ...]
    categories: tuple[str, ...]
    subcategories: tuple[str, ...]
    severities: tuple[str, ...]
    is_fatal: tuple[bool, ...]
    creator_actions: tuple[str, ...]
    platform_actions: tuple[str, ...]
    remediations: tuple[str, ...]
    localization_keys: tuple[str, ...]
    docs_urls: tuple[str, ...]
    revoked: bool
    revocation_details: tuple[dict[str, str], ...]


def _revocation_details(entries: tuple[object, ...]) -> tuple[dict[str, str], ...]:
    details: list[dict[str, str]] = []
    for entry in entries:
        if hasattr(entry, "__dict__"):
            entry_dict = {
                key: str(value)
                for key, value in entry.__dict__.items()
                if value is not None
            }
            details.append(entry_dict)
    return tuple(details)


def verify_unsealed(
    bundle_dir: Path,
    policy: VerificationPolicy,
    file_path: Path | None = None,
    localization: Mapping[str, str] | None = None,
) -> VerificationResult:
    result = verify_bundle_with_policy(bundle_dir, policy, file_path=file_path)
    formatted = format_reasons(result.reasons)
    reason_details = tuple(
        (reason.code, localization.get(reason.localization_key, reason.message) if localization else reason.message)
        for reason in formatted
    )
    return VerificationResult(
        result.ok,
        result.reasons,
        reason_details,
        tuple(reason.category for reason in formatted),
        tuple(reason.subcategory for reason in formatted),
        tuple(reason.severity for reason in formatted),
        tuple(reason.is_fatal for reason in formatted),
        tuple(reason.creator_action for reason in formatted),
        tuple(reason.platform_action for reason in formatted),
        tuple(reason.remediation for reason in formatted),
        tuple(reason.localization_key for reason in formatted),
        tuple(reason.docs_url for reason in formatted),
        revoked="revoked" in result.reasons,
        revocation_details=_revocation_details(result.revocation_entries),
    )


def verify_sealed(
    bundle_path: Path,
    policy: VerificationPolicy,
    localization: Mapping[str, str] | None = None,
) -> VerificationResult:
    result = verify_sealed_bundle_with_policy(bundle_path, policy)
    formatted = format_reasons(result.reasons)
    reason_details = tuple(
        (reason.code, localization.get(reason.localization_key, reason.message) if localization else reason.message)
        for reason in formatted
    )
    return VerificationResult(
        result.ok,
        result.reasons,
        reason_details,
        tuple(reason.category for reason in formatted),
        tuple(reason.subcategory for reason in formatted),
        tuple(reason.severity for reason in formatted),
        tuple(reason.is_fatal for reason in formatted),
        tuple(reason.creator_action for reason in formatted),
        tuple(reason.platform_action for reason in formatted),
        tuple(reason.remediation for reason in formatted),
        tuple(reason.localization_key for reason in formatted),
        tuple(reason.docs_url for reason in formatted),
        revoked="revoked" in result.reasons,
        revocation_details=_revocation_details(result.revocation_entries),
    )


def as_dict(result: VerificationResult) -> dict[str, object]:
    return {
        "ok": result.ok,
        "reasons": list(result.reasons),
        "reason_details": list(result.reason_details),
        "categories": list(result.categories),
        "subcategories": list(result.subcategories),
        "severities": list(result.severities),
        "is_fatal": list(result.is_fatal),
        "creator_actions": list(result.creator_actions),
        "platform_actions": list(result.platform_actions),
        "remediations": list(result.remediations),
        "localization_keys": list(result.localization_keys),
        "docs_urls": list(result.docs_urls),
        "revoked": result.revoked,
        "revocation_details": list(result.revocation_details),
    }


def load_localization(path: Path) -> Mapping[str, str]:
    return json.loads(path.read_text())
