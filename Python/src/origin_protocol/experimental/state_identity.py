from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Iterable


@dataclass(frozen=True)
class IdentityState:
    """Experimental identity state.

    This model is non-critical to Origin Protocol and may be replaced.
    """

    state_id: str
    created_at: str
    coherence: float
    entropy_level: float
    harmonics: tuple[float, ...]
    signature: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_harmonics(values: Iterable[float]) -> tuple[float, ...]:
    items = tuple(float(value) for value in values)
    if not items:
        return (1.0,)
    norm = math.sqrt(sum(value * value for value in items))
    if norm == 0:
        return tuple(0.0 for _ in items)
    return tuple(value / norm for value in items)


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _state_payload(state: IdentityState) -> bytes:
    harmonics = ",".join(f"{value:.6f}" for value in state.harmonics)
    raw = f"{state.state_id}|{state.created_at}|{state.coherence:.6f}|{state.entropy_level:.6f}|{harmonics}"
    return raw.encode("utf-8")


def compute_state_signature(state: IdentityState, secret: str | None = None) -> str:
    payload = _state_payload(state)
    if secret:
        return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(payload).hexdigest()


def initialize_state(
    *,
    seed: str,
    coherence: float = 0.8,
    entropy_level: float = 0.2,
    harmonics: Iterable[float] = (1.0, 0.5, 0.25),
    secret: str | None = None,
) -> IdentityState:
    normalized = _normalize_harmonics(harmonics)
    state = IdentityState(
        state_id=hashlib.sha256(seed.encode("utf-8")).hexdigest(),
        created_at=_now_iso(),
        coherence=_clamp(coherence),
        entropy_level=_clamp(entropy_level),
        harmonics=normalized,
        signature="",
    )
    signature = compute_state_signature(state, secret=secret)
    return replace(state, signature=signature)


def evolve_state(
    state: IdentityState,
    *,
    coherence_drift: float = -0.01,
    entropy_drift: float = 0.01,
    harmonics_delta: Iterable[float] | None = None,
    secret: str | None = None,
) -> IdentityState:
    harmonics = state.harmonics
    if harmonics_delta is not None:
        delta = tuple(float(value) for value in harmonics_delta)
        harmonics = tuple(value + delta[idx] if idx < len(delta) else value for idx, value in enumerate(harmonics))
    harmonics = _normalize_harmonics(harmonics)

    updated = replace(
        state,
        coherence=_clamp(state.coherence + coherence_drift),
        entropy_level=_clamp(state.entropy_level + entropy_drift),
        harmonics=harmonics,
    )
    signature = compute_state_signature(updated, secret=secret)
    return replace(updated, signature=signature)


def validate_state(state: IdentityState, *, coherence_threshold: float = 0.6) -> bool:
    if not (0.0 <= state.coherence <= 1.0):
        return False
    if not (0.0 <= state.entropy_level <= 1.0):
        return False
    if state.coherence < coherence_threshold:
        return False
    if not state.harmonics:
        return False
    return True
