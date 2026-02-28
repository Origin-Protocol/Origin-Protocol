"""State identity module for managing creator state with coherence and entropy tracking."""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Optional


@dataclass(frozen=True)
class StateIdentity:
    seed: str
    coherence: float
    entropy: float
    created_at: str
    signature: str


def _canonical_payload(state: StateIdentity) -> bytes:
    """Return a deterministic JSON encoding of the non-signature state fields."""
    payload = {
        "seed": state.seed,
        "coherence": state.coherence,
        "entropy": state.entropy,
        "created_at": state.created_at,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_state_signature(state: StateIdentity, secret: Optional[str] = None) -> str:
    """Compute a deterministic signature string for *state*.

    When *secret* is provided an HMAC-SHA-256 is used; otherwise a plain
    SHA-256 digest of the canonical payload is returned.
    """
    payload = _canonical_payload(state)
    if secret:
        return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(payload).hexdigest()


def initialize_state(
    seed: str,
    secret: Optional[str] = None,
    coherence: float = 1.0,
) -> StateIdentity:
    """Create a new :class:`StateIdentity` for *seed* and compute its signature."""
    entropy = 0.0
    created_at = datetime.now(timezone.utc).isoformat()
    partial = StateIdentity(
        seed=seed,
        coherence=coherence,
        entropy=entropy,
        created_at=created_at,
        signature="",
    )
    sig = compute_state_signature(partial, secret=secret)
    return replace(partial, signature=sig)


def evolve_state(
    state: StateIdentity,
    coherence_drift: float = 0.0,
    entropy_drift: float = 0.0,
) -> StateIdentity:
    """Return a new :class:`StateIdentity` with updated coherence and entropy."""
    new_coherence = max(0.0, min(1.0, state.coherence + coherence_drift))
    new_entropy = max(0.0, min(1.0, state.entropy + entropy_drift))
    evolved = StateIdentity(
        seed=state.seed,
        coherence=new_coherence,
        entropy=new_entropy,
        created_at=datetime.now(timezone.utc).isoformat(),
        signature="",
    )
    sig = compute_state_signature(evolved)
    return replace(evolved, signature=sig)


def validate_state(state: StateIdentity, coherence_threshold: float = 0.5) -> bool:
    """Return ``True`` if *state* meets the minimum coherence threshold."""
    return state.coherence >= coherence_threshold
