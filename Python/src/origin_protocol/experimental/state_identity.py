"""Experimental state-identity primitives with explicit HMAC-SHA256 authentication."""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, replace


@dataclass
class StateIdentity:
    seed: str
    coherence: float
    entropy: float
    signature: str


def _state_payload(state: StateIdentity) -> bytes:
    """Return a deterministic canonical byte representation of the core state fields."""
    data = {"seed": state.seed, "coherence": state.coherence, "entropy": state.entropy}
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def compute_state_signature(state: StateIdentity, secret: str = "") -> str:
    """Compute an HMAC-SHA256 signature over the core state fields.

    When *secret* is provided the signature is authenticated; when empty a
    fixed internal key is used so that the output remains deterministic and
    tamper-detectable within the same process context.
    """
    key = secret.encode("utf-8") if secret else b"origin-protocol-state"
    return hmac.new(key, _state_payload(state), hashlib.sha256).hexdigest()


def initialize_state(
    seed: str,
    secret: str = "",
    coherence: float = 0.8,
    entropy: float = 0.5,
) -> StateIdentity:
    """Create a new :class:`StateIdentity` and sign it immediately."""
    state = StateIdentity(seed=seed, coherence=coherence, entropy=entropy, signature="")
    sig = compute_state_signature(state, secret=secret)
    return replace(state, signature=sig)


def evolve_state(
    state: StateIdentity,
    coherence_drift: float = 0.0,
    entropy_drift: float = 0.0,
    secret: str = "",
) -> StateIdentity:
    """Return a new :class:`StateIdentity` with updated coherence/entropy and a fresh signature."""
    evolved = replace(
        state,
        coherence=state.coherence + coherence_drift,
        entropy=state.entropy + entropy_drift,
        signature="",
    )
    sig = compute_state_signature(evolved, secret=secret)
    return replace(evolved, signature=sig)


def validate_state(state: StateIdentity, coherence_threshold: float = 0.5) -> bool:
    """Return True if the state has a non-empty signature and coherence meets the threshold."""
    return bool(state.signature) and state.coherence >= coherence_threshold
