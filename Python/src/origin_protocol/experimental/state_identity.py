"""State identity primitives for coherence-aware content identity."""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass


@dataclass
class IdentityState:
    seed: str
    coherence: float
    entropy: float
    signature: str


def _compute_signature(seed: str, coherence: float, entropy: float, secret: str = "") -> str:
    data = f"{seed}:{coherence}:{entropy}".encode()
    if secret:
        return hmac.new(secret.encode(), data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def initialize_state(
    seed: str,
    secret: str = "",
    coherence: float = 1.0,
    entropy: float = 0.0,
) -> IdentityState:
    sig = _compute_signature(seed, coherence, entropy, secret)
    return IdentityState(seed=seed, coherence=coherence, entropy=entropy, signature=sig)


def compute_state_signature(state: IdentityState, secret: str = "") -> str:
    return _compute_signature(state.seed, state.coherence, state.entropy, secret)


def evolve_state(
    state: IdentityState,
    coherence_drift: float = 0.0,
    entropy_drift: float = 0.0,
) -> IdentityState:
    new_coherence = state.coherence + coherence_drift
    new_entropy = state.entropy + entropy_drift
    new_sig = _compute_signature(state.seed, new_coherence, new_entropy)
    return IdentityState(
        seed=state.seed,
        coherence=new_coherence,
        entropy=new_entropy,
        signature=new_sig,
    )


def validate_state(state: IdentityState, coherence_threshold: float = 0.5) -> bool:
    return state.coherence >= coherence_threshold
