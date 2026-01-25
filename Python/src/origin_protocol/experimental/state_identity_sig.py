from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass, replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from origin_protocol.keys import public_key_fingerprint
from .state_identity import IdentityState, evolve_state, initialize_state, _state_payload

SIGNATURE_ALGORITHM = "ed25519"


@dataclass(frozen=True)
class StateSignature:
    algorithm: str
    key_id: str
    signature: bytes


def format_state_signature(signature: StateSignature) -> str:
    encoded = b64encode(signature.signature).decode("ascii")
    return f"{signature.algorithm}:{signature.key_id}:{encoded}"


def parse_state_signature(value: str) -> StateSignature:
    parts = value.split(":", 2)
    if len(parts) != 3:
        raise ValueError("Invalid signature format")
    algorithm, key_id, encoded = parts
    if not algorithm or not key_id or not encoded:
        raise ValueError("Invalid signature format")
    try:
        signature = b64decode(encoded.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError("Invalid signature encoding") from exc
    return StateSignature(algorithm=algorithm, key_id=key_id, signature=signature)


def sign_state(
    state: IdentityState,
    private_key: Ed25519PrivateKey,
    *,
    key_id: str | None = None,
) -> IdentityState:
    payload = _state_payload(state)
    signature = private_key.sign(payload)
    resolved_key_id = key_id or public_key_fingerprint(private_key.public_key())
    encoded = format_state_signature(
        StateSignature(algorithm=SIGNATURE_ALGORITHM, key_id=resolved_key_id, signature=signature)
    )
    return replace(state, signature=encoded)


def verify_state_signature(
    state: IdentityState,
    public_key: Ed25519PublicKey,
    *,
    expected_key_id: str | None = None,
) -> bool:
    try:
        parsed = parse_state_signature(state.signature)
    except ValueError:
        return False

    if parsed.algorithm.lower() != SIGNATURE_ALGORITHM:
        return False

    derived_key_id = public_key_fingerprint(public_key)
    if parsed.key_id != derived_key_id:
        return False
    if expected_key_id is not None and parsed.key_id != expected_key_id:
        return False

    payload = _state_payload(state)
    try:
        public_key.verify(parsed.signature, payload)
    except Exception:
        return False

    return True


def initialize_state_signed(
    *,
    seed: str,
    private_key: Ed25519PrivateKey,
    key_id: str | None = None,
    coherence: float = 0.8,
    entropy_level: float = 0.2,
    harmonics: tuple[float, ...] = (1.0, 0.5, 0.25),
) -> IdentityState:
    state = initialize_state(
        seed=seed,
        coherence=coherence,
        entropy_level=entropy_level,
        harmonics=harmonics,
        secret=None,
    )
    return sign_state(state, private_key, key_id=key_id)


def evolve_state_signed(
    state: IdentityState,
    *,
    private_key: Ed25519PrivateKey,
    key_id: str | None = None,
    coherence_drift: float = -0.01,
    entropy_drift: float = 0.01,
    harmonics_delta: tuple[float, ...] | None = None,
) -> IdentityState:
    evolved = evolve_state(
        state,
        coherence_drift=coherence_drift,
        entropy_drift=entropy_drift,
        harmonics_delta=harmonics_delta,
        secret=None,
    )
    return sign_state(evolved, private_key, key_id=key_id)
