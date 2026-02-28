"""Ed25519 cryptographic signatures for :class:`~.state_identity.StateIdentity` objects."""
from __future__ import annotations

import base64
from dataclasses import dataclass, replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..keys import public_key_fingerprint
from .state_identity import StateIdentity, _canonical_payload

SIGNATURE_ALGORITHM = "Ed25519"


@dataclass(frozen=True)
class ParsedSignature:
    algorithm: str
    key_id: str
    signature: str


def sign_state(
    state: StateIdentity,
    private_key: Ed25519PrivateKey,
    key_id: str | None = None,
) -> StateIdentity:
    """Return a copy of *state* whose ``signature`` field holds an Ed25519 signature.

    If *key_id* is not supplied it is derived from the public key of *private_key*.
    """
    if key_id is None:
        key_id = public_key_fingerprint(private_key.public_key())
    payload = _canonical_payload(state)
    raw_sig = private_key.sign(payload)
    sig_b64 = base64.b64encode(raw_sig).decode("ascii")
    sig_str = f"{SIGNATURE_ALGORITHM}:{key_id}:{sig_b64}"
    return replace(state, signature=sig_str)


def parse_state_signature(signature: str) -> ParsedSignature:
    """Parse a signature string created by :func:`sign_state` into its components."""
    parts = signature.split(":", 2)
    if len(parts) != 3:
        raise ValueError(f"Invalid signature format: {signature!r}")
    return ParsedSignature(algorithm=parts[0], key_id=parts[1], signature=parts[2])


def verify_state_signature(signed: StateIdentity, public_key: Ed25519PublicKey) -> bool:
    """Return ``True`` if *signed* carries a valid Ed25519 signature from *public_key*."""
    try:
        parsed = parse_state_signature(signed.signature)
    except Exception:
        return False

    expected_key_id = public_key_fingerprint(public_key)
    if parsed.key_id != expected_key_id:
        return False

    try:
        raw_sig = base64.b64decode(parsed.signature)
        payload = _canonical_payload(signed)
        public_key.verify(raw_sig, payload)
        return True
    except Exception:
        return False
