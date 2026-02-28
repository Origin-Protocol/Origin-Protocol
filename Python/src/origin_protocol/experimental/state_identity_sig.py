"""Ed25519 signing layer for :class:`StateIdentity` objects."""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, replace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from origin_protocol.experimental.state_identity import StateIdentity, _state_payload
from origin_protocol.keys import public_key_fingerprint

SIGNATURE_ALGORITHM = "ed25519"


@dataclass(frozen=True)
class SignatureMeta:
    algorithm: str
    key_id: str
    signature: str


def sign_state(
    state: StateIdentity,
    private_key: Ed25519PrivateKey,
    key_id: str = "",
) -> StateIdentity:
    """Sign *state* with an Ed25519 *private_key* and return a new state whose
    ``signature`` field contains a JSON envelope with algorithm, key_id, and
    the base64-encoded Ed25519 signature over the canonical state payload.
    """
    if not key_id:
        key_id = public_key_fingerprint(private_key.public_key())
    payload = _state_payload(state)
    sig_bytes = private_key.sign(payload)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
    envelope = json.dumps(
        {"algorithm": SIGNATURE_ALGORITHM, "key_id": key_id, "signature": sig_b64},
        sort_keys=True,
        separators=(",", ":"),
    )
    return replace(state, signature=envelope)


def parse_state_signature(signature: str) -> SignatureMeta:
    """Parse a JSON signature envelope produced by :func:`sign_state`."""
    data = json.loads(signature)
    return SignatureMeta(
        algorithm=data["algorithm"],
        key_id=data["key_id"],
        signature=data["signature"],
    )


def verify_state_signature(state: StateIdentity, public_key: Ed25519PublicKey) -> bool:
    """Return True if *state* carries a valid Ed25519 signature for *public_key*.

    Verification fails if the embedded ``key_id`` does not match the
    fingerprint of the provided public key, or if the cryptographic
    signature is invalid.
    """
    try:
        parsed = parse_state_signature(state.signature)
        expected_key_id = public_key_fingerprint(public_key)
        if parsed.key_id != expected_key_id:
            return False
        payload = _state_payload(state)
        sig_bytes = base64.b64decode(parsed.signature)
        public_key.verify(sig_bytes, payload)
        return True
    except (json.JSONDecodeError, KeyError, ValueError, InvalidSignature):
        return False
