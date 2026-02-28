"""Cryptographic signing and verification for IdentityState objects."""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from origin_protocol.experimental.state_identity import IdentityState
from origin_protocol.keys import public_key_fingerprint

SIGNATURE_ALGORITHM = "ed25519"


@dataclass
class ParsedStateSignature:
    algorithm: str
    key_id: str
    signature: str


def sign_state(
    state: IdentityState,
    private_key: Ed25519PrivateKey,
    key_id: Optional[str] = None,
) -> IdentityState:
    pub = private_key.public_key()
    actual_key_id = key_id if key_id is not None else public_key_fingerprint(pub)
    payload = f"{state.seed}:{state.coherence}:{state.entropy}:{actual_key_id}".encode()
    raw_sig = private_key.sign(payload)
    sig_b64 = base64.b64encode(raw_sig).decode()
    combined = json.dumps(
        {"algorithm": SIGNATURE_ALGORITHM, "key_id": actual_key_id, "signature": sig_b64}
    )
    return IdentityState(
        seed=state.seed,
        coherence=state.coherence,
        entropy=state.entropy,
        signature=combined,
    )


def verify_state_signature(state: IdentityState, public_key: Ed25519PublicKey) -> bool:
    import binascii

    from cryptography.exceptions import InvalidSignature

    try:
        parsed = parse_state_signature(state.signature)
        actual_key_id = public_key_fingerprint(public_key)
        if parsed.key_id != actual_key_id:
            return False
        payload = f"{state.seed}:{state.coherence}:{state.entropy}:{parsed.key_id}".encode()
        raw_sig = base64.b64decode(parsed.signature)
        public_key.verify(raw_sig, payload)
        return True
    except (json.JSONDecodeError, KeyError, ValueError, binascii.Error, InvalidSignature):
        return False


def parse_state_signature(signature: str) -> ParsedStateSignature:
    data = json.loads(signature)
    return ParsedStateSignature(
        algorithm=data["algorithm"],
        key_id=data["key_id"],
        signature=data["signature"],
    )
