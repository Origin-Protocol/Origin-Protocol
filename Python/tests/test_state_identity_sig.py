import unittest

from origin_protocol.experimental.state_identity import initialize_state
from origin_protocol.experimental.state_identity_sig import (
    SIGNATURE_ALGORITHM,
    parse_state_signature,
    sign_state,
    verify_state_signature,
)
from origin_protocol.keys import generate_keypair


class StateIdentitySignatureTests(unittest.TestCase):
    def test_sign_and_verify(self) -> None:
        keypair = generate_keypair()
        state = initialize_state(seed="creator-1")
        signed = sign_state(state, keypair.private_key)

        self.assertTrue(verify_state_signature(signed, keypair.public_key))

    def test_signature_metadata(self) -> None:
        keypair = generate_keypair()
        state = initialize_state(seed="creator-1")
        signed = sign_state(state, keypair.private_key)

        parsed = parse_state_signature(signed.signature)
        self.assertEqual(parsed.algorithm, SIGNATURE_ALGORITHM)
        self.assertTrue(parsed.key_id)
        self.assertTrue(parsed.signature)

    def test_key_id_mismatch_fails(self) -> None:
        keypair = generate_keypair()
        state = initialize_state(seed="creator-1")
        signed = sign_state(state, keypair.private_key, key_id="not-a-match")

        self.assertFalse(verify_state_signature(signed, keypair.public_key))


if __name__ == "__main__":
    unittest.main()
