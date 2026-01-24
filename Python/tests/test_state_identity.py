import unittest

from origin_protocol.experimental.state_identity import (
    compute_state_signature,
    evolve_state,
    initialize_state,
    validate_state,
)


class StateIdentityTests(unittest.TestCase):
    def test_initialize_state(self) -> None:
        state = initialize_state(seed="creator-1", secret="secret")
        self.assertTrue(state.signature)
        self.assertTrue(validate_state(state))

    def test_evolve_state_changes_signature(self) -> None:
        state = initialize_state(seed="creator-1")
        evolved = evolve_state(state, coherence_drift=-0.05, entropy_drift=0.05)
        self.assertNotEqual(state.signature, evolved.signature)

    def test_signature_deterministic_with_secret(self) -> None:
        state = initialize_state(seed="creator-1", secret="secret")
        signature = compute_state_signature(state, secret="secret")
        self.assertEqual(state.signature, signature)

    def test_validate_state_threshold(self) -> None:
        state = initialize_state(seed="creator-1", coherence=0.4)
        self.assertFalse(validate_state(state, coherence_threshold=0.6))


if __name__ == "__main__":
    unittest.main()
