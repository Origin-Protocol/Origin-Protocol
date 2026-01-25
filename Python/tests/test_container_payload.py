import json
import unittest

from origin_protocol.container import _pick_latest_payload


class ContainerPayloadTests(unittest.TestCase):
    def test_pick_latest_payload_prefers_newer_timestamp(self) -> None:
        older = json.dumps({"created_at": "2026-01-01T00:00:00Z"}).encode("utf-8")
        newer = json.dumps({"created_at": "2026-01-01T00:00:00.500000+00:00"}).encode("utf-8")
        selected = _pick_latest_payload([older, newer])
        self.assertEqual(selected, newer)

    def test_pick_latest_payload_ignores_invalid(self) -> None:
        invalid = b"not-json"
        valid = json.dumps({"created_at": "2026-01-01T00:00:00+00:00"}).encode("utf-8")
        selected = _pick_latest_payload([invalid, valid])
        self.assertEqual(selected, valid)


if __name__ == "__main__":
    unittest.main()
