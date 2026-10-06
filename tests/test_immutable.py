"""Shared records cannot be changed through readers or retained input aliases."""

import json
import sys
import unittest
from pathlib import Path
from types import MappingProxyType

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from holdup import decision, evidence, routes, transport
from holdup.data import freeze, json_value
from holdup.engine import validate_configuration


class ImmutableContracts(unittest.TestCase):
    def test_freeze_detaches_nested_inputs_and_uses_standard_types(self):
        source = {"reports": [{"regions": ["us-east-1"]}], "flags": {"observed"}}
        record = freeze(source)
        source["reports"][0]["regions"].append("us-west-2")
        self.assertIsInstance(record, MappingProxyType)
        self.assertIsInstance(record["reports"], tuple)
        self.assertIsInstance(record["flags"], frozenset)
        self.assertEqual(record["reports"][0]["regions"], ("us-east-1",))
        with self.assertRaises(TypeError):
            record["reports"][0]["regions"] = ()
        with self.assertRaises(TypeError):
            freeze(bytearray(b"mutable"))

    def test_configuration_evidence_and_decisions_are_immutable(self):
        config, feeds = validate_configuration({"feeds": []})
        self.assertIsInstance(config, MappingProxyType)
        self.assertIsInstance(feeds, tuple)
        reports = evidence.parse(
            b'[{"summary":"current impact","description":"complete text"}]',
            {"name": "AWS", "format": "aws-json", "url": "https://example.invalid"},
            1,
        )
        with self.assertRaises(TypeError):
            reports[0]["summary"] = "recovered"
        route = routes.normalize({"tool_name": "Read", "tool_input": {}})
        result = routes.classify(route, reports, {})
        with self.assertRaises(TypeError):
            result["decision"] = "pause"
        self.assertEqual(json.loads(json.dumps(result, default=json_value))["decision"], "allow")
        self.assertEqual(decision.digest(result), decision.digest(dict(result)))

    def test_authentication_does_not_mutate_shared_messages(self):
        value = freeze({"nonce": "fixture", "nested": {"values": (1, 2)}})
        signed = freeze({**value, "signature": transport.signature(value, "fixture")})
        self.assertTrue(transport.authenticate(signed, "fixture"))
        self.assertIn("signature", signed)
        self.assertEqual(signed["nested"]["values"], (1, 2))


if __name__ == "__main__":
    unittest.main()
