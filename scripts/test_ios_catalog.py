import json
import unittest
from pathlib import Path

from ios_vision360_rules import EXACT_RULES, rule_for


class IOSCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = json.loads(Path("scripts/requirements.json").read_text(encoding="utf-8"))
        cls.requirements = cls.catalog["requirements"]

    def test_catalog_identity_and_unique_requirements(self):
        self.assertEqual("secm-cat-ios-requirements-v1", self.catalog["metadata"]["schema"])
        self.assertEqual("iOS", self.catalog["metadata"]["target_platform"])
        self.assertEqual(len(self.requirements), self.catalog["requirements_count"])
        puids = [item["PUID"] for item in self.requirements]
        self.assertEqual(len(puids), len(set(puids)))
        self.assertTrue(all(item.get("Target platform") == "iOS" for item in self.requirements))

    def test_requirement_relationships_are_valid(self):
        puids = {item["PUID"] for item in self.requirements}
        allowed = puids | {"root", "0", "Not described", ""}
        for item in self.requirements:
            for field in ("Child PUIDs", "Parent PUIDs", "Exclusion PUIDs"):
                references = (part.strip() for part in str(item.get(field, "")).split(","))
                self.assertTrue(all(reference in allowed for reference in references), item["PUID"])

    def test_automated_fingerprint_coverage_is_explicit(self):
        flags = {
            flag
            for item in self.requirements
            for flag in (item.get("Flags") or [])
        }
        automated = {flag for flag in flags if rule_for(flag) is not None}
        # The rest are intentionally manual/backend/runtime controls. This guard
        # prevents the iOS catalogue and fingerprint implementation drifting
        # silently apart again.
        self.assertGreaterEqual(len(automated), 80)
        self.assertGreaterEqual(len(automated) / len(flags), 0.30)

    def test_rule_signal_names_are_not_empty(self):
        self.assertTrue(all(rule.signal for rule in EXACT_RULES.values()))


if __name__ == "__main__":
    unittest.main()
