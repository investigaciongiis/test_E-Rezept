import json
import unittest
from pathlib import Path

from ios_vision360_rules import EXACT_RULES, rule_for


class IOSCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = json.loads(Path("scripts/requirements.json").read_text(encoding="utf-8"))
        cls.catalog_metadata = json.loads(Path("scripts/ios_catalog_metadata.json").read_text(encoding="utf-8"))
        cls.source_registry = json.loads(Path("scripts/ios_catalog_sources.json").read_text(encoding="utf-8"))
        cls.requirements = cls.catalog["requirements"]

    def test_catalog_identity_and_unique_requirements(self):
        self.assertEqual("secm-cat-requirements-with-flags-v1", self.catalog["metadata"]["schema"])
        self.assertEqual("iOS", self.catalog_metadata["target_platform"])
        self.assertEqual(len(self.requirements), self.catalog["requirements_count"])
        puids = [item["PUID"] for item in self.requirements]
        self.assertEqual(len(puids), len(set(puids)))
        baseline_fields = {
            "PUID", "Requirement description", "Source", "Priority", "Rationale",
            "Number of Children", "Number of Parents", "Cycles", "Number of audits",
            "Child PUIDs", "Parent PUIDs", "Exclusion PUIDs", "Importance",
            "Current state", "Verification method", "Validation criteria", "controles", "Flags",
        }
        self.assertTrue(all(set(item) == baseline_fields for item in self.requirements))
        self.assertTrue(all(item.get("Flags") for item in self.requirements))

    def test_aosp_is_not_a_normative_source(self):
        self.assertTrue(self.catalog_metadata["aosp_normative_source_excluded"])
        self.assertTrue(all("[18]" not in item.get("Source", "") for item in self.requirements))
        self.assertTrue(all("Android Open Source Project" not in item.get("Source", "") for item in self.requirements))

    def test_ios_and_new_research_sources_are_registered_and_used(self):
        registry = self.source_registry["sources"]
        for source_id in ("153", "154", "155", "157", "158", "159", "160", "165", "167"):
            self.assertIn(source_id, registry)
            self.assertTrue(any(f"[{source_id}]" in item.get("Source", "") for item in self.requirements))

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
