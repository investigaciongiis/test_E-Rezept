import json
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
