import unittest

from scripts.gitleaks_to_sarif import convert


class GitleaksToSarifTests(unittest.TestCase):
    def test_redacts_sensitive_and_author_metadata(self):
        historical = {
            "RuleID": "generic-api-key", "File": "Config.swift", "StartLine": 8,
            "Secret": "must-not-appear", "Author": "Private Person", "Email": "private@example.test",
        }
        sarif, summary = convert([], [historical])
        serialized = str(sarif)
        self.assertNotIn("must-not-appear", serialized)
        self.assertNotIn("Private Person", serialized)
        self.assertNotIn("private@example.test", serialized)
        self.assertEqual(1, summary["history_only"])
        self.assertEqual(0, summary["current"])

    def test_current_finding_takes_precedence_over_history(self):
        finding = {"RuleID": "github-pat", "File": "Secrets.swift", "StartLine": 3}
        sarif, summary = convert([finding], [finding])
        self.assertEqual(1, len(sarif["runs"][0]["results"]))
        self.assertEqual("current", sarif["runs"][0]["results"][0]["properties"]["exposureScope"])
        self.assertEqual(1, summary["current"])


if __name__ == "__main__":
    unittest.main()
