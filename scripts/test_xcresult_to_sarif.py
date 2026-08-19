import unittest

from xcresult_to_sarif import convert


class XcresultToSarifTests(unittest.TestCase):
    def test_converts_wrapped_issue_and_location(self):
        document = {
            "issues": {
                "_values": [{
                    "issueType": {"_value": "Memory leak"},
                    "message": {"_value": "Potential leak of an object"},
                    "documentLocationInCreatingWorkspace": {
                        "url": {"_value": "file:///tmp/App/ViewController.m#StartingLineNumber=42&StartingColumnNumber=7"}
                    },
                }]
            }
        }
        result = convert(document)["runs"][0]["results"]
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ruleId"], "clang-analyzer.memory-leak")
        physical = result[0]["locations"][0]["physicalLocation"]
        self.assertEqual(physical["artifactLocation"]["uri"], "/tmp/App/ViewController.m")
        self.assertEqual(physical["region"], {"startLine": 42, "startColumn": 7})

    def test_deduplicates_identical_issues(self):
        issue = {"issueType": "Warning", "message": "Same finding"}
        result = convert({"a": issue, "b": issue})["runs"][0]["results"]
        self.assertEqual(len(result), 1)


if __name__ == "__main__":
    unittest.main()
