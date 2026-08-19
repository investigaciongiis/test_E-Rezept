import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.ci_prepare_vision360_inputs import add_gitleaks_to_merged_sarif


class PrepareVision360InputsTests(unittest.TestCase):
    def test_merges_gitleaks_run_into_sarif_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "sast-findings.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("merged.sarif", json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}}}]}))
            gitleaks = root / "gitleaks.sarif"
            gitleaks.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Gitleaks"}}}]}), encoding="utf-8")

            add_gitleaks_to_merged_sarif(str(archive), str(gitleaks))

            with zipfile.ZipFile(archive) as result:
                merged = json.loads(result.read("merged.sarif"))
            self.assertEqual(["CodeQL", "Gitleaks"], [run["tool"]["driver"]["name"] for run in merged["runs"]])


if __name__ == "__main__":
    unittest.main()
