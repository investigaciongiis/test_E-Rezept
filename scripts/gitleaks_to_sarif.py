#!/usr/bin/env python3
"""Create redacted, report-safe SARIF and summary files from Gitleaks JSON."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_findings(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or not path.read_text(encoding="utf-8").strip():
        return []
    value = json.loads(path.read_text(encoding="utf-8"))
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def finding_identity(finding: dict[str, Any]) -> tuple[str, str, int]:
    return (
        str(finding.get("RuleID") or "generic-secret"),
        str(finding.get("File") or "unknown"),
        max(1, int(finding.get("StartLine") or 1)),
    )


def convert(current: list[dict[str, Any]], history: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    current_ids = {finding_identity(item) for item in current}
    combined: dict[tuple[str, str, int], dict[str, Any]] = {}
    for item in history + current:
        combined.setdefault(finding_identity(item), item)

    results = []
    current_count = 0
    history_only_count = 0
    by_rule: dict[str, int] = {}
    for identity, finding in sorted(combined.items()):
        rule_id, filename, start_line = identity
        scope = "current" if identity in current_ids else "history_only"
        if scope == "current":
            current_count += 1
        else:
            history_only_count += 1
        by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
        region = {"startLine": start_line}
        if int(finding.get("StartColumn") or 0) > 0:
            region["startColumn"] = int(finding["StartColumn"])
        results.append({
            "ruleId": f"gitleaks.{rule_id}",
            "level": "error",
            "message": {"text": f"Potential {rule_id} exposure detected in {scope.replace('_', ' ')}; secret value redacted."},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": filename},
                "region": region,
            }}],
            "properties": {"exposureScope": scope, "secretValueIncluded": False},
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Gitleaks", "informationUri": "https://gitleaks.io"}},
            "results": results,
        }],
    }
    summary = {
        "tool": "Gitleaks",
        "total": len(results),
        "current": current_count,
        "history_only": history_only_count,
        "by_rule": by_rule,
        "values_redacted": True,
        "author_data_included": False,
    }
    return sarif, summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--history", type=Path, required=True)
    parser.add_argument("--sarif", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    sarif, summary = convert(load_findings(args.current), load_findings(args.history))
    args.sarif.write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    args.summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Gitleaks findings: {summary['total']} ({summary['current']} current, {summary['history_only']} history only)")


if __name__ == "__main__":
    main()
