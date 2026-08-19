#!/usr/bin/env python3
"""Convert Xcode/Clang analyzer issue summaries from xcresulttool JSON to SARIF."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import unquote, urlparse


def unwrap(value: Any) -> Any:
    """Remove xcresulttool's typed `_value`/`_values` wrappers recursively."""
    if isinstance(value, list):
        return [unwrap(item) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value).issubset({"_type", "_value"}) and "_value" in value:
        return unwrap(value["_value"])
    if set(value).issubset({"_type", "_values"}) and "_values" in value:
        return unwrap(value["_values"])
    return {key: unwrap(item) for key, item in value.items() if key != "_type"}


def issue_objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        if "message" in value and any(key in value for key in ("issueType", "documentLocationInCreatingWorkspace")):
            yield value
        for child in value.values():
            yield from issue_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from issue_objects(child)


def location_from_url(raw_url: str) -> tuple[str, int | None, int | None]:
    # Xcode locations commonly end in #StartingLineNumber=12&StartingColumnNumber=4.
    parsed = urlparse(raw_url)
    path = unquote(parsed.path) if parsed.scheme == "file" else raw_url.split("#", 1)[0]
    fragment = parsed.fragment
    line_match = re.search(r"(?:^|&)StartingLineNumber=(\d+)", fragment)
    column_match = re.search(r"(?:^|&)StartingColumnNumber=(\d+)", fragment)
    return path, int(line_match.group(1)) if line_match else None, int(column_match.group(1)) if column_match else None


def convert(document: Any) -> dict[str, Any]:
    results = []
    seen = set()
    for issue in issue_objects(unwrap(document)):
        message = str(issue.get("message") or "Xcode Static Analyzer finding")
        issue_type = str(issue.get("issueType") or "clang-analyzer")
        location = issue.get("documentLocationInCreatingWorkspace") or {}
        raw_url = str(location.get("url") if isinstance(location, dict) else location or "")
        path, line, column = location_from_url(raw_url)
        key = (issue_type, message, path, line, column)
        if key in seen:
            continue
        seen.add(key)
        physical = {"artifactLocation": {"uri": path or "xcode-analyzer"}}
        region = {}
        if line is not None:
            region["startLine"] = line
        if column is not None:
            region["startColumn"] = column
        if region:
            physical["region"] = region
        results.append({
            "ruleId": f"clang-analyzer.{re.sub(r'[^a-z0-9]+', '-', issue_type.lower()).strip('-') or 'issue'}",
            "level": "warning",
            "message": {"text": message},
            "locations": [{"physicalLocation": physical}],
            "properties": {"issueType": issue_type},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Xcode Static Analyzer", "informationUri": "https://developer.apple.com/xcode/"}},
            "results": results,
        }],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    document = json.loads(args.input.read_text(encoding="utf-8"))
    sarif = convert(document)
    args.output.write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Converted {len(sarif['runs'][0]['results'])} Xcode Analyzer findings to SARIF")


if __name__ == "__main__":
    main()
