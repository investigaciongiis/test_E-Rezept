#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CI helper - prepare VISION360 inputs in /mnt/data (deterministic, local-only)

Goal:
- Downloaded GitHub Actions artifacts can come in varied names/structures.
- This helper normalizes the four required ZIP inputs used by the iOS VISION360 generator:

  /mnt/data/mobsf-report.zip           -> mobsf_results.json
  /mnt/data/app.zip                -> source code zip
  /mnt/data/sast-findings.zip          -> merged.sarif (CodeQL, Semgrep, Xcode Analyzer and Gitleaks)
  /mnt/data/trivy-payload.zip          -> trivy.json, agent_payload.json, gitleaks_summary.json

It supports either:
- already-zipped artifacts containing the expected member names, OR
- raw JSON/SARIF files that it will wrap into the expected ZIPs.

Exit codes:
- 0 success
- 2 missing required inputs
"""

import argparse
import json
import os
import shutil
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple


REQUIRED = {
    "mobsf-report.zip": {
        "members_any": ["mobsf_results.json"],
        "members_all": ["mobsf_results.json"],
        "raw_fallback": ["mobsf_results.json"],
    },
    "app.zip": {
        "members_any": [],  # source zip can be arbitrary; filename is the key
        "members_all": [],
        "raw_fallback": [],
    },
    "sast-findings.zip": {
        "members_any": ["merged.sarif"],
        "members_all": ["merged.sarif"],
        "raw_fallback": ["merged.sarif"],
    },
    "trivy-payload.zip": {
        "members_any": ["trivy.json", "agent_payload.json", "gitleaks_summary.json"],
        "members_all": ["trivy.json", "agent_payload.json", "gitleaks_summary.json"],
        "raw_fallback": ["trivy.json", "agent_payload.json", "gitleaks_summary.json"],
    },
}


def walk_files(root: str) -> List[str]:
    out = []
    for base, _, files in os.walk(root):
        for fn in files:
            out.append(os.path.join(base, fn))
    return out


def is_zip(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    if not path.lower().endswith(".zip"):
        return False
    try:
        with zipfile.ZipFile(path, "r") as zf:
            zf.testzip()  # validates CRCs
        return True
    except Exception:
        return False


def zip_has_members(zip_path: str, members_all: List[str]) -> bool:
    if not is_zip(zip_path):
        return False
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = set(zf.namelist())
        return all(m in names for m in members_all)
    except Exception:
        return False


def find_best_zip_candidate(files: List[str], expected_name: str, members_all: List[str]) -> Optional[str]:
    # 1) Exact filename match (case-insensitive), anywhere
    exp_low = expected_name.lower()
    exact = [p for p in files if os.path.basename(p).lower() == exp_low and is_zip(p)]
    for p in exact:
        if not members_all or zip_has_members(p, members_all):
            return p

    # 2) Any ZIP containing required members
    if members_all:
        zips = [p for p in files if is_zip(p)]
        for p in zips:
            if zip_has_members(p, members_all):
                return p

    return None


def find_raw_members(files: List[str], raw_names: List[str]) -> Dict[str, str]:
    # Returns mapping member_name -> path on disk
    found: Dict[str, str] = {}
    want = {n.lower(): n for n in raw_names}
    for p in files:
        bn = os.path.basename(p).lower()
        if bn in want and bn not in found:
            found[want[bn]] = p
    return found


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def copy_to(src: str, dst: str) -> None:
    ensure_dir(os.path.dirname(dst))
    shutil.copy2(src, dst)


def build_zip_from_raw(raw_map: Dict[str, str], dst_zip: str) -> None:
    ensure_dir(os.path.dirname(dst_zip))
    with zipfile.ZipFile(dst_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for member_name, src_path in raw_map.items():
            zf.write(src_path, arcname=member_name)


def add_gitleaks_to_merged_sarif(sast_zip: str, gitleaks_sarif: str) -> None:
    with zipfile.ZipFile(sast_zip, "r") as source:
        members = {name: source.read(name) for name in source.namelist() if name != "merged.sarif"}
        merged = json.loads(source.read("merged.sarif"))
    gitleaks = json.loads(Path(gitleaks_sarif).read_text(encoding="utf-8"))
    merged.setdefault("runs", []).extend(gitleaks.get("runs", []))
    with zipfile.ZipFile(sast_zip, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for name, content in members.items():
            target.writestr(name, content)
        target.writestr("merged.sarif", json.dumps(merged, ensure_ascii=False))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts-dir", required=True, help="Directory where actions/download-artifact stored files.")
    ap.add_argument("--out-dir", default="/mnt/data", help="Output directory (default: /mnt/data).")
    args = ap.parse_args()

    artifacts_dir = os.path.abspath(args.artifacts_dir)
    out_dir = os.path.abspath(args.out_dir)

    if not os.path.isdir(artifacts_dir):
        print(f"[ERR] artifacts-dir not found: {artifacts_dir}", file=sys.stderr)
        return 2

    ensure_dir(out_dir)
    files = walk_files(artifacts_dir)

    plan: List[Tuple[str, str]] = []  # (expected_zip_name, method_desc)
    missing: List[str] = []

    for expected_zip, spec in REQUIRED.items():
        dst = os.path.join(out_dir, expected_zip)

        # Special: app.zip should be found by filename first; if not found, try any zip named similarly.
        if expected_zip == "app.zip":
            cand = None
            # exact basename match first:
            for p in files:
                if os.path.basename(p).lower() in {"app.zip", "app-zip.zip", "app_source.zip"} and is_zip(p):
                    cand = p
                    break
            # otherwise any file named app.zip anywhere
            if cand is None:
                cand = find_best_zip_candidate(files, "app.zip", [])
            if cand is None:
                missing.append(expected_zip)
                continue
            copy_to(cand, dst)
            plan.append((expected_zip, f"copied zip from {os.path.relpath(cand, artifacts_dir)}"))
            continue

        # 1) prefer: a ZIP that already matches expected name or contains required members
        cand_zip = find_best_zip_candidate(files, expected_zip, spec.get("members_all", []))
        if cand_zip:
            copy_to(cand_zip, dst)
            plan.append((expected_zip, f"copied zip from {os.path.relpath(cand_zip, artifacts_dir)}"))
            continue

        # 2) fallback: raw files exist; wrap into expected zip
        raw_needed = spec.get("raw_fallback", [])
        raw_map = find_raw_members(files, raw_needed)
        if raw_needed and all(k in raw_map for k in raw_needed):
            build_zip_from_raw(raw_map, dst)
            srcs = ", ".join(os.path.relpath(raw_map[k], artifacts_dir) for k in raw_needed)
            plan.append((expected_zip, f"built zip from raw files: {srcs}"))
            continue

        missing.append(expected_zip)

    if missing:
        print("[ERR] Missing required VISION360 inputs after artifact download:", file=sys.stderr)
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        print("\n[HINT] Ensure upstream jobs upload artifacts containing these members:", file=sys.stderr)
        print("  - mobsf_results.json (MobSF IPA static report)", file=sys.stderr)
        print("  - merged.sarif (CodeQL, Semgrep and Xcode Analyzer) as zip or raw file", file=sys.stderr)
        print("  - trivy.json, agent_payload.json, gitleaks.sarif and gitleaks_summary.json", file=sys.stderr)
        print("  - app.zip from package_source_zip job", file=sys.stderr)
        return 2

    gitleaks_map = find_raw_members(files, ["gitleaks.sarif"])
    if "gitleaks.sarif" not in gitleaks_map:
        print("[ERR] Missing redacted gitleaks.sarif", file=sys.stderr)
        return 2
    add_gitleaks_to_merged_sarif(
        os.path.join(out_dir, "sast-findings.zip"),
        gitleaks_map["gitleaks.sarif"],
    )
    plan.append(("sast-findings.zip", "merged redacted Gitleaks findings into SARIF"))

    print("[OK] Prepared VISION360 inputs in:", out_dir)
    for name, how in plan:
        print(f"  - {name}: {how}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
