#!/usr/bin/env python3
"""Build the VISION360 evidence bundle for an iOS/Swift application."""
from __future__ import annotations

import json
import plistlib
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

DATA = Path("/mnt/data")


def zip_json(archive: str, member: str):
    path = DATA / archive
    if not path.exists():
        return {}
    with zipfile.ZipFile(path) as zf:
        try:
            return json.loads(zf.read(member))
        except (KeyError, json.JSONDecodeError):
            return {}


def source_files():
    result = {}
    with zipfile.ZipFile(DATA / "app.zip") as zf:
        for name in zf.namelist():
            if name.lower().endswith((".swift", ".m", ".mm", ".h", ".plist", ".entitlements", ".pbxproj", ".xcconfig")):
                try:
                    result[name] = zf.read(name).decode("utf-8", "replace")
                except Exception:
                    pass
    return result


def sarif_results(doc):
    return [r for run in doc.get("runs", []) for r in run.get("results", [])]


def evidence(source, location, rule, excerpt):
    return {"source": source, "location": location, "rule_id": rule, "excerpt": excerpt[:500]}


src = source_files()
joined = "\n".join(src.values())
lower = joined.lower()
mobsf = zip_json("mobsf-report.zip", "mobsf_results.json")
sast = zip_json("sast-findings.zip", "merged.sarif")
trivy = zip_json("trivy-payload.zip", "trivy.json")
agent_payload = zip_json("trivy-payload.zip", "agent_payload.json")
gitleaks_summary = zip_json("trivy-payload.zip", "gitleaks_summary.json")

plist_docs = []
for path, text in src.items():
    if path.lower().endswith(("info.plist", ".entitlements")):
        try:
            plist_docs.append((path, plistlib.loads(text.encode())))
        except Exception:
            pass


def plist_value(key):
    def find(value):
        if isinstance(value, dict):
            if key in value:
                return value[key]
            for child in value.values():
                found = find(child)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = find(child)
                if found is not None:
                    return found
        return None
    for _path, document in plist_docs:
        found = find(document)
        if found is not None:
            return found
    return None

signals = {
    "ats_arbitrary_loads": bool(plist_value("NSAllowsArbitraryLoads")) or bool(re.search(r"NSAllowsArbitraryLoads.{0,100}<true", joined, re.I | re.S)),
    "insecure_http": "http://" in lower,
    "webview": "wkwebview" in lower,
    "keychain": any(x in lower for x in ("secitemadd", "secitemcopymatching", "ksecattraccessible")),
    "biometric": any(x in lower for x in ("lacontext", "deviceownerauthenticationwithbiometrics")),
    "jailbreak_detection": any(x in lower for x in ("cydia", "canopenurl", "/applications/cydia.app")),
    "hardcoded_secret": bool(re.search(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][^\"']{8,}" , joined)),
    "weak_crypto": bool(re.search(r"(?i)\b(md5|sha1|des|rc4)\b", joined)),
    "certificate_pinning": any(x in lower for x in ("servertrust", "secpolicyevaluateservertrust", "pinnedcertificates", "publickeys")),
    "insecure_random": bool(re.search(r"(?i)\b(rand|random|srandom|drand48|arc4random)\s*\(", joined)),
    "debuggable": bool(plist_value("get-task-allow")),
    "dynamic_code_loading": bool(re.search(r"(?i)\b(dlopen|dlsym|nsbundle\s*\([^)]*path|javascriptcore)\b", joined)),
    "file_sharing": bool(plist_value("UIFileSharingEnabled")),
    # Backup exposure requires file-level evidence and remains unknown unless a
    # dedicated scanner or runtime test provides it.
    "backup_enabled": False,
    "sensitive_permissions": any(plist_value(key) is not None for key in (
        "NSCameraUsageDescription", "NSMicrophoneUsageDescription", "NSLocationWhenInUseUsageDescription",
        "NSLocationAlwaysAndWhenInUseUsageDescription", "NSContactsUsageDescription", "NSHealthShareUsageDescription",
    )),
    "gitleaks_current": int(gitleaks_summary.get("current") or 0) > 0,
    "gitleaks_any": int(gitleaks_summary.get("total") or 0) > 0,
}

sast_items = sarif_results(sast)
sast_evidence = []
gitleaks_evidence = []
gitleaks_current_evidence = []
for item in sast_items:
    loc = (((item.get("locations") or [{}])[0].get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri", "SARIF")
    message = (item.get("message") or {}).get("text", "Static-analysis finding")
    converted = evidence("SAST", loc, item.get("ruleId", "unknown"), message)
    if str(item.get("ruleId") or "").startswith("gitleaks."):
        gitleaks_evidence.append(converted)
        if (item.get("properties") or {}).get("exposureScope") == "current":
            gitleaks_current_evidence.append(converted)
    elif len(sast_evidence) < 500:
        sast_evidence.append(converted)

reqs = json.loads(Path("scripts/requirements.json").read_text(encoding="utf-8"))
if isinstance(reqs, dict):
    reqs = reqs.get("requirements", [])
flag_ids = set()
for req in reqs:
    value = req.get("Flags") or []
    if isinstance(value, str):
        value = [x.strip() for x in re.split(r"[,;\n]", value) if x.strip()]
    flag_ids.update(str(fid) for fid in value)
flag_ids = sorted(flag_ids)

def verdict(flag_id):
    fid = flag_id.lower()
    mapping = {
        "api_keys_in_version_control": "gitleaks_any",
        "secrets_generic_found": "gitleaks_any",
        "secrets_count": "gitleaks_any",
        "hardcoded_credentials": "gitleaks_current",
        "ios_certificate_pinning": "certificate_pinning",
        "ios_insecure_random": "insecure_random",
        "ios_get_task_allow": "debuggable",
        "ios_dynamic_code_loading": "dynamic_code_loading",
        "ios_file_sharing_enabled": "file_sharing",
        "ios_sensitive_permissions_present": "sensitive_permissions",
        "ios_ats_arbitrary_loads": "ats_arbitrary_loads",
        "ios_sensitive_backup_exposure": "backup_enabled",
        "clear_text": "ats_arbitrary_loads", "cleartext": "ats_arbitrary_loads",
        "insecure_http": "insecure_http", "webview": "webview", "keychain": "keychain",
        "biometric": "biometric", "jailbreak": "jailbreak_detection",
        "hardcoded": "hardcoded_secret", "weak_crypto": "weak_crypto", "ssl_pinning": "certificate_pinning",
    }
    key = next((value for token, value in mapping.items() if token in fid), None)
    if key:
        found = bool(signals[key])
        selected_gitleaks_evidence = gitleaks_current_evidence if key == "gitleaks_current" else gitleaks_evidence
        ev = (selected_gitleaks_evidence[:3] if key in {"gitleaks_current", "gitleaks_any"} and selected_gitleaks_evidence
              else [evidence("SOURCE_CODE_APP", "app.zip", key, f"iOS source heuristic {key}={found}")])
        negative = {"ats_arbitrary_loads", "insecure_http", "hardcoded_secret", "weak_crypto", "insecure_random", "debuggable", "dynamic_code_loading", "file_sharing", "sensitive_permissions", "gitleaks_current", "gitleaks_any"}
        note = f"iOS heuristic: {key}={found}."
        return ("fail" if found and key in negative else
                "pass" if found else "unknown"), ("YES" if found else "UNKNOWN"), note, ev
    if sast_evidence:
        return "unknown", "UNKNOWN", "SAST evidence exists but cannot be mapped deterministically to this control.", sast_evidence[:3]
    return "unknown", "UNKNOWN", "No conclusive iOS evidence was found for this control.", []

flags = []
output_flags = {}
for fid in flag_ids:
    state, summary, notes, ev = verdict(fid)
    obj = {"id": fid, "title": fid.replace("_", " "), "description": "iOS security signal",
           "severity": "info", "expected_state": "good",
           "app_verdict": {"state": state, "summary": summary, "notes": notes, "evidence": ev, "evidence_count": len(ev)}}
    flags.append(obj)
    output_flags[fid] = obj["app_verdict"]

project = {"name": "iOS app", "platform": "ios", "generated_at": datetime.now(timezone.utc).isoformat(),
           "tools": ["CodeQL Swift", "Xcode/Clang Static Analyzer", "Semgrep Swift/Objective-C", "Gitleaks", "MobSF IPA", "Trivy"]}
fingerprint = {"schema_version": 1, "project": project, "flags": flags}
output = {"schema_version": 1, "project": project, "flags": output_flags,
          "raw": {"ios_signals": signals, "info_plists": [p for p, _ in plist_docs], "mobsf_static_full": mobsf,
                  "sast_merged_full": sast, "trivy_full": trivy,
                  "agent_payload_full": agent_payload, "gitleaks_summary": gitleaks_summary}}
(DATA / "vision360_fingerprint.json").write_text(json.dumps(fingerprint, ensure_ascii=False, indent=2), encoding="utf-8")
(DATA / "vision360_output.json").write_text(json.dumps(output, ensure_ascii=False), encoding="utf-8")
print(f"Generated iOS fingerprint with {len(flags)} flags and {len(sast_items)} SAST results")
