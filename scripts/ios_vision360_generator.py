#!/usr/bin/env python3
"""Build the VISION360 evidence bundle for an iOS/Swift application."""
from __future__ import annotations

import json
import os
import plistlib
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from ios_vision360_rules import evaluate_flag, rule_for

DATA = Path(os.getenv("VISION360_DATA_DIR", "/mnt/data"))


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
            if name.lower().endswith((
                ".swift", ".m", ".mm", ".h", ".plist", ".entitlements",
                ".pbxproj", ".xcconfig", ".xcprivacy", ".yml", ".yaml",
            )) or name.lower().endswith("package.swift"):
                try:
                    result[name] = zf.read(name).decode("utf-8", "replace")
                except Exception:
                    pass
    return result


def sarif_results(doc):
    return [r for run in doc.get("runs", []) for r in run.get("results", [])]


def evidence(source, location, rule, excerpt):
    return {"source": source, "location": location, "rule_id": rule, "excerpt": excerpt[:500]}


def matching_source_evidence(pattern, rule, limit=3):
    found = []
    regex = re.compile(pattern, re.I | re.S)
    for path, text in src.items():
        match = regex.search(text)
        if match:
            start = max(0, match.start() - 100)
            end = min(len(text), match.end() + 180)
            found.append(evidence("SOURCE_CODE_APP", path, rule, text[start:end].replace("\n", " ")))
            if len(found) >= limit:
                break
    return found


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

def source_has(pattern):
    return bool(re.search(pattern, joined, re.I | re.S))


privacy_files = [path for path in src if path.lower().endswith("privacyinfo.xcprivacy")]
entitlement_files = [path for path in src if path.lower().endswith(".entitlements")]
swift_files = [path for path in src if path.lower().endswith(".swift")]

signals = {
    "ats_arbitrary_loads": bool(plist_value("NSAllowsArbitraryLoads")) or bool(re.search(r"NSAllowsArbitraryLoads.{0,100}<true", joined, re.I | re.S)),
    "insecure_http": "http://" in lower,
    "webview": "wkwebview" in lower,
    "keychain": any(x in lower for x in ("secitemadd", "secitemcopymatching", "ksecattraccessible")),
    "biometric": any(x in lower for x in ("lacontext", "deviceownerauthenticationwithbiometrics")),
    "jailbreak_detection": any(x in lower for x in ("cydia", "canopenurl", "/applications/cydia.app")),
    "hardcoded_secret": bool(re.search(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][^\"']{8,}" , joined)),
    "published_security_contact": source_has(r"security(?: contact)?\s*[:=].{0,120}[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"),
    "safe_object_serialization": source_has(r"\b(Codable|Encodable|PropertyListEncoder|JSONEncoder)\b"),
    "safe_object_deserialization": source_has(r"\b(Decodable|JSONDecoder|PropertyListDecoder)\b.{0,1200}(do\s*\{|catch\s*\{|guard|validate)"),
    "weak_crypto": bool(re.search(r"(?i)\b(md5|sha1|des|rc4)\b", joined)),
    "certificate_pinning": any(x in lower for x in ("servertrust", "secpolicyevaluateservertrust", "pinnedcertificates", "publickeys")),
    "insecure_random": bool(re.search(r"(?i)\b(rand|random|srandom|drand48|arc4random)\s*\(", joined)),
    "get_task_allow": bool(plist_value("get-task-allow")),
    "dynamic_code_loading": bool(re.search(r"(?i)\b(dlopen|dlsym|nsbundle\s*\([^)]*path|javascriptcore)\b", joined)),
    "file_sharing": bool(plist_value("UIFileSharingEnabled")),
    "no_public_file_storage": not bool(plist_value("UIFileSharingEnabled")),
    # Backup exposure requires file-level evidence and remains unknown unless a
    # dedicated scanner or runtime test provides it.
    "backup_enabled": False,
    "sensitive_permissions": any(plist_value(key) is not None for key in (
        "NSCameraUsageDescription", "NSMicrophoneUsageDescription", "NSLocationWhenInUseUsageDescription",
        "NSLocationAlwaysAndWhenInUseUsageDescription", "NSContactsUsageDescription", "NSHealthShareUsageDescription",
    )),
    "gitleaks_current": int(gitleaks_summary.get("current") or 0) > 0,
    "gitleaks_any": int(gitleaks_summary.get("total") or 0) > 0,
    "privacy_manifest": bool(privacy_files),
    "required_reason_apis": source_has(r"NSPrivacyAccessedAPITypes|NSPrivacyAccessedAPITypeReasons"),
    "third_party_privacy_manifest": None,
    "keychain_accessibility": source_has(r"kSecAttrAccessible"),
    "keychain_device_only": source_has(r"kSecAttrAccessible\w*ThisDeviceOnly"),
    "secure_enclave": source_has(r"kSecAttrTokenIDSecureEnclave|SecureEnclave"),
    "biometric_keychain_binding": source_has(r"SecAccessControlCreateWithFlags.{0,500}(biometry|userPresence)"),
    "biometric_enrollment_validation": source_has(r"canEvaluatePolicy|biometryType|evaluatedPolicyDomainState"),
    "app_attest": source_has(r"DCAppAttestService|generateKey|attestKey"),
    "device_check": source_has(r"DCDevice|DeviceCheck"),
    "environment_configuration": source_has(r"\.xcconfig|#if\s+(DEBUG|STAGING)|ProcessInfo\.processInfo\.environment"),
    # These obligations depend on backend/runtime configuration and cannot be
    # proven merely by finding an xcconfig file or an IPC API name in source.
    "separate_environment_credentials": None,
    "authenticated_scoped_ios_ipc": None,
    "unique_api_key_per_app_instance": None,
    "api_key_usage_restrictions": None,
    "secure_secret_injection": source_has(r"ProcessInfo\.processInfo\.environment|keychain|SecItem"),
    "entitlements_present": bool(entitlement_files),
    # Effective/minimal entitlements must be read from the signed product.
    "minimal_entitlements": None,
    "app_groups": source_has(r"com\.apple\.security\.application-groups|containerURL\s*\(\s*forSecurityApplicationGroupIdentifier"),
    "secure_ios_ipc": source_has(r"application-groups|keychain-access-groups|NSXPCConnection|NSExtension"),
    "ios_ipc_authorization_checks": None,
    "universal_links_validation": source_has(r"associated-domains|NSUserActivityTypeBrowsingWeb|continue\s+userActivity"),
    "url_scheme_validation": source_has(r"CFBundleURLSchemes|openURLContexts|application\s*\([^)]*open\s+url"),
    "secure_pasteboard": source_has(r"UIPasteboard.{0,500}(localOnly|expirationDate)|detectPatterns"),
    "background_redaction": source_has(r"sceneWillResignActive|applicationDidEnterBackground|sceneDidEnterBackground.{0,800}(hidden|blur|overlay|redact)"),
    "screen_capture_protection": source_has(r"UIScreen\.capturedDidChangeNotification|isCaptured"),
    "notification_redaction": source_has(r"UNNotification(Content|ServiceExtension)|hiddenPreviewsBodyPlaceholder|showPreviews"),
    "notification_sensitive_data": source_has(r"UNMutableNotificationContent.{0,500}(token|password|patient|health|secret)"),
    "webview_javascript": source_has(r"javaScriptEnabled|allowsContentJavaScript"),
    "webview_file_access": source_has(r"allowingReadAccessTo|file://"),
    "webview_remote_content": source_has(r"WKWebView.{0,1000}https?://|load\s*\(\s*URLRequest"),
    "secure_webview_configuration": (
        source_has(r"WKWebViewConfiguration")
        and source_has(r"WKContentWorld|WKWebsiteDataStore\.nonPersistent|limitsNavigationsToAppBoundDomains|javaScriptEnabled\s*=\s*false|allowsContentJavaScript\s*=\s*false")
    ),
    "webview_navigation_validation": (
        source_has(r"WKNavigationDelegate|decidePolicyFor")
        and source_has(r"decidePolicyFor.{0,1800}(allowlist|allowed|host|scheme|cancel)")
    ),
    "safe_webview_message_handlers": (
        source_has(r"WKScriptMessageHandler|WKScriptMessageHandlerWithReply")
        and source_has(r"(didReceive|replyHandler).{0,1800}(guard|JSONDecoder|allowed|validate|is\s+String|as\?)")
    ),
    "logout": source_has(r"logout|logOut|signOut"),
    "logout_cleanup": source_has(r"(logout|signOut).{0,1500}(SecItemDelete|removeObject|delete|clear|nil)"),
    "sensitive_memory_cleanup": source_has(
        r"explicit_bzero|memset_s|resetBytes\s*\(|withUnsafeMutableBytes.{0,800}(initialize|assign|update)\s*\(\s*repeating:\s*0"
    ),
    "cookie_cleanup": source_has(r"(logout|signOut).{0,1500}(HTTPCookieStorage|WKWebsiteDataStore).{0,500}(remove|delete)"),
    "server_logout": None,
    "token_auth": source_has(r"Authorization.{0,100}Bearer|accessToken|refreshToken"),
    "jwt": source_has(r"\bJWT\b|JSONWebToken|eyJ[A-Za-z0-9_-]+\."),
    "oauth": source_has(r"OAuth|ASWebAuthenticationSession|OIDAuthState"),
    "plaintext_token_storage": source_has(r"UserDefaults.{0,500}(token|credential|password)"),
    "plaintext_key_storage": source_has(r"UserDefaults.{0,500}(key|secret)|write.{0,300}(key|secret).{0,100}toFile"),
    "plaintext_pii_storage": source_has(r"UserDefaults.{0,500}(patient|email|address|health|medical)"),
    "encrypted_database": source_has(r"SQLCipher|Realm\.Configuration.{0,300}encryptionKey|NSPersistentStoreFileProtectionKey"),
    "data_protection": source_has(r"FileProtectionType|NSFileProtection|completeFileProtection"),
    "backup_exclusion": source_has(r"isExcludedFromBackup|NSURLIsExcludedFromBackupKey"),
    "strict_concurrency": source_has(r"SWIFT_STRICT_CONCURRENCY|StrictConcurrency|swift-tools-version:\s*6|swiftLanguageModes?.{0,100}v6"),
    "resilient_background_tasks": source_has(r"BGTaskScheduler|BGProcessingTaskRequest|BGAppRefreshTaskRequest|URLSessionConfiguration\.background"),
    "race_protection": None,
    "swift_sources": bool(swift_files),
    "ats_secure_configuration": not (bool(plist_value("NSAllowsArbitraryLoads")) or source_has(r"NSAllowsArbitraryLoads.{0,100}<true")),
    "no_tls_validation_bypass": not source_has(r"URLSession.{0,1200}didReceive.{0,1200}(useCredential|performDefaultHandling).{0,500}serverTrust|SecTrustEvaluate.{0,500}(proceed|unspecified)"),
    "ios_sandbox_isolation": None,
    "get_task_allow_disabled": not bool(plist_value("get-task-allow")),
    "no_dynamic_code_loading": not source_has(r"\b(dlopen|dlsym|NSBundle\s*\([^)]*path|JavaScriptCore)\b"),
    "no_gitleaks_current": int(gitleaks_summary.get("current") or 0) == 0,
    "backup_exposure": None,
    "valid_signature": None,
    "production_signing": None,
    "aslr": None,
    "nx": None,
    "stack_canary": None,
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

sarif_text = "\n".join(
    f"{item.get('ruleId', '')} {(item.get('message') or {}).get('text', '')}".lower()
    for item in sast_items
)
signals.update({
    "race_findings": bool(re.search(r"race|concurren|thread safety", sarif_text)),
    "memory_findings": bool(re.search(r"buffer|out.of.bounds|memory corrupt|use.after.free|overflow", sarif_text)),
    "integer_findings": bool(re.search(r"integer.{0,30}(overflow|underflow)|arithmetic overflow", sarif_text)),
    "error_disclosure_findings": bool(re.search(r"information exposure|error.{0,30}disclos", sarif_text)),
    "log_injection_findings": bool(re.search(r"log.{0,30}inject", sarif_text)),
    "malware_findings": bool(re.search(r"malware|trojan|spyware|ransomware", json.dumps(mobsf).lower())),
    "no_command_injection_findings": not bool(re.search(r"command.{0,30}inject|os command|shell inject", sarif_text)),
})

evidence_by_signal = {}
for signal, observed in signals.items():
    evidence_by_signal[signal] = [evidence(
        "DERIVED_SCAN_SIGNAL", "combined artifacts", signal,
        f"Deterministic signal {signal}={observed}."
    )] if observed is not None else []
evidence_by_signal["gitleaks_current"] = gitleaks_current_evidence[:3]
evidence_by_signal["gitleaks_any"] = gitleaks_evidence[:3]
evidence_by_signal["no_gitleaks_current"] = gitleaks_current_evidence[:3]
for signal in ("race_findings", "memory_findings", "integer_findings", "error_disclosure_findings", "log_injection_findings"):
    if signals[signal]:
        evidence_by_signal[signal] = sast_evidence[:3]

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

flags = []
output_flags = {}
capabilities = {
    # build_ios_ipa.sh intentionally uses CODE_SIGNING_ALLOWED=NO.
    "signed_ipa": False,
    "source_code": True,
    "static_analysis": True,
    "runtime_device_test": False,
    "backend_access": False,
    "organizational_documents": False,
}
coverage = {"evaluated": 0, "fallback": 0, "manual": 0, "out_of_scope": 0}
for fid in flag_ids:
    state, summary, notes, ev, method = evaluate_flag(fid, signals, evidence_by_signal, capabilities)
    bucket = (
        "out_of_scope" if method.startswith("out_of_scope:")
        else "manual" if method.startswith("manual:")
        else "fallback" if method.startswith("fallback:")
        else "evaluated"
    )
    coverage[bucket] += 1
    obj = {"id": fid, "title": fid.replace("_", " "), "description": "iOS security signal",
           "severity": "info", "expected_state": "good",
           "app_verdict": {"state": state, "summary": summary, "notes": notes, "evidence": ev,
                           "evidence_count": len(ev), "evaluation_method": method}}
    flags.append(obj)
    output_flags[fid] = obj["app_verdict"]

project = {"name": "iOS app", "platform": "ios", "generated_at": datetime.now(timezone.utc).isoformat(),
           "tools": ["CodeQL Swift", "Xcode/Clang Static Analyzer", "Semgrep Swift/Objective-C", "Gitleaks", "MobSF IPA", "Trivy"]}
fingerprint = {"schema_version": 2, "project": project, "capabilities": capabilities,
               "coverage": coverage, "flags": flags}
output = {"schema_version": 1, "project": project, "flags": output_flags,
          "raw": {"ios_signals": signals, "info_plists": [p for p, _ in plist_docs], "mobsf_static_full": mobsf,
                  "sast_merged_full": sast, "trivy_full": trivy,
                  "agent_payload_full": agent_payload, "gitleaks_summary": gitleaks_summary}}
(DATA / "vision360_fingerprint.json").write_text(json.dumps(fingerprint, ensure_ascii=False, indent=2), encoding="utf-8")
(DATA / "vision360_output.json").write_text(json.dumps(output, ensure_ascii=False), encoding="utf-8")
print(f"Generated iOS fingerprint with {len(flags)} flags and {len(sast_items)} SAST results; coverage={coverage}")
