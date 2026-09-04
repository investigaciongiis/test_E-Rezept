"""Deterministic mapping from iOS catalogue flags to observable scan signals."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple


@dataclass(frozen=True)
class Rule:
    signal: str
    # False means that not finding the pattern is not enough to prove absence.
    conclusive_absence: bool = True
    requires: Optional[str] = None


# Exact mappings take precedence.  A signal describes whether the named feature
# or risk was observed.  The audit layer decides whether presence is good or bad.
EXACT_RULES: Dict[str, Rule] = {
    "has_api_keys_in_version_control": Rule("gitleaks_any"),
    "has_secrets_generic_found": Rule("gitleaks_any"),
    "has_secrets_count": Rule("gitleaks_any"),
    "has_hardcoded_credentials": Rule("gitleaks_current"),
    "has_signing_creds_not_hardcoded": Rule("no_gitleaks_current"),
    "has_secrets_secure_keystore_env_vars": Rule("secure_secret_injection"),
    "has_secure_ci_secret_injection": Rule("secure_secret_injection"),
    "has_ci_cd_uses_encrypted_keys": Rule("secure_secret_injection"),
    "has_published_security_contact": Rule("published_security_contact", False),
    "has_safe_object_serialization": Rule("safe_object_serialization", False),
    "has_safe_object_deserialization": Rule("safe_object_deserialization", False),
    "has_biometric_enrollment_validation": Rule("biometric_enrollment_validation", False),
    "has_no_tls_validation_bypass": Rule("no_tls_validation_bypass"),
    "has_command_injection_protection": Rule("no_command_injection_findings"),
    "has_ios_sandbox_isolation": Rule("ios_sandbox_isolation", False, "signed_ipa"),
    "has_environment_specific_api_keys": Rule("environment_configuration"),
    "has_env_specific_api_credentials_configured": Rule("environment_configuration"),
    "has_separate_environment_credentials": Rule("separate_environment_credentials", False),
    "has_authenticated_scoped_ios_ipc": Rule("authenticated_scoped_ios_ipc", False),
    "has_unique_api_key_per_app_instance": Rule("unique_api_key_per_app_instance", False, "backend_evidence"),
    "has_api_key_usage_restrictions": Rule("api_key_usage_restrictions", False, "backend_evidence"),
    "ios_certificate_pinning": Rule("certificate_pinning", False),
    "has_https_with_cert_pinning": Rule("certificate_pinning", False),
    "has_ssl_cert_pinning_implemented": Rule("certificate_pinning", False),
    "has_tls_ssl_pinning_implemented": Rule("certificate_pinning", False),
    "ios_insecure_random": Rule("insecure_random"),
    "ios_get_task_allow": Rule("get_task_allow", requires="signed_ipa"),
    "has_get_task_allow_disabled": Rule("get_task_allow_disabled", requires="signed_ipa"),
    "ios_dynamic_code_loading": Rule("dynamic_code_loading"),
    "has_dynamic_code_loading": Rule("dynamic_code_loading"),
    "has_no_external_code_loading": Rule("no_dynamic_code_loading"),
    "ios_file_sharing_enabled": Rule("file_sharing"),
    "has_no_public_file_storage": Rule("no_public_file_storage"),
    "ios_sensitive_permissions_present": Rule("sensitive_permissions"),
    "ios_ats_arbitrary_loads": Rule("ats_arbitrary_loads"),
    "has_ats_secure_configuration": Rule("ats_secure_configuration"),
    "has_no_unjustified_ats_exceptions": Rule("ats_secure_configuration"),
    "ios_sensitive_backup_exposure": Rule("backup_exposure", False, "manual_review"),
    "has_webview_components": Rule("webview"),
    "has_webview_javascript": Rule("webview_javascript"),
    "has_webview_file_scheme": Rule("webview_file_access"),
    "has_webview_remote_content": Rule("webview_remote_content"),
    "has_secure_wkwebview_configuration": Rule("secure_webview_configuration", False),
    "has_wkwebview_navigation_allowlist": Rule("webview_navigation_validation", False),
    "has_wkwebview_safe_message_handlers": Rule("safe_webview_message_handlers", False),
    "has_insecure_http_based_webview_communication": Rule("insecure_http"),
    "has_keychain_secure_accessibility": Rule("keychain_accessibility"),
    "has_keychain_device_only_protection": Rule("keychain_device_only"),
    "has_os_secure_key_storage": Rule("keychain"),
    "has_auth_keys_stored_in_secure_hardware": Rule("secure_enclave"),
    "has_sensitive_data_encrypted_with_os_keystore": Rule("keychain"),
    "has_secure_local_authentication": Rule("biometric"),
    "has_biometric_keychain_binding": Rule("biometric_keychain_binding", False),
    "has_jailbreak_detection": Rule("jailbreak_detection"),
    "has_app_attest": Rule("app_attest"),
    "has_devicecheck": Rule("device_check"),
    "has_privacy_manifest": Rule("privacy_manifest"),
    "has_required_reason_api_declarations": Rule("required_reason_apis"),
    "has_third_party_sdk_privacy_manifest": Rule("third_party_privacy_manifest", False),
    "has_minimal_entitlements": Rule("minimal_entitlements", False, "signed_ipa"),
    "has_secure_app_groups": Rule("app_groups"),
    "has_secure_ios_ipc": Rule("secure_ios_ipc"),
    "has_ios_ipc_authorization_checks": Rule("ios_ipc_authorization_checks", False),
    "has_universal_links_validation": Rule("universal_links_validation"),
    "has_url_scheme_input_validation": Rule("url_scheme_validation"),
    "has_secure_pasteboard_usage": Rule("secure_pasteboard", False),
    "has_app_switcher_snapshot_protection": Rule("background_redaction", False),
    "has_clears_ui_on_background": Rule("background_redaction", False),
    "has_screen_capture_protection": Rule("screen_capture_protection", False),
    "has_notification_data_redaction": Rule("notification_redaction"),
    "has_notification_leaks_sensitive_data": Rule("notification_sensitive_data"),
    "has_secure_notifications": Rule("notification_redaction"),
    "has_supports_manual_logout": Rule("logout"),
    "has_clears_auth_data_on_logout": Rule("logout_cleanup"),
    "has_clears_cookies_on_logout": Rule("cookie_cleanup"),
    "has_clears_local_session_data_on_logout": Rule("logout_cleanup"),
    "has_sensitive_memory_cleanup": Rule("sensitive_memory_cleanup", False),
    "has_logout_invalidates_server_session": Rule("server_logout", False, "backend_evidence"),
    "has_token_based_auth": Rule("token_auth"),
    "has_jwt_tokens": Rule("jwt"),
    "has_oauth2_authentication": Rule("oauth"),
    "has_stores_auth_tokens_in_plaintext": Rule("plaintext_token_storage"),
    "has_stores_keys_in_plaintext": Rule("plaintext_key_storage"),
    "has_stores_pii_in_plaintext": Rule("plaintext_pii_storage"),
    "has_uses_encrypted_local_database": Rule("encrypted_database"),
    "has_data_protection": Rule("data_protection"),
    "has_sensitive_files_excluded_from_backup": Rule("backup_exclusion"),
    "has_swift_strict_concurrency": Rule("strict_concurrency"),
    "has_resilient_ios_background_tasks": Rule("resilient_background_tasks"),
    "has_security_state_race_protection": Rule("race_protection", False),
    "has_memory_safe_language_usage": Rule("swift_sources"),
    "has_race_condition_vulnerabilities": Rule("race_findings"),
    "has_buffer_overflow_vulnerabilities": Rule("memory_findings"),
    "has_memory_corruption_vulnerabilities": Rule("memory_findings"),
    "has_out_of_bounds_vulnerabilities": Rule("memory_findings"),
    "has_integer_arithmetic_vulnerabilities": Rule("integer_findings"),
    "has_null_pointer_protection_implemented": Rule("swift_sources"),
    "has_error_messages_disclose_internal_details": Rule("error_disclosure_findings"),
    "has_log_injection_vulnerabilities": Rule("log_injection_findings"),
    "has_malware_detections": Rule("malware_findings"),
    "has_aslr": Rule("aslr", False),
    "has_nx": Rule("nx", False),
    "has_stack_canary": Rule("stack_canary", False),
    "has_valid_ios_signature": Rule("valid_signature", False, "signed_ipa"),
    "has_production_code_signing": Rule("production_signing", False, "signed_ipa"),
    "has_no_development_entitlements": Rule("get_task_allow_disabled", requires="signed_ipa"),
    "has_cert_signed_with_code_signing_cert": Rule("valid_signature", requires="signed_ipa"),
    "has_cert_uses_sha1_signature_algorithm": Rule("sha1_signature", requires="signed_ipa"),
    "has_cert_validity_long_term": Rule("long_lived_signing_cert", requires="signed_ipa"),
}


# Conservative token fallbacks for equivalent catalogue names.
TOKEN_RULES: Tuple[Tuple[str, Rule], ...] = (
    ("hardcoded", Rule("hardcoded_secret")),
    ("weak_crypto", Rule("weak_crypto")),
    ("ssl_pinning", Rule("certificate_pinning", False)),
    ("certificate_pinning", Rule("certificate_pinning")),
    ("insecure_http", Rule("insecure_http")),
)


def rule_for(flag_id: str) -> Optional[Rule]:
    fid = flag_id.lower()
    if fid in EXACT_RULES:
        return EXACT_RULES[fid]
    return next((rule for token, rule in TOKEN_RULES if token in fid), None)


def manual_category(flag_id: str) -> Tuple[str, str]:
    fid = flag_id.lower()
    if fid.startswith(("has_org_", "has_defined_")) or any(
        token in fid for token in ("_policy", "_process", "_procedure", "_retention", "pentest", "security_assessment")
    ):
        return "organizational", "organizational policy, process, or documentary evidence"
    if any(token in fid for token in (
        "backend", "server_side", "_api", "rbac", "account_lifecycle", "audit_trail",
        "siem", "session_id", "saml", "soap", "replay", "rate_limiting", "dos_protection",
    )):
        return "backend", "backend configuration, server logs, or an authenticated integration test"
    if any(token in fid for token in (
        "patient", "clinical", "consent", "data_deletion", "data_export", "uninstall",
        "runtime", "device_loss", "emergency_access", "transaction_recovery", "offline",
    )):
        return "runtime", "a runtime device/end-to-end test or product-level functional evidence"
    return "manual", "manual review or evidence not represented by the current static-analysis artifacts"


def capability_for_flag(flag_id: str) -> Optional[str]:
    """Return the essential non-static capability needed to assess a flag."""
    rule = rule_for(flag_id)
    if rule and rule.requires:
        return rule.requires
    if rule is not None:
        return None
    category, _ = manual_category(flag_id)
    return {
        "runtime": "runtime_device_test",
        "backend": "backend_evidence",
        "organizational": "organizational_evidence",
        "manual": "manual_review",
    }[category]


def evaluate_flag(
    flag_id: str,
    signals: Mapping[str, Optional[bool]],
    evidence_by_signal: Mapping[str, List[Dict[str, Any]]],
    capabilities: Optional[Mapping[str, bool]] = None,
) -> Tuple[str, str, str, List[Dict[str, Any]], str]:
    """Return state, summary, notes, evidence and evaluation method."""
    rule = rule_for(flag_id)
    capabilities = capabilities or {}
    if rule is None:
        category, required_evidence = manual_category(flag_id)
        required_capability = capability_for_flag(flag_id)
        if required_capability and not capabilities.get(required_capability, False):
            capability_descriptions = {
                "runtime_device_test": "dynamic iOS execution on a supported runtime device",
                "backend_evidence": "backend configuration, server logs, or an authenticated integration test",
                "organizational_evidence": "organizational policy, process, or documentary evidence",
                "manual_review": "manual evidence not represented by the automated static-analysis artifacts",
            }
            return (
                "out_of_scope",
                "NA",
                f"Not evaluated: this check requires {capability_descriptions[required_capability]}, "
                "which is outside the predefined automated static audit profile.",
                [],
                f"out_of_scope:{required_capability}",
            )
        return (
            "not_detected",
            "NO",
            f"Conservative fallback: no supporting evidence was found in the supplied artifacts; this control requires {required_evidence}.",
            [],
            f"manual:{category}",
        )

    if rule.requires and not capabilities.get(rule.requires, False):
        reason = (
            "a signed production IPA, but the pipeline intentionally supplies an unsigned IPA"
            if rule.requires == "signed_ipa"
            else f"the unavailable {rule.requires} assessment capability"
        )
        return (
            "out_of_scope",
            "NA",
            f"Not evaluated: this check requires {reason}.",
            [],
            f"out_of_scope:{rule.requires}",
        )

    observed = signals.get(rule.signal)
    ev = list(evidence_by_signal.get(rule.signal, []))[:3]
    if observed is None or (observed is False and not rule.conclusive_absence):
        return (
            "not_detected",
            "NO",
            f"Conservative fallback: the supplied artifacts contain no supporting evidence for {rule.signal}.",
            ev,
            f"fallback:{rule.signal}",
        )

    summary = "YES" if observed else "NO"
    return (
        "detected" if observed else "not_detected",
        summary,
        f"Deterministic iOS artifact check: {rule.signal}={str(observed).lower()}.",
        ev,
        rule.signal,
    )
