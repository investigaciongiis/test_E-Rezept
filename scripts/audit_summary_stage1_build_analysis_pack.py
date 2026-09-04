#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Audit Summary Stage 1 — Build analysis pack JSON

Reads:
  - /mnt/data/security_audit_requirements.xlsx (sheet: audit)

Writes:
  - /mnt/data/audit_summary_analysis_pack.json

This script is robust to different column headers produced by upstream steps.
It supports the current Excel headers produced by ai_security_audit_requirements_excel.py:
  - id (PUID)
  - Description (EN)
  - Result            (values: yes/no/n/a)
  - Justification (EN)
  - Flags used

It also supports legacy/Spanish variants (e.g., "Cumple", "Descripción").
"""

import json
import os
import re
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path

import pandas as pd


LITERALS_PATH = Path(__file__).resolve().parent / "audit_summary_literals.json"
with open(LITERALS_PATH, "r", encoding="utf-8") as f:
    literals = json.load(f)
APP_METADATA = literals["app_metadata"]
ACTORS = literals["actors"]

DEFAULT_EXCEL = "/mnt/data/security_audit_requirements.xlsx"
DEFAULT_SHEET = "audit"
DEFAULT_OUT = "/mnt/data/audit_summary_analysis_pack.json"

CAT_MAP = {
    "ICU": "Improper Credential Usage",
    "ISU": "Inadequate Supply Chain Security",
    "IAA": "Insecure Authentication/Authorization",
    "IOV": "Insufficient Input/Output Validation",
    "ICO": "Insecure Communication",
    "IPC": "Inadequate Privacy Controls",
    "IBP": "Insufficient Binary Protections",
    "SMC": "Security Misconfiguration",
    "IDS": "Insecure Data Storage",
    "ICR": "Insufficient Cryptography",
}

# Deterministic weakness-pattern mapping (reproducible; defensible; fast)
PATTERNS = [
    {
        "name": "Hardcoded credentials / embedded secrets",
        "keywords": [r"hardcoded", r"embedded\s+(?:secret|credential|api\s*key)", r"secret", r"api\s*key", r"auth(?:orization)?\s+token", r"credential", r"password.*code"],
        "severity": "High",
        "owner": "Mobile Engineering / Security Engineering",
    },
    {
        "name": "Weak authentication lifecycle / brute-force protections",
        "keywords": [r"brute", r"lockout", r"throttl", r"captcha", r"password", r"reauth", r"concurrent", r"session timeout", r"authentication"],
        "severity": "High",
        "owner": "Mobile Engineering",
    },
    {
        "name": "Authorization / RBAC / least privilege gaps",
        "keywords": [r"authorization", r"access control", r"role", r"rbac", r"least privilege", r"privilege", r"dual access", r"separation of duties", r"workgroup"],
        "severity": "High",
        "owner": "Mobile Engineering / Governance",
    },
    {
        "name": "Input validation & injection weaknesses (XSS/SQLi/command/log injection)",
        "keywords": [r"input validation", r"injection", r"xss", r"cross[-\s]?site scripting", r"sql", r"command injection", r"log injection", r"sanitize", r"encoding"],
        "severity": "High",
        "owner": "Mobile Engineering",
    },
    {
        "name": "Embedded browser / WKWebView hardening gaps",
        "keywords": [r"wkwebview", r"\bwebview", r"embedded\s+brows"],
        "severity": "High",
        "owner": "Mobile Engineering",
    },
    {
        "name": "Transport security / certificate validation weaknesses",
        "keywords": [r"tls", r"https", r"certificate", r"pinning", r"cleartext", r"mitm", r"trust manager", r"hostnameverifier", r"ssl"],
        "severity": "High",
        "owner": "Mobile Engineering / DevOps",
    },
    {
        "name": "Insecure local storage / key management gaps",
        "keywords": [r"data storage", r"storage", r"encrypt", r"keystore", r"sharedpreferences", r"database", r"cache", r"key management", r"data at rest"],
        "severity": "High",
        "owner": "Mobile Engineering",
    },
    {
        "name": "Supply chain governance & outdated components",
        "keywords": [r"outdated", r"dependency", r"library", r"vulnerab", r"supply chain", r"patch", r"sbom", r"cicd", r"official sources"],
        "severity": "High",
        "owner": "DevOps / Security Engineering",
    },
    {
        "name": "Tampering / reverse engineering protections missing",
        "keywords": [r"tamper", r"reverse", r"obfusc", r"debuggable", r"anti[-\s]?debug", r"repackag", r"binary protection", r"integrity check", r"root"],
        "severity": "Medium",
        "owner": "Mobile Engineering",
    },
    {
        "name": "Audit logging completeness / retention / alerting gaps",
        "keywords": [r"audit", r"log", r"retention", r"backup", r"central", r"alert", r"ISSO", r"forensic", r"override"],
        "severity": "Medium",
        "owner": "Governance / DevOps",
    },
    {
        "name": "Privacy notice / consent / governance gaps",
        "keywords": [r"privacy", r"consent", r"terms", r"notification", r"mask", r"blocked record", r"decision-maker", r"privacy policy"],
        "severity": "Medium",
        "owner": "Governance / Product",
    },
    {
        "name": "Security misconfiguration / insecure defaults",
        "keywords": [r"misconfig", r"default", r"cookie", r"httponly", r"secure flag", r"ddos", r"error.*reveal", r"server", r"configuration"],
        "severity": "Medium",
        "owner": "DevOps / Mobile Engineering",
    },
]

PREVALENCE_RUBRIC = {
    "High": "≥50",
    "Medium–High": "20–49",
    "Medium": "10–19",
    "Low–Medium": "<10",
}

def _find_col(columns: List[str], patterns: List[str]) -> Optional[str]:
    for p in patterns:
        rx = re.compile(p, re.IGNORECASE)
        for c in columns:
            if rx.search(str(c)):
                return c
    return None


def _norm_status(x: Any) -> str:
    """
    Normalizes upstream outputs into:
      - Compliant
      - Non-compliant
      - Not applicable

    Supports:
      - yes/no/n/a (from ai_security_audit_requirements_excel.py)
      - Compliant/Non-compliant/Not applicable
      - Spanish variants (si/sí, no, no aplica, cumple/no cumple)
    """
    if x is None:
        return "Not applicable"
    s = str(x).strip()
    if not s or s.lower() == "nan":
        return "Not applicable"

    s_low = s.lower().strip()

    # Upstream "Result" column (yes/no/n/a)
    if s_low in {"yes", "y"}:
        return "Compliant"
    if s_low in {"no", "n"}:
        return "Non-compliant"
    if s_low in {"n/a", "na", "not applicable"}:
        return "Not applicable"

    # Explicit compliance labels
    if s_low in {"compliant", "ok", "pass", "passed"}:
        return "Compliant"
    if s_low in {"non-compliant", "noncompliant", "fail", "failed"}:
        return "Non-compliant"

    # Spanish variants (legacy)
    if s_low in {"si", "sí", "cumple", "verdadero", "true"}:
        return "Compliant"
    if s_low in {"no cumple", "falso", "false"}:
        return "Non-compliant"
    if s_low in {"no aplica"}:
        return "Not applicable"

    # Conservative default
    return "Not applicable"


def _cat_from_puid(puid: str) -> Dict[str, str]:
    m = re.search(r"SECM-CAT-([A-Z]{3})-", puid or "")
    code = m.group(1) if m else "UNK"
    return {"code": code, "name": CAT_MAP.get(code, "Other")}


def _excerpt(s: Any, limit: int = 180) -> str:
    t = re.sub(r"\s+", " ", str(s or "")).strip()
    if not t or t.lower() == "nan":
        return ""
    return (t[:limit] + "…") if len(t) > limit else t


def _to_declarative(desc: str) -> str:
    t = re.sub(r"\s+", " ", str(desc or "")).strip()
    # Remove leading numbering
    t = re.sub(r"^\d+[\.\)]\s*", "", t)
    # Remove example parentheses if any
    t = re.sub(r"\(e\.g\.,.*?\)", "", t, flags=re.IGNORECASE)
    t = re.sub(r"\s+", " ", t).strip()

    if t.lower().startswith("application "):
        t = "The " + t
    elif not t.lower().startswith("the application"):
        if t:
            t = "The application must " + t[0].lower() + t[1:]
        else:
            t = "The application implements security controls."
    t = t.strip().rstrip(".") + "."
    return t


def _match_pattern(desc: str, flags: str) -> str:
    text = f"{desc or ''} {flags or ''}".lower()
    for p in PATTERNS:
        for kw in p["keywords"]:
            if re.search(kw, text, flags=re.IGNORECASE):
                return p["name"]
    return "Other control gaps"


def _prevalence_from_count(cnt: int) -> str:
    if cnt >= 50:
        return "High"
    if cnt >= 20:
        return "Medium–High"
    if cnt >= 10:
        return "Medium"
    return "Low–Medium"


def main() -> None:
    excel_path = os.getenv("AUDIT_EXCEL_PATH", DEFAULT_EXCEL)
    sheet = os.getenv("AUDIT_SHEET", DEFAULT_SHEET)
    out_path = os.getenv("AUDIT_ANALYSIS_JSON_PATH", DEFAULT_OUT)

    if not os.path.isfile(excel_path):
        raise SystemExit(f"[ERROR] Excel not found: {excel_path}")

    df = pd.read_excel(excel_path, sheet_name=sheet)

    cols = [str(c) for c in df.columns]

    col_puid = _find_col(cols, [r"^id\b", r"\bpuid\b"])
    col_desc = _find_col(cols, [r"description", r"descrip", r"descri", r"descripci", r"descripción"])
    col_result = _find_col(cols, [r"\bresult\b", r"\bstatus\b", r"\bcumple\b"])
    col_flags = _find_col(cols, [r"\bflags\b"])
    col_evid = _find_col(cols, [r"justif", r"evid", r"\bevidence\b"])
    col_na_reason = _find_col(cols, [r"n/a reason", r"scope reason"])

    missing = [("id (PUID)", col_puid), ("Description", col_desc), ("Result/Status", col_result), ("Flags", col_flags)]
    missing = [name for name, col in missing if col is None]
    if missing:
        raise SystemExit(f"[ERROR] Missing mandatory columns in sheet '{sheet}': {', '.join(missing)}")

    df = df.copy()
    df["PUID"] = df[col_puid].astype(str)
    df["Description"] = df[col_desc].astype(str)
    df["Flags"] = df[col_flags].astype(str).fillna("").str.strip()
    df["Evidence"] = df[col_evid].astype(str).fillna("").str.strip() if col_evid else ""
    df["NAReason"] = df[col_na_reason].astype(str).fillna("").str.strip() if col_na_reason else ""

    df["Status"] = df[col_result].apply(_norm_status)
    df["DeterminationBasis"] = df.apply(
        lambda r: (
            "evidenced_noncompliance"
            if r["Status"] == "Non-compliant" and "contradicting signals:" in str(r["Evidence"]).lower()
            else "evidence_not_found"
            if r["Status"] == "Non-compliant"
            else "supporting_evidence"
            if r["Status"] == "Compliant"
            else "not_applicable"
        ),
        axis=1,
    )
    df["CategoryCode"] = df["PUID"].apply(lambda x: _cat_from_puid(x)["code"])
    df["CategoryName"] = df["PUID"].apply(lambda x: _cat_from_puid(x)["name"])

    total_assessed = int(len(df))
    compliant = int((df["Status"] == "Compliant").sum())
    non_compliant = int((df["Status"] == "Non-compliant").sum())
    evidenced_non_compliant = int((df["DeterminationBasis"] == "evidenced_noncompliance").sum())
    evidence_not_found = int((df["DeterminationBasis"] == "evidence_not_found").sum())
    not_applicable = int((df["Status"] == "Not applicable").sum())
    na_rows = df[df["Status"] == "Not applicable"]
    dynamic_na = int(na_rows["NAReason"].str.contains("dynamic iOS analysis", case=False, na=False).sum())
    signed_ipa_na = int(na_rows["NAReason"].str.contains("signed production IPA", case=False, na=False).sum())
    other_na = int(not_applicable - len(na_rows[
        na_rows["NAReason"].str.contains("dynamic iOS analysis|signed production IPA", case=False, na=False)
    ]))
    applicable = int(compliant + non_compliant)
    overall_compliance_pct = float((compliant / applicable * 100.0) if applicable else 0.0)

    # Category metrics for charts (not for narrative dumps)
    grp = df.groupby(["CategoryCode", "CategoryName", "Status"]).size().reset_index(name="count")
    cat_stats: Dict[str, Dict[str, Any]] = {}
    for (code, name), sub in grp.groupby(["CategoryCode", "CategoryName"]):
        counts = {r["Status"]: int(r["count"]) for _, r in sub.iterrows()}
        c = int(counts.get("Compliant", 0))
        n = int(counts.get("Non-compliant", 0))
        na = int(counts.get("Not applicable", 0))
        app = c + n
        pct = float((c / app * 100.0) if app else 0.0)
        cat_stats[code] = {
            "category_name": name,
            "applicable": app,
            "compliant": c,
            "non_compliant": n,
            "not_applicable": na,
            "compliance_pct": pct,
        }

    # Verified positive controls candidates (Compliant + support signals)
    comp = df[df["Status"] == "Compliant"].copy()
    comp["HasSupport"] = comp["Flags"].astype(str).str.strip().ne("") | comp["Evidence"].astype(str).str.strip().ne("")
    comp = comp[comp["HasSupport"]].copy()
    comp["Declarative"] = comp["Description"].apply(_to_declarative)
    comp["EvidenceExcerpt"] = comp["Evidence"].apply(lambda x: _excerpt(x, 180))

    positive_controls = []
    for _, r in comp.iterrows():
        positive_controls.append({
            "puid": r["PUID"],
            "category_code": r["CategoryCode"],
            "category_name": r["CategoryName"],
            "declarative_statement": r["Declarative"],
            "flags_used": r["Flags"],
            "evidence_excerpt": r["EvidenceExcerpt"],
        })

    # Non-compliance mapping to weakness patterns
    non = df[df["Status"] == "Non-compliant"].copy()
    non["Pattern"] = non.apply(lambda rr: _match_pattern(rr["Description"], rr["Flags"]), axis=1)
    non["Anchor"] = non["Description"].apply(lambda x: _excerpt(x, 220))

    pattern_summary = []
    for pat, sub in non.groupby("Pattern"):
        sub = sub.copy()
        cnt = int(len(sub))
        ex = list(dict.fromkeys(sub["PUID"].tolist()))[:5]
        anchors = list(dict.fromkeys(sub["Anchor"].tolist()))[:2]
        meta = next((p for p in PATTERNS if p["name"] == pat), None)
        severity = meta["severity"] if meta else "Low"
        owner = meta["owner"] if meta else "Engineering"
        prevalence = _prevalence_from_count(cnt)
        pattern_summary.append({
            "pattern": pat,
            "mapped_noncompliant_count": cnt,
            "evidenced_noncompliant_count": int((sub["DeterminationBasis"] == "evidenced_noncompliance").sum()),
            "evidence_not_found_count": int((sub["DeterminationBasis"] == "evidence_not_found").sum()),
            "example_puids": ex,
            "description_anchors": anchors,
            "severity": severity,
            "recommended_owner": owner,
            "prevalence": prevalence,
        })

    # Sort by severity then count (deterministic)
    sev_rank = {"High": 3, "Medium": 2, "Low": 1}
    pattern_summary.sort(key=lambda x: (sev_rank.get(x["severity"], 0), x["mapped_noncompliant_count"]), reverse=True)

    out: Dict[str, Any] = {
        "generated_at_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "inputs": {
            "excel_path": excel_path,
            "sheet": sheet,
            "evidence_column_present": bool(col_evid),
            "detected_columns": {
                "puid": col_puid,
                "description": col_desc,
                "result_status": col_result,
                "flags": col_flags,
                "evidence": col_evid,
                "n_a_reason": col_na_reason,
            },
        },
        "app_metadata": APP_METADATA,
        "actors": ACTORS,
        "normalization": {
            "status_values": ["Compliant", "Non-compliant", "Not applicable"],
            "category_map": CAT_MAP,
            "result_mapping_note": "Upstream 'Result' values yes/no/n/a are normalized to Compliant/Non-compliant/Not applicable.",
        },
        "metrics": {
            "total_assessed": total_assessed,
            "applicable": applicable,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "evidenced_non_compliant": evidenced_non_compliant,
            "evidence_not_found_non_compliant": evidence_not_found,
            "not_applicable": not_applicable,
            "not_applicable_dynamic_analysis": dynamic_na,
            "not_applicable_signed_ipa": signed_ipa_na,
            "not_applicable_other": other_na,
            "overall_compliance_pct": overall_compliance_pct,
        },
        "category_metrics": cat_stats,
        "prevalence_rubric": PREVALENCE_RUBRIC,
        "positive_controls_candidates": positive_controls[:12],  # cap
        "weakness_patterns": pattern_summary,
        "notes": {
            "global_replacement": {"SEC-AM": "i-mSEC-AT"},
            "method_sentence": "The audit was carried out using the i-mSEC-AT (mobile SECurity Audit Tool).",
            "prohibitions": [
                "No category-level bullet dumps in narrative.",
                "No long exhaustive lists of IDs.",
                "No time-window subheadings inside Recommendations."
            ],
        }
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    print(f"[OK] analysis pack -> {out_path}")


if __name__ == "__main__":
    main()
