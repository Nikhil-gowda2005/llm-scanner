"""
JSON reporter module.
Generates a structured, machine-readable JSON report from scan result data.

This report format is intentionally simple and stable — it mirrors the
internal scan result dict exactly, enriched with a top-level "meta" block.
Its primary purpose is machine consumption:

  - Feed into CI/CD pipelines (e.g. fail a build if critical findings exist)
  - Ingest into SIEM or security dashboards
  - Convert to SARIF format for GitHub Advanced Security or GitLab SAST
    (SARIF is the standard static-analysis interchange format; the flat
    structure of this JSON maps directly onto SARIF "results" objects)
  - Archive scan history for trend analysis over time

The HTML report (reporters/html_report.py) handles all visual complexity.
This file stays short and dependency-free by design.
"""

import json
import os

from detectors.scorer import aggregate_layer_summaries


TOOL_META = {
    "tool_name":   "LLM Security Scanner",
    "version":     "0.3.0",
    "report_type": "json",
}


def _build_finding_report(f: dict) -> dict:
    """
    Converts a raw scored finding into a clean, structured report record
    with explicit layer_1_heuristic and layer_2_judges blocks.
    """
    h = f.get("heuristic_data", {})
    layer1 = {
        "triggered":       bool(h.get("triggered", False)),
        "matched_pattern": h.get("matched_pattern", ""),
        "rule_tag":        h.get("detected_tag", f.get("detected_tag", "")),
        "confidence":      round(float(h.get("confidence", f.get("confidence", 0.0))), 3),
    }

    # Build per-judge records
    judge_records = []
    for ev in f.get("judge_evaluations", []):
        judge_records.append({
            "judge":      ev.get("judge", "?"),
            "model":      ev.get("model", "?"),
            "provider":   ev.get("provider", "?"),
            "verdict":    ev.get("verdict", "SAFE"),
            "confidence": round(float(ev.get("confidence", 0.0)), 3),
            "status":     ev.get("status", "unavailable"),
            "reason":     ev.get("reason", ""),
            "error":      ev.get("error"),
        })

    # Superior judge block
    sup = f.get("superior_judge", {})
    superior = None
    if sup:
        superior = {
            "invoked":       bool(sup.get("invoked", False)),
            "model":         sup.get("model", ""),
            "provider":      sup.get("provider", ""),
            "final_verdict": sup.get("final_verdict", ""),
            "confidence":    round(float(sup.get("confidence", 0.0)), 3),
            "reason":        sup.get("reason", ""),
            "status":        sup.get("status", ""),
        }

    cons = f.get("judge_consensus", {})
    layer2 = {
        "invoked":          len(judge_records) > 0,
        "judges":           judge_records,
        "consensus":        {
            "vulnerable":   cons.get("vulnerable", 0),
            "safe":         cons.get("safe", 0),
            "unavailable":  cons.get("unavailable", 0),
        },
        "disagreement":     bool(f.get("disagreement", False)),
        "superior_judge":   superior,
        "validation_status": f.get("validation_status", ""),
    }

    return {
        "id":               f.get("id", ""),
        "name":             f.get("name", ""),
        "category":         f.get("category", ""),
        "severity":         f.get("severity", ""),
        "risk_score":       f.get("risk_score", 0),
        "source":           f.get("source", "heuristic"),
        "prompt_sent":      f.get("prompt_sent", ""),
        "matched_text":     f.get("matched_text", ""),
        "layer_1_heuristic": layer1,
        "layer_2_judges":   layer2,
    }


def generate_json_report(scan_result: dict, output_path: str) -> str:
    """
    Serialises the full scan result to a formatted, machine-readable JSON file.
    Each finding includes explicit layer_1_heuristic and layer_2_judges blocks.

    Args:
        scan_result (dict): Complete scan result returned by ScanEngine.run_scan().
        output_path (str):  File path where the JSON report will be written.

    Returns:
        str: The output_path that was written.
    """
    output_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_dir, exist_ok=True)

    # Build structured findings
    structured_findings = [
        _build_finding_report(f) for f in scan_result.get("findings", [])
    ]
    # Sort by risk_score descending
    structured_findings.sort(key=lambda x: float(x.get("risk_score", 0)), reverse=True)

    summary = scan_result.get("summary", {})

    # Build per-layer aggregate summaries from raw findings
    raw_findings = scan_result.get("findings", [])
    layer_summaries = aggregate_layer_summaries(raw_findings)

    report = {
        "meta": TOOL_META,
        "target_url":            scan_result.get("target_url", ""),
        "scan_timestamp":        scan_result.get("scan_timestamp", ""),
        "total_payloads_tested": scan_result.get("total_payloads_tested", 0),
        "summary": {
            "total_findings":       summary.get("total_findings", 0),
            "by_severity":          summary.get("by_severity", {}),
            "by_category":          summary.get("by_category", {}),
            "average_risk_score":   summary.get("average_risk_score", 0),
            "validation_summary":   summary.get("validation_summary", {}),
        },
        "layer_summaries": layer_summaries,
        "findings": structured_findings,
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)

    return output_path


def generate_groq_report(scan_result: dict, output_path: str) -> str:
    """
    Generates a dedicated report containing only the LLM Judges' findings,
    individual model verdicts (e.g. GPT-OSS 120B/20B/27B), and Supreme Judge arbitration.
    """
    output_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_dir, exist_ok=True)

    raw_findings = scan_result.get("findings", [])
    layer_summaries = aggregate_layer_summaries(raw_findings)

    # Filter findings that had Layer 2 LLM Judges invoked
    judge_findings = []
    for f in raw_findings:
        rec = _build_finding_report(f)
        if rec["layer_2_judges"]["invoked"]:
            judge_findings.append({
                "id": rec["id"],
                "name": rec["name"],
                "category": rec["category"],
                "severity": rec["severity"],
                "prompt_sent": rec["prompt_sent"],
                "layer_2_judges": rec["layer_2_judges"],
            })

    report = {
        "meta": {
            "tool_name":   "LLM Security Scanner",
            "version":     "0.3.0",
            "report_type": "groq_judges_report",
        },
        "target_url":            scan_result.get("target_url", ""),
        "scan_timestamp":        scan_result.get("scan_timestamp", ""),
        "judge_summaries": {
            "judges":         layer_summaries.get("judges", []),
            "superior_judge": layer_summaries.get("superior_judge", {}),
        },
        "judge_findings": judge_findings,
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)

    return output_path

