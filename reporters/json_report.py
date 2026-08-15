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


TOOL_META = {
    "tool_name":   "LLM Security Scanner",
    "version":     "1.0",
    "report_type": "json",
}


def generate_json_report(scan_result: dict, output_path: str) -> str:
    """
    Serialises the full scan result to a formatted, machine-readable JSON file.

    Injects a top-level ``meta`` key containing tool name, version, and report
    type before writing, so every output file is self-describing and can be
    processed without any out-of-band context.

    Args:
        scan_result (dict): Complete scan result returned by ScanEngine.run_scan().
                            Expected keys: target_url, scan_timestamp,
                            total_payloads_tested, findings, summary.
        output_path (str):  File path where the JSON report will be written.
                            Parent directories are created automatically if absent.

    Returns:
        str: The output_path that was written (unchanged, for caller convenience).
    """
    # Ensure the output directory exists before attempting to write
    output_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_dir, exist_ok=True)

    # Build the enriched report — meta block first for readability at the top
    report = {
        "meta":    TOOL_META,
        **scan_result,
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)

    return output_path
