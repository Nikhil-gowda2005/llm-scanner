"""
Scan engine module.
Orchestrates a full LLM security scan by connecting the payload library,
the Target HTTP connector, the heuristic detector, the LLM judge, and the
severity scorer.

Flow:
    ScanEngine.run_scan()
        └── load_payloads()           -> list[(category, payload_dict)]
            └── for each payload:
                    Target.send_message()         -> raw reply
                    detect_vulnerabilities()      -> raw findings  [Layer 1]
                    GroqJudge.judge_response()    -> verdict       [Layer 2, fallback]
                    score_finding()               -> enriched findings
        └── aggregate_summary()       -> scan summary dict
        └── returns full scan result dict
"""

import os
import time
import yaml
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any

import colorama
from colorama import Fore, Style

from core.target import Target
from detectors.heuristic import detect_vulnerabilities
from detectors.scorer import score_finding, aggregate_summary
from detectors.multi_judge import MultiJudgePanel
from detectors.llm_judge import GroqJudge



# Initialise colorama once at module load time.
# autoreset=True means we never need to manually call Style.RESET_ALL after each print.
colorama.init(autoreset=True)


class ScanEngine:
    """
    Orchestrates the end-to-end LLM security scan.

    Connects all subsystems:
        - Payload loader   : reads .yaml files from the payloads directory
        - Target connector : sends HTTP POST requests to the chatbot endpoint
        - Heuristic detector: pattern-matches the raw reply for known vulnerability signals
        - Scorer           : converts raw detections into prioritised, risk-scored findings
        - Aggregator       : summarises the complete scan outcome

    Attributes:
        target (Target):              The chatbot HTTP client.
        payload_dir (str):            Path to the directory containing payload YAML files.
        categories (list or None):    Optional whitelist of payload file stems to load.
                                      e.g. ["prompt_injection", "jailbreak"]
                                      If None, every .yaml file in payload_dir is loaded.
        rate_limit_seconds (float):   Seconds to sleep between consecutive requests.
                                      Guards against rate-limiting and ensures demo pacing.
    """

    def __init__(
        self,
        target: Target,
        payload_dir: str = "payloads",
        categories: Optional[List[str]] = None,
        rate_limit_seconds: float = 0.5,
        llm_judge: Optional[GroqJudge] = None,
        judge_mode: str = "fallback",
        multi_judge: Optional[MultiJudgePanel] = None,
    ):
        """
        Initialise the ScanEngine.

        Args:
            target (Target):              Configured Target connector instance.
            payload_dir (str):            Path to the payloads directory.
                                          Defaults to "payloads" (relative to cwd).
            categories (list, optional):  List of payload file name stems to include.
                                          Pass None to include all YAML files.
            rate_limit_seconds (float):   Inter-request delay in seconds. Defaults to 0.5.
            multi_judge (MultiJudgePanel, optional): If set, overrides llm_judge and
                                          runs the full 3-judge + superior-judge pipeline.
                                          When None and llm_judge is set, the legacy
                                          single-judge path is used. Defaults to None.
        """
        self.target = target
        self.payload_dir = payload_dir
        self.categories = [c.lower().strip() for c in categories] if categories else None
        self.rate_limit_seconds = rate_limit_seconds
        self.llm_judge = llm_judge   # Optional[GroqJudge] -- legacy single-judge
        self.judge_mode = judge_mode  # "fallback" | "always" | "off" | "consensus" | "full" | "legacy"
        self.multi_judge = multi_judge  # Optional[MultiJudgePanel] -- new multi-judge pipeline

    # ------------------------------------------------------------------
    # Payload loading
    # ------------------------------------------------------------------

    def load_payloads(self) -> List[Tuple[str, dict]]:
        """
        Discovers and loads all relevant payload YAML files from payload_dir.

        If self.categories is set, only files whose stem (filename without .yaml)
        matches an entry in the list are loaded. Otherwise all .yaml files are loaded.

        Each YAML file is expected to have the structure:
            category: "<OWASP label>"
            description: "..."
            payloads:
              - id: ...
                name: ...
                prompt: ...
                detects: [...]
                severity: ...

        Returns:
            list[tuple[str, dict]]: A flat list of (category_name, payload_dict) tuples,
                                    one entry per individual payload entry across all files.
        """
        results: List[Tuple[str, dict]] = []

        if not os.path.isdir(self.payload_dir):
            print(
                Fore.RED
                + f"[ERROR] Payload directory not found: {self.payload_dir}"
            )
            return results

        yaml_files = sorted(
            f for f in os.listdir(self.payload_dir) if f.endswith(".yaml")
        )

        if not yaml_files:
            print(Fore.YELLOW + f"[WARN]  No .yaml files found in '{self.payload_dir}'")
            return results

        for filename in yaml_files:
            file_stem = filename[: -len(".yaml")].lower()

            # Filter by category whitelist when specified
            if self.categories is not None and file_stem not in self.categories:
                print(Fore.YELLOW + f"[SKIP]  '{filename}' not in category filter — skipping")
                continue

            filepath = os.path.join(self.payload_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
            except Exception as exc:
                print(Fore.RED + f"[ERROR] Failed to read '{filename}': {exc}")
                continue

            if not data or not isinstance(data, dict):
                print(Fore.YELLOW + f"[WARN]  '{filename}' is empty or malformed — skipping")
                continue

            category = data.get("category", file_stem)
            payloads = data.get("payloads", [])

            if not payloads:
                print(Fore.YELLOW + f"[WARN]  '{filename}' has no payloads — skipping")
                continue

            print(
                Fore.CYAN
                + f"[LOAD]  '{filename}' -> {len(payloads)} payload(s) | {category}"
            )
            for payload in payloads:
                results.append((category, payload))

        return results

    # ------------------------------------------------------------------
    # Core scan orchestration
    # ------------------------------------------------------------------

    def run_scan(self) -> Dict[str, Any]:
        """
        Executes the complete LLM security scan.

        Steps:
            1. Load all payloads via load_payloads().
            2. For each payload, send the attack prompt to the target chatbot.
            3. On success, run heuristic detection on the reply.
            4. Score each raw finding and accumulate results.
            5. Sleep for rate_limit_seconds between requests.
            6. After all payloads, compute aggregate_summary().
            7. Return the full structured scan result.

        Terminal output uses colorama colors:
            CYAN   — section headers and progress lines
            GREEN  — no vulnerability detected (safe response)
            RED    — vulnerability detected (finding present)
            YELLOW — non-fatal warnings (skip/error per payload)

        Returns:
            dict: Full scan result with keys:
                - target_url (str)           : base_url + endpoint
                - scan_timestamp (str)       : ISO 8601 UTC timestamp
                - total_payloads_tested (int): number of payloads attempted
                - findings (list[dict])      : all enriched, scored finding dicts
                - summary (dict)             : aggregate_summary() output
        """
        scan_start_time = datetime.now(tz=timezone.utc)

        print()
        print(
            Fore.CYAN + Style.BRIGHT
            + "=" * 60
        )
        print(
            Fore.CYAN + Style.BRIGHT
            + "   LLM SECURITY SCANNER — SCAN STARTED"
        )
        print(
            Fore.CYAN
            + f"   Target  : {self.target.base_url}{self.target.endpoint}"
        )
        print(
            Fore.CYAN
            + f"   Started : {scan_start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        print(Fore.CYAN + Style.BRIGHT + "=" * 60)
        print()

        # ----------------------------------------------------------------
        # Step 1: Load payloads
        # ----------------------------------------------------------------
        payload_list = self.load_payloads()

        if not payload_list:
            print(Fore.RED + "[ERROR] No payloads loaded. Aborting scan.")
            return {
                "target_url":            self.target.base_url + self.target.endpoint,
                "scan_timestamp":        scan_start_time.isoformat(),
                "total_payloads_tested": 0,
                "findings":              [],
                "summary":               aggregate_summary([]),
            }

        print()
        print(
            Fore.CYAN + Style.BRIGHT
            + f"   Total payloads to test: {len(payload_list)}"
        )
        print(Fore.CYAN + "-" * 60)
        print()

        all_findings: List[dict] = []
        total_tested = 0



        # ----------------------------------------------------------------
        # Step 2-5: Iterate through each payload
        # ----------------------------------------------------------------
        for idx, (category, payload) in enumerate(payload_list, start=1):
            payload_id   = payload.get("id", f"UNKNOWN-{idx}")
            payload_name = payload.get("name", "Unnamed")
            prompt_text  = payload.get("prompt", "")

            # -- Progress banner --
            print(
                Fore.CYAN
                + f"[{idx}/{len(payload_list)}] "
                + Style.BRIGHT
                + f"[*] Sending {payload_id}: {payload_name}..."
            )
            print(
                Fore.CYAN
                + f"          Category : {category}"
            )


            # -- Guard: skip empty prompts --
            if not prompt_text:
                print(Fore.YELLOW + "    [SKIP] Payload has an empty prompt -- skipping.")
                print()
                continue

            total_tested += 1

            # -- Step 2: Send the attack prompt (with retry on transient failures) --
            _MAX_RETRIES = 2
            _RETRY_DELAY = 2.0
            response = None
            for _attempt in range(_MAX_RETRIES + 1):
                response = self.target.send_message(prompt_text)
                if response.get("success"):
                    break
                if _attempt < _MAX_RETRIES:
                    err_msg = response.get("error", "Unknown error")
                    print(
                        Fore.YELLOW
                        + f"    [RETRY] Attempt {_attempt + 1} failed: {err_msg}"
                        + f" — retrying in {_RETRY_DELAY}s..."
                    )
                    time.sleep(_RETRY_DELAY)

            # -- Step 3: Handle final failure after all retries exhausted --
            if not response.get("success"):
                err_msg = response.get("error", "Unknown error")
                status  = response.get("status_code", 0)
                print(
                    Fore.RED
                    + f"    [FAIL]  Request failed after {_MAX_RETRIES + 1} attempt(s)"
                    + f" (HTTP {status}): {err_msg}"
                )
                print(Fore.YELLOW + "           Skipping to next payload.")
                print()
                # Sleep even on failure to respect rate limiting
                if self.rate_limit_seconds > 0:
                    time.sleep(self.rate_limit_seconds)
                continue

            reply_text = response.get("reply", "")

            # -- Step 4: Heuristic detection (Layer 1) --
            elapsed_seconds = response.get("elapsed_seconds")
            raw_findings = detect_vulnerabilities(payload, reply_text, elapsed_seconds)

            # -- Step 4b: LLM Judge(s) — Layer 2 --
            # Priority: multi_judge (new) > llm_judge (legacy) > skip
            judge_result = None
            multi_judge_data = None

            if self.multi_judge and self.judge_mode != "off":
                # ---- NEW: Multi-judge evaluation pipeline ----
                _run_panel = self.multi_judge.should_invoke(raw_findings)
                if _run_panel:
                    print(
                        Fore.CYAN
                        + f"    [MULTI-JUDGE] Invoking 3-judge panel "
                        + f"(mode: {self.judge_mode})..."
                    )
                    mj_result = self.multi_judge.evaluate(
                        attack_prompt=prompt_text,
                        chatbot_response=reply_text,
                        category=category,
                    )
                    multi_judge_data = mj_result
                    consensus = mj_result.get("consensus", {})
                    val_status = mj_result.get("validation_status", "INCONCLUSIVE")

                    # Print individual judge results
                    for ev in mj_result.get("judge_evaluations", []):
                        j_label = ev.get("judge", "?")
                        j_model = ev.get("model", "?")
                        j_verdict = ev.get("verdict", "SAFE")
                        j_conf = ev.get("confidence", 0.0)
                        j_status = ev.get("status", "unavailable")
                        if j_status != "success":
                            print(
                                Fore.YELLOW
                                + f"    [{j_label.upper()}] {j_model}: UNAVAILABLE "
                                + f"(error: {ev.get('error', 'unknown')})"
                            )
                        elif j_verdict == "VULNERABLE":
                            print(
                                Fore.MAGENTA + Style.BRIGHT
                                + f"    [{j_label.upper()}] {j_model}: VULNERABLE "
                                + f"(confidence: {j_conf:.2f})"
                            )
                        else:
                            print(
                                Fore.CYAN
                                + f"    [{j_label.upper()}] {j_model}: SAFE "
                                + f"(confidence: {j_conf:.2f})"
                            )

                    # Print superior judge result if invoked
                    sup = mj_result.get("superior_judge", {})
                    if sup.get("invoked"):
                        sup_verdict = sup.get("final_verdict", "SAFE")
                        sup_conf = sup.get("confidence", 0.0)
                        sup_status_str = sup.get("status", "unavailable")
                        if sup_status_str == "success":
                            color = Fore.RED + Style.BRIGHT if sup_verdict == "VULNERABLE" else Fore.CYAN
                            print(
                                color
                                + f"    [SUPERIOR] {sup.get('model', '?')}: "
                                + f"{sup_verdict} -> {val_status} "
                                + f"(confidence: {sup_conf:.2f})"
                            )
                            if sup.get("reason"):
                                print(Fore.MAGENTA + f"               Reason: \"{sup['reason']}\"")
                        else:
                            print(
                                Fore.YELLOW
                                + f"    [SUPERIOR] Unavailable: {sup.get('error', 'unknown')}"
                            )

                    # Synthesise raw finding from multi-judge result if VULNERABLE
                    if mj_result.get("verdict") == "VULNERABLE" and val_status != "FALSE_POSITIVE":
                        judge_finding = {
                            "payload_id":    payload.get("id", "UNKNOWN"),
                            "payload_name":  payload.get("name", "Unknown"),
                            "detected_tag":  mj_result.get("detected_category", category),
                            "matched_text":  mj_result.get("reason", "")[:150],
                            "confidence":    mj_result.get("confidence", 0.5),
                            "source":        "multi_judge",
                            "multi_judge":   mj_result,
                        }
                        raw_findings.append(judge_finding)

                    # Print consensus summary
                    print(
                        Fore.CYAN
                        + f"    [PANEL] Consensus: "
                        + Fore.RED   + f"{consensus.get('vulnerable', 0)} VULNERABLE  "
                        + Fore.GREEN + f"{consensus.get('safe', 0)} SAFE  "
                        + Fore.YELLOW + f"{consensus.get('unavailable', 0)} UNAVAILABLE"
                    )
                    val_color = {
                        "CONFIRMED":      Fore.RED + Style.BRIGHT,
                        "POTENTIAL":      Fore.YELLOW,
                        "SAFE_CONFIRMED": Fore.GREEN + Style.BRIGHT,
                        "FALSE_POSITIVE": Fore.GREEN,
                        "INCONCLUSIVE":   Fore.CYAN,
                    }.get(val_status, Fore.CYAN)
                    print(val_color + f"    [VALIDATION] {val_status}")

            elif self.llm_judge and self.judge_mode not in ("off", "legacy"):
                # ---- LEGACY: Single-judge evaluation (backward compatible) ----
                _run_judge = (
                    self.judge_mode == "always"
                    or self.llm_judge.should_judge(raw_findings)
                )
                if _run_judge:
                    print(Fore.CYAN + f"    [JUDGE] Invoking {self.llm_judge.model}...")
                    judge_result = self.llm_judge.judge_response(
                        attack_prompt=prompt_text,
                        chatbot_response=reply_text,
                        category=category,
                    )
                    if judge_result["error"]:
                        print(
                            Fore.YELLOW
                            + f"    [JUDGE] Unavailable: {judge_result['reason']}"
                        )
                        judge_result = None
                    elif judge_result["verdict"] == "VULNERABLE":
                        judge_finding = {
                            "payload_id":   payload.get("id", "UNKNOWN"),
                            "payload_name": payload.get("name", "Unknown"),
                            "detected_tag": judge_result["detected_category"],
                            "matched_text": judge_result["reason"][:120],
                            "confidence":   judge_result["confidence"],
                            "source":       "llm_judge",
                        }
                        raw_findings.append(judge_finding)
                        print(
                            Fore.MAGENTA + Style.BRIGHT
                            + f"    [JUDGE] {self.llm_judge.model}: VULNERABLE "
                            + f"(confidence: {judge_result['confidence']:.2f})"
                        )
                        print(
                            Fore.MAGENTA
                            + f"            Reason: \"{judge_result['reason']}\""
                        )
                    else:
                        if not raw_findings:
                            print(
                                Fore.CYAN
                                + f"    [JUDGE] {self.llm_judge.model}: SAFE "
                                + f"(confidence: {judge_result['confidence']:.2f})"
                            )

            if not raw_findings:
                # Safe response -- no vulnerability signals detected
                print(
                    Fore.GREEN
                    + "    [OK]   No vulnerability detected."
                )

            else:
                # -- Step 5: Score each raw finding --
                scored_findings_this_payload: List[dict] = []
                for raw_finding in raw_findings:
                    scored = score_finding(payload, raw_finding, category)
                    all_findings.append(scored)
                    scored_findings_this_payload.append(scored)

                    tag      = scored["detected_tag"]
                    sev      = scored["severity"].upper()
                    rs       = scored["risk_score"]
                    matched  = scored["matched_text"]

                    print(
                        Fore.RED + Style.BRIGHT
                        + f"    [VULNERABLE] Found: {tag}"
                        + Fore.RED
                        + f" | Severity: {sev}"
                        + f" | Risk Score: {rs}/100"
                    )
                    print(
                        Fore.RED
                        + f"                Matched text : \"{matched}\""
                    )





            print()

            # -- Rate limiting: pause between requests --
            if self.rate_limit_seconds > 0 and idx < len(payload_list):
                time.sleep(self.rate_limit_seconds)

        # ----------------------------------------------------------------
        # Step 6: Aggregate summary
        # ----------------------------------------------------------------
        summary = aggregate_summary(all_findings)

        scan_end_time = datetime.now(tz=timezone.utc)
        duration_secs = round(
            (scan_end_time - scan_start_time).total_seconds(), 1
        )

        # -- Final results banner --
        print(Fore.CYAN + Style.BRIGHT + "=" * 60)
        print(Fore.CYAN + Style.BRIGHT + "   SCAN COMPLETE")
        print(Fore.CYAN + f"   Duration         : {duration_secs}s")
        print(Fore.CYAN + f"   Payloads tested  : {total_tested}")
        print(Fore.CYAN + f"   Total findings   : {summary['total_findings']}")
        print(
            Fore.CYAN
            + f"   By severity      : "
            + Fore.RED   + f"Critical={summary['by_severity'].get('critical', 0)}  "
            + Fore.RED   + f"High={summary['by_severity'].get('high', 0)}  "
            + Fore.YELLOW + f"Medium={summary['by_severity'].get('medium', 0)}  "
            + Fore.GREEN  + f"Low={summary['by_severity'].get('low', 0)}"
        )
        print(Fore.CYAN + f"   Avg risk score   : {summary['average_risk_score']}/100")

        if summary.get("highest_risk_finding"):
            top = summary["highest_risk_finding"]
            print(
                Fore.RED + Style.BRIGHT
                + f"   Highest risk     : [{top['id']}] {top['name']}"
                + Fore.RED
                + f" — Risk Score: {top['risk_score']}/100"
            )

        print(Fore.CYAN + Style.BRIGHT + "=" * 60)
        print()



        # ----------------------------------------------------------------
        # Step 7: Return structured scan result
        # ----------------------------------------------------------------
        return {
            "target_url":            self.target.base_url + self.target.endpoint,
            "scan_timestamp":        scan_start_time.isoformat(),
            "total_payloads_tested": total_tested,
            "findings":              all_findings,
            "summary":               summary,
        }