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
from detectors.llm_judge import GroqJudge
from core import sound as _sound
from core import live_status as _ls

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
        sound_enabled: bool = False,
        live_map_enabled: bool = False,
        llm_judge: Optional[GroqJudge] = None,
        judge_mode: str = "fallback",
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
            sound_enabled (bool):         If True, play audio beeps during the scan to
                                          signal safe/vulnerable/critical results.
                                          Defaults to False (no sound). Pass --sound via
                                          the CLI to enable. Requires Windows + audio hw.
            live_map_enabled (bool):      If True, write reports/live_status.json after
                                          each payload so attack_map.html can poll it.
                                          Defaults to False. Pass --live-map via the CLI.
        """
        self.target = target
        self.payload_dir = payload_dir
        self.categories = [c.lower().strip() for c in categories] if categories else None
        self.rate_limit_seconds = rate_limit_seconds
        self.sound_enabled = sound_enabled
        _sound.SOUND_ENABLED = sound_enabled
        self.live_map_enabled = live_map_enabled
        self.llm_judge = llm_judge   # Optional[GroqJudge] — None means judge disabled
        self.judge_mode = judge_mode  # "fallback" | "always" | "off"

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
        # Live Attack Map: build initial status and pre-count per-category
        # totals so the map can show accurate progress from the start.
        # ----------------------------------------------------------------
        _lm_status: Dict[str, Any] = {}
        _lm_path = "reports/live_status.json"
        if self.live_map_enabled:
            try:
                # Collect ordered unique categories and per-category totals
                _cat_order: List[str] = []
                _cat_totals: Dict[str, int] = {}
                for _cat, _pl in payload_list:
                    if _cat not in _cat_totals:
                        _cat_order.append(_cat)
                        _cat_totals[_cat] = 0
                    _cat_totals[_cat] += 1
                _lm_status = _ls.init_status(
                    categories=_cat_order,
                    target_url=self.target.base_url + self.target.endpoint,
                )
                # Fill in per-category totals and overall total
                for _cat in _cat_order:
                    _lm_status["categories"][_cat]["total"] = _cat_totals[_cat]
                _lm_status["overall_progress"]["total"] = len(payload_list)
                _ls.write_status(_lm_status, _lm_path)
            except Exception:
                pass

        # Track which category we are currently inside (for state transitions)
        _lm_prev_category: Optional[str] = None

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

            # -- Live map: detect category transitions --
            if self.live_map_enabled and _lm_status:
                try:
                    if category != _lm_prev_category:
                        # Finalise previous category state (if any)
                        if _lm_prev_category and _lm_prev_category in _lm_status["categories"]:
                            prev_cat_data = _lm_status["categories"][_lm_prev_category]
                            prev_cat_data["state"] = (
                                "vulnerable" if prev_cat_data["findings"] > 0 else "safe"
                            )
                            _ls.write_status(_lm_status, _lm_path)
                        # Mark new category as testing
                        if category in _lm_status["categories"]:
                            _lm_status["categories"][category]["state"] = "testing"
                            _ls.write_status(_lm_status, _lm_path)
                        _lm_prev_category = category
                except Exception:
                    pass

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

            # -- Step 4b: LLM Judge (Layer 2, secondary / fallback) --
            judge_result = None
            if self.llm_judge and self.judge_mode != "off":
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
                        # Judge found something — synthesise a finding
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
                # -- Optional sound: soft high-pitched blip for safe result --
                if self.sound_enabled:
                    try:
                        _sound.play_safe_sound()
                    except Exception:
                        pass
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

                # -- Optional sound: alert tone based on highest severity --
                if self.sound_enabled:
                    try:
                        severities = [
                            f["severity"].lower()
                            for f in scored_findings_this_payload
                        ]
                        if "critical" in severities:
                            _sound.play_critical_sound()
                        else:
                            _sound.play_vulnerable_sound()
                    except Exception:
                        pass

            # -- Live map: update per-payload and per-category counts --
            if self.live_map_enabled and _lm_status:
                try:
                    _lm_status["overall_progress"]["tested"] = total_tested
                    if category in _lm_status["categories"]:
                        _lm_status["categories"][category]["tested"] += 1
                        # raw_findings is always defined after detect_vulnerabilities()
                        if raw_findings:
                            _lm_status["categories"][category]["findings"] += len(raw_findings)
                    _ls.write_status(_lm_status, _lm_path)
                except Exception:
                    pass

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

        # -- Live map: finalise last category + mark scan finished --
        if self.live_map_enabled and _lm_status:
            try:
                if _lm_prev_category and _lm_prev_category in _lm_status["categories"]:
                    last = _lm_status["categories"][_lm_prev_category]
                    last["state"] = "vulnerable" if last["findings"] > 0 else "safe"
                _lm_status["overall_progress"]["tested"] = total_tested
                _lm_status["finished"] = True
                _ls.write_status(_lm_status, _lm_path)
            except Exception:
                pass

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