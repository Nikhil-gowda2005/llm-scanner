"""
Main CLI entry point for llm-scanner.
Handles command-line argument parsing, orchestrates the scan, and saves reports.

Example:
    python cli.py --target http://localhost:5000 --apikey demo123
    python cli.py --target http://localhost:5000 --apikey demo123 --categories prompt_injection,jailbreak --format html
    python cli.py --target http://localhost:5000 --apikey demo123 --format json --rate-limit 1.0 --output ./reports
"""

import argparse
import os
import sys
import webbrowser
from datetime import datetime

import colorama
from colorama import Fore, Style

from core.target import Target
from core.engine import ScanEngine
from detectors.llm_judge import GroqJudge
from detectors.multi_judge import build_multi_judge_panel
from config_cmd import load_saved_config
from reporters.json_report import generate_json_report
from reporters.html_report import generate_html_report

colorama.init(autoreset=True)

# ──────────────────────────────────────────────────────────────────────────────
# Version
# ──────────────────────────────────────────────────────────────────────────────
VERSION = "0.3.0"


# ──────────────────────────────────────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────────────────────────────────────
BANNER = r"""
  _     _     __  __   ____                                 
 | |   | |   |  \/  | / ___|  ___ __ _ _ __  _ __   ___ _ __ 
 | |   | |   | |\/| | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |___| |___| |  | |  ___) | (_| (_| | | | | | | |  __/ |   
 |_____|_____|_|  |_| |____/ \___\__,_|_| |_|_| |_|\___|_|   

         LLM Security Scanner  {version}
         OWASP LLM Top 10 | AI Red-Teaming Toolkit
"""


def _print_banner() -> None:
    """Prints the ASCII-art tool banner to the terminal in cyan."""
    print(Fore.CYAN + Style.BRIGHT + BANNER.format(version=VERSION))


def _print_welcome() -> None:
    """
    Dynamic welcome/onboarding screen shown when llm-scanner is run with no
    arguments. Features a typewriter banner animation, live payload stats,
    a styled configuration panel, and colour-coded status indicators.
    """
    import time
    import yaml
    from config_cmd import load_saved_config, _mask

    W = 76  # total panel width (characters)

    def _bar(char="-", width=W):
        """Returns a horizontal divider line."""
        return "  +" + char * (width - 4) + "+"

    def _row(label, value, label_w=26, value_w=None):
        """Returns a formatted table row padded to panel width."""
        value_w = value_w or (W - label_w - 7)
        label   = str(label)[:label_w].ljust(label_w)
        value   = str(value)[:value_w].ljust(value_w)
        return f"  | {label} | {value} |"

    def _section(title):
        """Prints a section header bar."""
        pad  = W - len(title) - 6
        left = pad // 2
        right = pad - left
        print(Fore.CYAN + Style.BRIGHT
              + "  +" + "-" * left + " " + title + " " + "-" * right + "+")

    # ── 1. Typewriter banner ────────────────────────────────────────────────
    banner_lines = BANNER.format(version=VERSION).splitlines()
    for line in banner_lines:
        sys.stdout.write(Fore.CYAN + Style.BRIGHT + line + "\n")
        sys.stdout.flush()
        time.sleep(0.03)

    # ── 2. Spinner: loading payload stats ──────────────────────────────────
    payload_counts = {}
    payload_total  = 0
    payload_dir    = os.path.join(os.path.dirname(__file__), "payloads")
    spinner_frames = ["|", "/", "-", "\\"]
    labels = {
        "data_leakage":           "Sensitive Data Leakage",
        "excessive_agency":       "Excessive Agency",
        "insecure_plugin_design": "Insecure Plugin Design",
        "jailbreak":              "Jailbreak",
        "model_dos":              "Model Denial of Service",
        "model_theft_leak":       "Model Theft / IP Leakage",
        "output_handling":        "Insecure Output Handling",
        "overreliance":           "Overreliance",
        "prompt_injection":       "Prompt Injection",
    }

    if os.path.isdir(payload_dir):
        for i, (stem, label) in enumerate(labels.items()):
            frame = spinner_frames[i % len(spinner_frames)]
            sys.stdout.write(f"\r  {Fore.CYAN}{frame}{Style.RESET_ALL}  Loading payloads..."
                             + " " * 20)
            sys.stdout.flush()
            time.sleep(0.08)
            path = os.path.join(payload_dir, f"{stem}.yaml")
            if os.path.exists(path):
                try:
                    data  = yaml.safe_load(open(path, encoding="utf-8"))
                    count = len(data.get("payloads", []))
                    payload_counts[label] = count
                    payload_total += count
                except Exception:
                    payload_counts[label] = 0
        sys.stdout.write("\r" + " " * 50 + "\r")  # clear spinner line
        sys.stdout.flush()

    # ── 3. Summary bar ─────────────────────────────────────────────────────
    summary = f" v{VERSION}  |  OWASP LLM Top 10  |  {payload_total} payloads loaded "
    pad   = W - len(summary) - 4
    left  = pad // 2
    right = pad - left
    print(Fore.CYAN + Style.BRIGHT
          + "  +" + "=" * left + summary + "=" * right + "+")
    print()

    # ── 4. Configuration panel ─────────────────────────────────────────────
    cfg         = load_saved_config()
    chatbot_key = cfg.get("llm_scanner_api_key", "")
    groq_key    = cfg.get("groq_api_key", "")
    google_key  = cfg.get("google_ai_api_key", "")

    _section("CONFIGURATION")
    print(Fore.CYAN + _bar())
    print(Fore.CYAN + _row("Setting", "Value"))
    print(Fore.CYAN + _bar())

    if chatbot_key:
        print(Fore.GREEN  + _row("Chatbot API key",
                                  f"{_mask(chatbot_key)}  [READY]",
                                  label_w=24, value_w=44))
    else:
        print(Fore.YELLOW + _row("Chatbot API key",
                                  "(not set)  -> llm-scanner-config set-apikey KEY",
                                  label_w=24, value_w=44))

    if groq_key:
        print(Fore.GREEN  + _row("Groq key  (LLM Judge)",
                                  f"{_mask(groq_key)}  [ENABLED - 120B+27B+20B]",
                                  label_w=24, value_w=44))
    else:
        print(Fore.YELLOW + _row("Groq key  (LLM Judge)",
                                  "(not set)  -> console.groq.com (free)",
                                  label_w=24, value_w=44))

    print(Fore.CYAN + _bar())
    print()

    # ── 5. Payload library table ────────────────────────────────────────────
    if payload_counts:
        _section("PAYLOAD LIBRARY")
        print(Fore.CYAN + _bar())
        print(Fore.CYAN + _row("Category", "Payloads", label_w=40, value_w=28))
        print(Fore.CYAN + _bar())
        for label, count in payload_counts.items():
            color = Fore.GREEN if count > 0 else Fore.RED
            print(color + _row(label, str(count), label_w=40, value_w=28))
        print(Fore.CYAN + _bar())
        print(Fore.CYAN + Style.BRIGHT
              + _row("TOTAL", str(payload_total), label_w=40, value_w=28))
        print(Fore.CYAN + _bar())
        print()

    # ── 6. Quick start ─────────────────────────────────────────────────────
    _section("QUICK START")
    print(Fore.CYAN + _bar())
    if chatbot_key:
        cmds = [
            ("Scan (keys auto-loaded)",
             "llm-scanner --target http://localhost:5000"),
            ("Scan without opening report",
             "llm-scanner --target URL --no-open-browser"),
            ("Scan specific categories",
             "llm-scanner --target URL --categories jailbreak"),
            ("Slow / local LLM",
             "llm-scanner --target URL --timeout 120"),
        ]
    else:
        cmds = [
            ("First scan",
             "llm-scanner --target URL --apikey KEY"),
            ("Save chatbot key once",
             "llm-scanner-config set-apikey YOUR_KEY"),
            ("Enable LLM Judge",
             "llm-scanner-config set-groq-key gsk_xxx"),
            ("Open web dashboard",
             "llm-scanner-web"),
        ]
    for label, cmd in cmds:
        print(Fore.CYAN   + _row(label, "", label_w=26, value_w=42))
        print(Fore.WHITE  + _row("",     cmd, label_w=26, value_w=42))
        print(Fore.CYAN   + _bar("." if label != cmds[-1][0] else "-"))
    print()

    # ── 7. Commands reference ──────────────────────────────────────────────
    _section("COMMANDS")
    print(Fore.CYAN + _bar())
    commands = [
        ("llm-scanner --help",                 "Full options reference"),
        ("llm-scanner --version",              "Show version"),
        ("llm-scanner --target URL",           "Run a security scan"),
        ("llm-scanner-config set-apikey",      "Save chatbot API key"),
        ("llm-scanner-config set-groq-key",    "Save Groq key (LLM Judge)"),
        ("llm-scanner-config show",            "View saved configuration"),
        ("llm-scanner-web",                    "Open web dashboard (port 8080)"),
    ]
    for cmd, desc in commands:
        print(Fore.WHITE + _row(cmd, desc, label_w=38, value_w=30))
    print(Fore.CYAN + _bar())
    print()

    # ── 8. Status line ─────────────────────────────────────────────────────
    if chatbot_key:
        status_color = Fore.GREEN
        status_msg   = "  READY  -  Run: llm-scanner --target http://your-chatbot-url"
    else:
        status_color = Fore.YELLOW
        status_msg   = "  SETUP  -  Run: llm-scanner-config set-apikey YOUR_KEY"

    status_pad = W - len(status_msg) - 4
    print(status_color + Style.BRIGHT
          + "  +" + "=" * 2 + status_msg + "=" * max(0, status_pad - 2) + "+")
    print()



# ──────────────────────────────────────────────────────────────────────────────
# Argument parser
# ──────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    """
    Builds and returns the argparse argument parser with all CLI flags.

    Returns:
        argparse.ArgumentParser: Configured parser instance.
    """
    parser = argparse.ArgumentParser(
        prog="llm-scanner",
        description="LLM Security Scanner — OWASP LLM Top 10 Red-Teaming CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  llm-scanner --target http://localhost:5000 --apikey demo123\n"
            "  llm-scanner --target http://localhost:5000 --categories jailbreak,prompt_injection\n"
            "  llm-scanner --target http://localhost:5000  # keys auto-loaded from llm-scanner-config\n"
            "  llm-scanner --target http://localhost:5000 --no-open-browser  # don't auto-open report\n"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"llm-scanner {VERSION}",
    )

    parser.add_argument(
        "--target",
        required=True,
        metavar="URL",
        help="Base URL of the target AI application. Example: http://localhost:5000",
    )
    parser.add_argument(
        "--endpoint",
        default="/chat",
        metavar="PATH",
        help="API endpoint path on the target. Default: /chat",
    )
    parser.add_argument(
        "--apikey",
        required=False,
        default=os.environ.get("LLM_SCANNER_API_KEY", ""),
        metavar="KEY",
        help=(
            "API key sent via the auth header to the target chatbot. "
            "Can also be set via the LLM_SCANNER_API_KEY environment variable."
        ),
    )
    parser.add_argument(
        "--categories",
        default=None,
        metavar="LIST",
        help=(
            "Comma-separated list of payload categories to test. "
            "Example: prompt_injection,jailbreak  "
            "Omit to test all categories."
        ),
    )
    parser.add_argument(
        "--output",
        default="reports",
        metavar="DIR",
        help="Directory to save report files into. Default: reports/",
    )
    parser.add_argument(
        "--format",
        default="both",
        choices=["json", "html", "both"],
        help="Report output format. Choices: json | html | both. Default: both",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.5,
        dest="rate_limit",
        metavar="SECONDS",
        help="Seconds to wait between consecutive requests. Default: 0.5",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help=(
            "HTTP request timeout in seconds per payload. Default: 30. "
            "Increase to 60+ for slow or local LLMs (e.g. Ollama, LM Studio)."
        ),
    )
    parser.add_argument(
        "--message-field",
        default="message",
        dest="message_field",
        metavar="FIELD",
        help=(
            "JSON body field name for the chat message. Default: message. "
            "Use 'prompt' or 'query' if the target API uses a different field."
        ),
    )
    parser.add_argument(
        "--auth-header",
        default="X-API-Key",
        dest="auth_header",
        metavar="HEADER",
        help=(
            "HTTP header name used to send the API key. Default: X-API-Key. "
            "Use 'Authorization' for Bearer token APIs."
        ),
    )
    # ── LLM Judge (multi-judge panel + legacy single-judge) ─────────────────
    parser.add_argument(
        "--groq-key",
        required=False,
        default=os.environ.get("GROQ_API_KEY", ""),
        dest="groq_key",
        metavar="KEY",
        help=(
            "Groq API key for the LLM Judge panel (GPT-OSS 120B). "
            "Get a free key at console.groq.com. "
            "Can also be set via the GROQ_API_KEY environment variable."
        ),
    )
    parser.add_argument(
        "--google-ai-key",
        required=False,
        default=os.environ.get("GOOGLE_AI_API_KEY", ""),
        dest="google_ai_key",
        metavar="KEY",
        help=(
            "(Unused) Google AI Studio API key — kept for backward compatibility. "
            "All judges now use Groq GPT-OSS 120B."
        ),
    )
    parser.add_argument(
        "--judge-mode",
        choices=["consensus", "full", "fallback", "legacy", "always", "off"],
        default="consensus",
        dest="judge_mode",
        help=(
            "LLM judge invocation mode. "
            "'consensus' (default): 3-judge panel, superior judge on disagreement. "
            "'full': 3-judge panel + superior on every payload. "
            "'fallback': 3-judge panel, invoked only when heuristic confidence is low. "
            "'legacy'/'always': single Groq judge (backward-compatible). "
            "'off': disable all judges."
        ),
    )
    parser.add_argument(
        "--judge-model",
        default="openai/gpt-oss-120b",
        dest="judge_model",
        metavar="MODEL",
        help=(
            "Groq model ID to use for the legacy single-judge mode. "
            "Default: openai/gpt-oss-120b. "
            "See console.groq.com/docs/models for available models."
        ),
    )
    parser.add_argument(
        "--judge-threshold",
        type=float,
        default=0.7,
        dest="judge_threshold",
        metavar="FLOAT",
        help=(
            "Minimum heuristic confidence (0.0-1.0) to skip the LLM judge. "
            "If all heuristic findings are below this threshold, the judge is "
            "invoked for a second opinion. Default: 0.7."
        ),
    )
    # --open-browser now defaults to ON: every scan automatically opens the
    # HTML report when it's done, no flag needed. Pass --no-open-browser to
    # suppress it for a specific run (e.g. scripting many scans back-to-back).
    parser.add_argument(
        "--no-open-browser",
        action="store_false",
        default=True,
        dest="open_browser",
        help="Disable automatically opening the HTML report in the default browser.",
    )


    return parser


# ──────────────────────────────────────────────────────────────────────────────
# Report saving helpers
# ──────────────────────────────────────────────────────────────────────────────

def _ensure_output_dir(output_dir: str) -> str:
    """
    Ensures the report output directory exists, creating it if necessary.

    Args:
        output_dir (str): Path to the desired output directory.

    Returns:
        str: Absolute path to the output directory.
    """
    abs_dir = os.path.abspath(output_dir)
    os.makedirs(abs_dir, exist_ok=True)
    return abs_dir


def _timestamped_basename() -> str:
    """
    Generates a timestamp string suitable for use in report filenames.

    Returns:
        str: String of the form 'scan_YYYYMMDD_HHMMSS'.
    """
    return "scan_" + datetime.now().strftime("%Y%m%d_%H%M%S")


def _save_reports(
    scan_result: dict,
    output_dir: str,
    fmt: str,
    basename: str,
) -> dict:
    """
    Calls the appropriate report generator(s) and saves files to disk.

    Args:
        scan_result (dict): Full scan result dict from ScanEngine.run_scan().
        output_dir (str):   Absolute path to the output directory.
        fmt (str):          One of 'json', 'html', 'both'.
        basename (str):     File name stem (without extension) for the reports.

    Returns:
        dict: Mapping {'json': path_or_None, 'html': path_or_None}.
    """
    saved = {"json": None, "html": None}

    if fmt in ("json", "both"):
        json_path = os.path.join(output_dir, f"{basename}.json")
        try:
            generate_json_report(scan_result, json_path)
            saved["json"] = json_path
            file_url = f"file:///{os.path.abspath(json_path).replace(os.sep, '/')}"
            print(Fore.GREEN + f"[REPORT] JSON report saved : {file_url}")
        except Exception as exc:
            print(Fore.RED + f"[ERROR]  Failed to write JSON report: {exc}")

    if fmt in ("html", "both"):
        html_path = os.path.join(output_dir, f"{basename}.html")
        try:
            generate_html_report(scan_result, html_path)
            saved["html"] = html_path
            file_url = f"file:///{os.path.abspath(html_path).replace(os.sep, '/')}"
            print(Fore.GREEN + f"[REPORT] HTML report saved : {file_url}")
        except Exception as exc:
            print(Fore.RED + f"[ERROR]  Failed to write HTML report: {exc}")

    return saved


# ──────────────────────────────────────────────────────────────────────────────
# Final summary printer
# ──────────────────────────────────────────────────────────────────────────────

def _print_final_summary(scan_result: dict, saved_paths: dict) -> None:
    """
    Prints a coloured final summary line to the terminal after the scan completes.

    Args:
        scan_result (dict): Full scan result dict from ScanEngine.run_scan().
        saved_paths (dict): {'json': path_or_None, 'html': path_or_None}.
    """
    summary = scan_result.get("summary", {})
    total   = summary.get("total_findings", 0)
    by_sev  = summary.get("by_severity", {})
    critical = by_sev.get("critical", 0)
    high     = by_sev.get("high", 0)
    medium   = by_sev.get("medium", 0)
    low      = by_sev.get("low", 0)

    print()
    print(Fore.CYAN + Style.BRIGHT + "=" * 60)

    if total == 0:
        print(Fore.GREEN + Style.BRIGHT + "  Scan complete. No vulnerabilities detected.")
    else:
        severity_breakdown = (
            Fore.RED    + f"{critical} critical" +
            Fore.CYAN   + ", " +
            Fore.RED    + f"{high} high"         +
            Fore.CYAN   + ", " +
            Fore.YELLOW + f"{medium} medium"     +
            Fore.CYAN   + ", " +
            Fore.GREEN  + f"{low} low"
        )
        print(
            Fore.RED + Style.BRIGHT
            + f"  Scan complete. {total} finding(s): "
            + severity_breakdown
        )

    print()

    for label, path in [("JSON", saved_paths.get("json")), ("HTML", saved_paths.get("html"))]:
        if path:
            file_url = f"file:///{os.path.abspath(path).replace(os.sep, '/')}"
            print(Fore.CYAN + f"  {label} Report : {file_url}")

    avg_rs = summary.get("average_risk_score", 0.0)
    print(Fore.CYAN + f"  Avg Risk Score : {avg_rs}/100")

    top = summary.get("highest_risk_finding")
    if top:
        print(
            Fore.RED
            + f"  Top Finding    : [{top['id']}] {top['name']} "
            + f"| Risk: {top['risk_score']}/100"
        )

    print(Fore.CYAN + Style.BRIGHT + "=" * 60)
    print()


# ──────────────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Main CLI entry point.

    Parses arguments, creates the Target and ScanEngine, runs the scan,
    saves reports, and prints the final summary.  All exceptions that could
    indicate a misconfigured target or network issue are caught and displayed
    as clean, coloured error messages instead of raw tracebacks.
    """
    parser = _build_parser()

    # ── Welcome screen when no arguments given ───────────────────────────
    if len(sys.argv) == 1:
        _print_welcome()
        sys.exit(0)

    args = parser.parse_args()

    _print_banner()

    # ── Resolve API keys (CLI flag → env var → saved config file) ───────
    _saved = load_saved_config()

    # Chatbot API key
    if not args.apikey:
        args.apikey = _saved.get("llm_scanner_api_key", "")
    if not args.apikey:
        print(
            Fore.RED + Style.BRIGHT
            + "[ERROR] No chatbot API key found.\n"
            + "        Provide one via:\n"
            + "          --apikey YOUR_KEY\n"
            + "          $env:LLM_SCANNER_API_KEY = 'YOUR_KEY'\n"
            + "          llm-scanner-config set-apikey YOUR_KEY"
        )
        sys.exit(1)

    # Groq API key (optional — judge disabled if not found)
    if not args.groq_key:
        args.groq_key = _saved.get("groq_api_key", "")
        if args.groq_key and args.judge_mode != "off":
            print(
                Fore.CYAN
                + "[INFO]  Groq API key loaded from saved config — Groq judges enabled."
            )

    # Google AI API key (unused — kept for backward compat)
    if not args.google_ai_key:
        args.google_ai_key = _saved.get("google_ai_api_key", "")

    # ── Parse categories ────────────────────────────────────────────────
    categories = None
    if args.categories:
        categories = [c.strip().lower() for c in args.categories.split(",") if c.strip()]
        print(
            Fore.CYAN
            + f"[CONFIG] Category filter : {categories}"
        )

    # ── Print startup config ─────────────────────────────────────────────
    print(Fore.CYAN + f"[CONFIG] Target URL      : {args.target}{args.endpoint}")
    print(Fore.CYAN + f"[CONFIG] Output folder   : {args.output}")
    print(Fore.CYAN + f"[CONFIG] Report format   : {args.format}")
    print(Fore.CYAN + f"[CONFIG] Rate limit      : {args.rate_limit}s")
    print(Fore.CYAN + f"[CONFIG] Timeout         : {args.timeout}s")
    print(Fore.CYAN + f"[CONFIG] Message field   : {args.message_field}")
    print(Fore.CYAN + f"[CONFIG] Auth header     : {args.auth_header}")
    print(Fore.CYAN + f"[CONFIG] Open browser    : {args.open_browser}")
    if args.judge_mode == "off":
        print(Fore.CYAN + "[CONFIG] Judge           : off")
    elif args.judge_mode in ("legacy", "always") and args.groq_key:
        print(Fore.CYAN + f"[CONFIG] Judge           : legacy ({args.judge_model}) | threshold={args.judge_threshold}")
    else:
        judges_active = []
        if args.groq_key:
            judges_active += ["J1 GPT-OSS 120B", "J2 GPT-OSS 27B", "J3 GPT-OSS 20B", "Superior 120B"]
        if judges_active:
            print(Fore.CYAN + f"[CONFIG] Multi-judge     : {', '.join(judges_active)} | mode={args.judge_mode}")
        else:
            print(Fore.YELLOW + "[CONFIG] Judge           : no API keys — disabled (heuristics only)")
    print()


    try:
        # -- Initialise subsystems --
        target = Target(
            base_url=args.target,
            endpoint=args.endpoint,
            api_key=args.apikey,
            timeout=args.timeout,
            message_field=args.message_field,
            auth_header=args.auth_header,
        )

        # -- Build judge subsystem --
        multi_judge = None
        llm_judge   = None
        judge_mode  = args.judge_mode

        if judge_mode == "legacy" or (judge_mode in ("always",) and args.groq_key):
            # Legacy single-judge path (backward compatible)
            if args.groq_key:
                threshold = getattr(args, 'judge_threshold', 0.7)
                llm_judge = GroqJudge(
                    api_key=args.groq_key,
                    model=getattr(args, 'judge_model', 'openai/gpt-oss-120b'),
                    threshold=threshold,
                )
                print(
                    Fore.CYAN
                    + f"[INFO]  Legacy judge: {llm_judge.model} (mode: {judge_mode})"
                )
        elif judge_mode not in ("off",):
            # Multi-judge path (consensus / full / fallback)
            multi_judge = build_multi_judge_panel(
                groq_key=args.groq_key,
                google_ai_key=args.google_ai_key,
                mode=judge_mode,
                threshold=getattr(args, 'judge_threshold', 0.7),
            )
            if multi_judge:
                panel_size = len(multi_judge.judges)
                has_sup    = multi_judge.superior and multi_judge.superior.is_available()
                print(
                    Fore.CYAN
                    + f"[INFO]  Multi-judge panel: {panel_size} judges | "
                    + f"Superior: {'enabled' if has_sup else 'disabled'} | "
                    + f"mode: {judge_mode}"
                )
            else:
                print(Fore.YELLOW + "[WARN]  No API keys found — judge disabled.")

        engine = ScanEngine(
            target=target,
            payload_dir=os.path.join(os.path.dirname(__file__), "payloads"),
            categories=categories,
            rate_limit_seconds=args.rate_limit,
            llm_judge=llm_judge,
            judge_mode=judge_mode,
            multi_judge=multi_judge,
        )

        # ── Run the scan ─────────────────────────────────────────────────
        scan_result = engine.run_scan()

        # ── Save reports ─────────────────────────────────────────────────
        output_dir  = _ensure_output_dir(args.output)
        basename    = _timestamped_basename()
        saved_paths = _save_reports(scan_result, output_dir, args.format, basename)

        # ── Print final summary ───────────────────────────────────────────
        _print_final_summary(scan_result, saved_paths)

        # ── Auto-open HTML report in browser (unless --no-open-browser) ───
        if args.open_browser and saved_paths.get("html"):
            html_abs = os.path.abspath(saved_paths["html"])
            file_url = f"file:///{html_abs.replace(os.sep, '/')}"
            print(Fore.CYAN + f"[BROWSER] Opening report: {file_url}")
            try:
                if sys.platform == "win32":
                    os.startfile(html_abs)
                else:
                    webbrowser.open(file_url)
            except Exception:
                webbrowser.open(file_url)

    except KeyboardInterrupt:
        print()
        print(Fore.YELLOW + "\n[ABORT] Scan interrupted by user (Ctrl+C).")
        sys.exit(0)

    except ConnectionRefusedError:
        print(
            Fore.RED + Style.BRIGHT
            + "\n[ERROR] Could not connect to target. Is the app running at "
            + f"{args.target}{args.endpoint} ?"
        )
        sys.exit(1)

    except Exception as exc:
        print(
            Fore.RED + Style.BRIGHT
            + f"\n[ERROR] An unexpected error occurred: {exc}"
        )
        print(
            Fore.YELLOW
            + "        Tip: Check that your --target URL and --apikey are correct, "
            "and that the target chatbot is running."
        )
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()