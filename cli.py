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
from config_cmd import load_saved_config
from reporters.json_report import generate_json_report
from reporters.html_report import generate_html_report

colorama.init(autoreset=True)

# ──────────────────────────────────────────────────────────────────────────────
# Version
# ──────────────────────────────────────────────────────────────────────────────
VERSION = "0.2.0"


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


    if os.path.isdir(payload_dir):
        yaml_files = sorted(f for f in os.listdir(payload_dir) if f.endswith(".yaml"))
        # Friendly display labels for known stems; fallback to title-cased stem
        friendly_labels = {
            "jailbreak":              "Jailbreak",
            "prompt_injection":       "Prompt Injection",
            "data_leakage":           "Sensitive Data Leakage",
            "output_handling":        "Insecure Output Handling",
            "excessive_agency":       "Excessive Agency",
            "overreliance":           "Overreliance",
            "model_theft_leak":       "Model Theft / IP Leakage",
            "model_dos":              "Model Denial of Service",
            "insecure_plugin_design": "Insecure Plugin Design",
        }
        for i, filename in enumerate(yaml_files):
            stem = filename[:-5]  # strip .yaml
            label = friendly_labels.get(stem, stem.replace("_", " ").title())
            frame = spinner_frames[i % len(spinner_frames)]
            sys.stdout.write(f"\r  {Fore.CYAN}{frame}{Style.RESET_ALL}  Loading payloads..."
                             + " " * 20)
            sys.stdout.flush()
            time.sleep(0.08)
            path = os.path.join(payload_dir, filename)
            try:
                data  = yaml.safe_load(open(path, encoding="utf-8"))
                count = len(data.get("payloads", [])) if data else 0
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
                                  f"{_mask(groq_key)}  [ENABLED - GPT-OSS 120B]",
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
        ("llm-scanner --help",              "Full options reference"),
        ("llm-scanner --version",           "Show version"),
        ("llm-scanner --target URL",        "Run a security scan"),
        ("llm-scanner-config set-apikey",   "Save chatbot API key"),
        ("llm-scanner-config set-groq-key", "Save Groq key (LLM Judge)"),
        ("llm-scanner-config show",         "View saved configuration"),
        ("llm-scanner-web",                 "Open web dashboard  (port 8080)"),
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
    # ── LLM Judge (Groq secondary detection) ────────────────────────────────
    parser.add_argument(
        "--groq-key",
        required=False,
        default=os.environ.get("GROQ_API_KEY", ""),
        dest="groq_key",
        metavar="KEY",
        help=(
            "Groq API key for the LLM-as-a-Judge secondary detection layer. "
            "Get a free key at console.groq.com. "
            "Can also be set via the GROQ_API_KEY environment variable. "
            "If not provided, the judge is disabled and only heuristics run."
        ),
    )
    parser.add_argument(
        "--judge-mode",
        choices=["fallback", "always", "off"],
        default="fallback",
        dest="judge_mode",
        help=(
            "LLM judge invocation mode. "
            "'fallback' (default): judge only when heuristic finds nothing or has low confidence. "
            "'always': judge every payload (most thorough, uses more Groq quota). "
            "'off': disable judge entirely."
        ),
    )
    parser.add_argument(
        "--judge-model",
        default="openai/gpt-oss-120b",
        dest="judge_model",
        metavar="MODEL",
        help=(
            "Groq model ID to use as the AI judge. "
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
            "Minimum heuristic confidence (0.0–1.0) to skip the LLM judge. "
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
    parser.add_argument(
        "--sound",
        action="store_true",
        default=False,
        dest="sound",
        help="Enable optional audio beeps during the scan (Windows only). Default: off.",
    )
    parser.add_argument(
        "--live-map",
        action="store_true",
        default=False,
        dest="live_map",
        help=(
            "Write reports/live_status.json during the scan so attack_map.html "
            "can display a live radial attack map. Default: off."
        ),
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
            print(Fore.GREEN + f"[REPORT] JSON report saved : {json_path}")
        except Exception as exc:
            print(Fore.RED + f"[ERROR]  Failed to write JSON report: {exc}")

    if fmt in ("html", "both"):
        html_path = os.path.join(output_dir, f"{basename}.html")
        try:
            generate_html_report(scan_result, html_path)
            saved["html"] = html_path
            print(Fore.GREEN + f"[REPORT] HTML report saved : {html_path}")
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
            print(Fore.CYAN + f"  {label} Report : {path}")

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

    # Groq API key for LLM Judge (optional — judge disabled if not found)
    if not args.groq_key:
        args.groq_key = _saved.get("groq_api_key", "")
    if args.groq_key and args.judge_mode != "off":
        print(
            Fore.CYAN
            + "[INFO]  Groq API key loaded from saved config — LLM Judge enabled."
        )

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
    print(Fore.CYAN + f"[CONFIG] Sound effects   : {args.sound}")
    print(Fore.CYAN + f"[CONFIG] Live map        : {args.live_map}")
    if args.groq_key:
        print(Fore.CYAN + f"[CONFIG] LLM Judge       : {args.judge_model} | mode={args.judge_mode} | threshold={args.judge_threshold}")
    else:
        print(Fore.CYAN + "[CONFIG] LLM Judge       : disabled (no --groq-key provided)")
    print()
    # -- Live map: instruct user to open attack_map.html before scan starts --
    if args.live_map:
        map_abs = os.path.abspath("attack_map.html")
        print(Fore.CYAN + Style.BRIGHT + "[LIVE MAP] " + Fore.YELLOW
              + "Open attack_map.html in your browser to watch the live attack map.")
        print(Fore.CYAN + f"           Path: file:///{map_abs.replace(os.sep, '/')}")
        print(Fore.CYAN + "           (The page polls reports/live_status.json every second.)")
        print()
        try:
            input(Fore.GREEN + Style.BRIGHT
                  + "   Press Enter when you have the map open, to start the scan... ")
        except (EOFError, KeyboardInterrupt):
            pass
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

        # Build LLM judge if Groq key provided and judge not disabled
        llm_judge = None
        if args.groq_key and args.judge_mode != "off":
            llm_judge = GroqJudge(
                api_key=args.groq_key,
                model=args.judge_model,
                threshold=args.judge_threshold,
            )
            print(
                Fore.CYAN
                + f"[INFO]  LLM Judge ready: {args.judge_model} (mode: {args.judge_mode})"
            )

        engine = ScanEngine(
            target=target,
            payload_dir=os.path.join(os.path.dirname(__file__), "payloads"),
            categories=categories,
            rate_limit_seconds=args.rate_limit,
            sound_enabled=args.sound,
            live_map_enabled=args.live_map,
            llm_judge=llm_judge,
            judge_mode=args.judge_mode,
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
            print(Fore.CYAN + f"[BROWSER] Opening report: {html_abs}")
            webbrowser.open(f"file:///{html_abs.replace(os.sep, '/')}")

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