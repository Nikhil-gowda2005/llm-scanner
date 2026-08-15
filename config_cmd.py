"""
config_cmd.py
=============
CLI command for managing llm-scanner configuration.
Saves API keys and settings to ~/.llm-scanner/config.json
so you never have to pass --groq-key or --apikey on every scan.

Commands:
    llm-scanner-config set-groq-key  <key>   Save your Groq API key (LLM Judge)
    llm-scanner-config set-apikey    <key>   Save your target chatbot API key
    llm-scanner-config show                  Show current saved config
    llm-scanner-config clear                 Remove all saved config

Examples:
    llm-scanner-config set-groq-key gsk_abc123
    llm-scanner-config set-apikey   demo123
    llm-scanner-config show
"""

import argparse
import json
import os
import sys

# Config is stored here so it persists across terminal sessions
CONFIG_DIR  = os.path.join(os.path.expanduser("~"), ".llm-scanner")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _load_config() -> dict:
    """Loads the saved config. Returns empty dict if file doesn't exist."""
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_config(cfg: dict) -> None:
    """Saves the config dict to disk, creating the directory if needed."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def _mask(key: str) -> str:
    """Masks a key for display: shows first 6 chars + stars."""
    if not key:
        return "(not set)"
    if len(key) <= 8:
        return "****"
    return key[:6] + "****" + key[-2:]


# ─── Commands ─────────────────────────────────────────────────────────────────

def cmd_set_groq_key(key: str) -> None:
    """Saves the Groq API key used by the LLM Judge."""
    key = key.strip()
    if not key:
        print("[ERROR] Key cannot be empty.")
        sys.exit(1)
    cfg = _load_config()
    cfg["groq_api_key"] = key
    _save_config(cfg)
    print(f"[OK]  Groq API key saved: {_mask(key)}")
    print(f"      Stored in: {CONFIG_FILE}")
    print()
    print("The LLM Judge (openai/gpt-oss-120b) is now enabled automatically.")
    print("Run your scan without --groq-key:")
    print("  llm-scanner --target http://localhost:5000 --apikey demo123")


def cmd_set_apikey(key: str) -> None:
    """Saves the target chatbot API key."""
    key = key.strip()
    if not key:
        print("[ERROR] Key cannot be empty.")
        sys.exit(1)
    cfg = _load_config()
    cfg["llm_scanner_api_key"] = key
    _save_config(cfg)
    print(f"[OK]  Chatbot API key saved: {_mask(key)}")
    print(f"      Stored in: {CONFIG_FILE}")
    print()
    print("Run your scan without --apikey:")
    print("  llm-scanner --target http://localhost:5000")


def cmd_show() -> None:
    """Shows the current saved configuration (keys are masked)."""
    cfg = _load_config()
    groq_key    = cfg.get("groq_api_key", "")
    scanner_key = cfg.get("llm_scanner_api_key", "")

    print()
    print("  LLM Scanner - Saved Configuration")
    print("  " + "-" * 40)
    print(f"  Config file    : {CONFIG_FILE}")
    print(f"  Groq API key   : {_mask(groq_key)}")
    print(f"  Chatbot API key: {_mask(scanner_key)}")
    print()

    if not groq_key:
        print("  [TIP] Add your Groq key to enable the LLM Judge:")
        print("        llm-scanner-config set-groq-key gsk_your_key_here")
        print("        Get a free key at: https://console.groq.com")
    else:
        print("  [OK] LLM Judge (openai/gpt-oss-120b) is enabled.")

    print()


def cmd_clear() -> None:
    """Removes all saved configuration."""
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)
        print(f"[OK]  Config cleared. Removed: {CONFIG_FILE}")
    else:
        print("[INFO] No saved config found. Nothing to clear.")


# ─── Config loader for cli.py ─────────────────────────────────────────────────

def load_saved_config() -> dict:
    """
    Public helper used by cli.py to read saved API keys.

    Priority order for each key:
        1. CLI flag (--groq-key / --apikey)
        2. Environment variable (GROQ_API_KEY / LLM_SCANNER_API_KEY)
        3. Saved config file (~/.llm-scanner/config.json)  ← this function

    Returns:
        dict with keys: "groq_api_key", "llm_scanner_api_key"
    """
    return _load_config()


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="llm-scanner-config",
        description="Manage llm-scanner API keys and settings.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  llm-scanner-config set-groq-key gsk_abc123xyz\n"
            "  llm-scanner-config set-apikey   demo123\n"
            "  llm-scanner-config show\n"
            "  llm-scanner-config clear\n"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    # set-groq-key
    p_groq = subparsers.add_parser(
        "set-groq-key",
        help="Save your Groq API key for the LLM Judge (openai/gpt-oss-120b).",
    )
    p_groq.add_argument("key", help="Your Groq API key (starts with gsk_...)")

    # set-apikey
    p_api = subparsers.add_parser(
        "set-apikey",
        help="Save your target chatbot API key.",
    )
    p_api.add_argument("key", help="Your chatbot API key.")

    # show
    subparsers.add_parser(
        "show",
        help="Show current saved configuration (keys are masked).",
    )

    # clear
    subparsers.add_parser(
        "clear",
        help="Remove all saved configuration.",
    )

    args = parser.parse_args()

    if args.command == "set-groq-key":
        cmd_set_groq_key(args.key)
    elif args.command == "set-apikey":
        cmd_set_apikey(args.key)
    elif args.command == "show":
        cmd_show()
    elif args.command == "clear":
        cmd_clear()


if __name__ == "__main__":
    main()
