"""
scripts/fetch_payloads.py
Downloads real-world LLM attack prompts from open-source security research
databases and appends them to the project payload YAML files.

Sources:
    1. TrustAIRLab/JailbreakLLMs  - ~1,400 in-the-wild confirmed jailbreaks
       https://github.com/TrustAIRLab/JailbreakLLMs
    2. JailbreakBench/JBB-Behaviors - 100 standardised misuse behaviors (MIT)
       https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors

Usage:
    python scripts/fetch_payloads.py
    python scripts/fetch_payloads.py --limit 15 --dry-run
    python scripts/fetch_payloads.py --categories jailbreak,prompt_injection
"""

import argparse
import csv
import io
import os
import re
import sys
import textwrap
from typing import Dict, List, Optional

try:
    import requests
    import yaml
except ImportError:
    print("[ERROR] Run: pip install requests pyyaml")
    sys.exit(1)

# ─── Source URLs ───────────────────────────────────────────────────────────────
JAILBREAK_LLMS_URL = (
    "https://raw.githubusercontent.com/TrustAIRLab/JailbreakLLMs/"
    "main/data/jailbreak_prompts.csv"
)
JBB_BEHAVIORS_URL = (
    "https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/"
    "resolve/main/data/harmful-behaviors.csv"
)
SOURCE_JAILBREAKLLMS = "https://github.com/TrustAIRLab/JailbreakLLMs"
SOURCE_JBB = "https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors"

# ─── Category mappings ─────────────────────────────────────────────────────────
CATEGORY_FILE_MAP = {
    "jailbreak": "jailbreak.yaml",
    "prompt_injection": "prompt_injection.yaml",
    "data_leakage": "data_leakage.yaml",
    "output_handling": "output_handling.yaml",
}
CATEGORY_YAML_LABEL = {
    "jailbreak": "OWASP LLM01 variant: Jailbreak",
    "prompt_injection": "OWASP LLM01: Prompt Injection",
    "data_leakage": "OWASP LLM06: Sensitive Information Disclosure",
    "output_handling": "OWASP LLM02: Insecure Output Handling",
}
CATEGORY_DETECT_TAGS = {
    "jailbreak": ["jailbreak_confirmation", "instruction_override"],
    "prompt_injection": ["instruction_override", "system_prompt_leak"],
    "data_leakage": ["credential_leak", "pii_leak", "config_leak"],
    "output_handling": ["unsafe_html_output", "unsafe_code_output"],
}
CATEGORY_SEVERITY = {
    "jailbreak": "high",
    "prompt_injection": "high",
    "data_leakage": "critical",
    "output_handling": "high",
}

# ─── Keyword classifiers ───────────────────────────────────────────────────────
JAILBREAK_RE = re.compile(
    r"dan|evilbot|jailbreak|no restriction|without restriction|unrestricted|"
    r"roleplay|act as|pretend|persona|alter ego|do anything now|"
    r"disable safety|bypass filter|ignore safety|no rules|free mode",
    re.IGNORECASE,
)
INJECTION_RE = re.compile(
    r"ignore previous|disregard.*instruction|forget.*instruction|"
    r"system prompt|override|new instruction|developer mode|"
    r"end of system|delimiter|context reset|initial config",
    re.IGNORECASE,
)
LEAKAGE_RE = re.compile(
    r"password|credential|api.?key|secret|ssn|social security|"
    r"credit card|pii|user data|admin|database|connection string",
    re.IGNORECASE,
)
OUTPUT_RE = re.compile(
    r"<script|<iframe|alert\(|onerror=|javascript:|select \*|"
    r"drop table|rm -rf|cat /etc/passwd",
    re.IGNORECASE,
)


def _classify(prompt: str) -> Optional[str]:
    if OUTPUT_RE.search(prompt):    return "output_handling"
    if LEAKAGE_RE.search(prompt):   return "data_leakage"
    if INJECTION_RE.search(prompt): return "prompt_injection"
    if JAILBREAK_RE.search(prompt): return "jailbreak"
    return None


def _clean(prompt: str, max_chars: int = 400) -> str:
    prompt = re.sub(r"\r\n", "\n", prompt.strip())
    prompt = re.sub(r"\n{3,}", "\n\n", prompt)
    return prompt[:max_chars].rstrip() + "..." if len(prompt) > max_chars else prompt


# ─── Fetchers ──────────────────────────────────────────────────────────────────
def fetch_jailbreakllms(limit: int) -> Dict[str, List[str]]:
    print("[FETCH] Downloading JailbreakLLMs from GitHub...")
    try:
        resp = requests.get(JAILBREAK_LLMS_URL, timeout=30)
        resp.raise_for_status()
    except Exception as e:
        print(f"[WARN]  JailbreakLLMs unavailable: {e}")
        return {}

    by_cat: Dict[str, List[str]] = {c: [] for c in CATEGORY_FILE_MAP}
    seen: set = set()
    for row in csv.DictReader(io.StringIO(resp.text)):
        if row.get("jailbreak", "").strip().lower() not in ("true", "1", "yes"):
            continue
        prompt = row.get("prompt", "").strip()
        if not prompt or len(prompt) < 30:
            continue
        key = prompt[:80].lower()
        if key in seen:
            continue
        seen.add(key)
        cat = _classify(prompt)
        if cat and len(by_cat[cat]) < limit:
            by_cat[cat].append(_clean(prompt))

    print(f"[FETCH] JailbreakLLMs: {sum(len(v) for v in by_cat.values())} prompts collected")
    return by_cat


def fetch_jbb(limit: int) -> Dict[str, List[str]]:
    print("[FETCH] Downloading JBB-Behaviors from HuggingFace...")
    try:
        resp = requests.get(JBB_BEHAVIORS_URL, timeout=30)
        resp.raise_for_status()
    except Exception as e:
        print(f"[WARN]  JBB-Behaviors unavailable: {e}")
        return {}

    by_cat: Dict[str, List[str]] = {c: [] for c in CATEGORY_FILE_MAP}
    seen: set = set()
    for row in csv.DictReader(io.StringIO(resp.text)):
        prompt = row.get("Goal", row.get("goal", row.get("Behavior", ""))).strip()
        if not prompt or len(prompt) < 30:
            continue
        key = prompt[:80].lower()
        if key in seen:
            continue
        seen.add(key)
        cat = _classify(prompt) or "jailbreak"
        if len(by_cat[cat]) < limit:
            by_cat[cat].append(_clean(prompt))

    print(f"[FETCH] JBB-Behaviors: {sum(len(v) for v in by_cat.values())} prompts collected")
    return by_cat


# ─── YAML helpers ──────────────────────────────────────────────────────────────
def _next_id(category: str, data: dict) -> int:
    pfx = {"jailbreak": "JB", "prompt_injection": "PI",
           "data_leakage": "DL", "output_handling": "OH"}.get(category, "XX")
    ids = []
    for p in data.get("payloads", []):
        pid = p.get("id", "")
        if pid.startswith(pfx + "-"):
            try: ids.append(int(pid.split("-")[1]))
            except (ValueError, IndexError): pass
    return max(ids, default=0) + 1


def _build_entries(category, prompts, source, start_id) -> List[dict]:
    pfx = {"jailbreak": "JB", "prompt_injection": "PI",
           "data_leakage": "DL", "output_handling": "OH"}.get(category, "XX")
    entries = []
    for i, prompt in enumerate(prompts):
        name = textwrap.shorten(prompt.split(".")[0].split("\n")[0].strip(), 60, placeholder="...")
        entries.append({
            "id": f"{pfx}-{start_id + i:03d}",
            "name": name,
            "prompt": prompt,
            "source": source,
            "detects": CATEGORY_DETECT_TAGS.get(category, []),
            "severity": CATEGORY_SEVERITY.get(category, "high"),
        })
    return entries


def _load_yaml(path: str) -> dict:
    if not os.path.exists(path):
        return {"category": "", "description": "", "payloads": []}
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    data.setdefault("payloads", [])
    return data


def _save_yaml(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True,
                  sort_keys=False, width=120)


# ─── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch LLM attack payloads from open-source databases.")
    parser.add_argument("--limit", type=int, default=20, help="Max prompts per category. Default: 20")
    parser.add_argument("--categories", default="jailbreak,prompt_injection",
                        help="Comma-separated categories. Default: jailbreak,prompt_injection")
    parser.add_argument("--dry-run", action="store_true", help="Print YAML without writing files.")
    parser.add_argument("--payloads-dir",
                        default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "payloads"))
    args = parser.parse_args()

    cats = [c.strip().lower() for c in args.categories.split(",")]
    bad  = [c for c in cats if c not in CATEGORY_FILE_MAP]
    if bad:
        print(f"[ERROR] Unknown categories: {bad}. Valid: {list(CATEGORY_FILE_MAP)}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("  LLM Scanner - Payload Fetcher")
    print("  Sources: JailbreakLLMs (TrustAIRLab) + JBB-Behaviors (MIT)")
    print("=" * 60 + "\n")

    src1 = fetch_jailbreakllms(args.limit)
    src2 = fetch_jbb(args.limit)

    # Merge + deduplicate
    merged: Dict[str, List[str]] = {}
    for cat in CATEGORY_FILE_MAP:
        combined = src1.get(cat, []) + src2.get(cat, [])
        seen: set = set()
        merged[cat] = []
        for p in combined:
            key = p[:80].lower()
            if key not in seen:
                seen.add(key)
                merged[cat].append(p)
        merged[cat] = merged[cat][: args.limit]

    print("\nPrompts per category:")
    for cat, ps in merged.items():
        print(f"  {cat:20s}: {len(ps):3d}")
    print()

    for category in cats:
        prompts  = merged.get(category, [])
        filepath = os.path.join(args.payloads_dir, CATEGORY_FILE_MAP[category])

        if not prompts:
            print(f"[SKIP]  No prompts collected for '{category}'")
            continue

        if args.dry_run:
            existing = _load_yaml(filepath)
            entries  = _build_entries(category, prompts, SOURCE_JAILBREAKLLMS, _next_id(category, existing))
            print(f"\n{'='*60}\nDRY RUN - {CATEGORY_FILE_MAP[category]}\n{'='*60}")
            print(yaml.dump({"payloads": entries}, default_flow_style=False, allow_unicode=True,
                            sort_keys=False, width=120))
            continue

        existing = _load_yaml(filepath)
        if not existing.get("category"):
            existing["category"] = CATEGORY_YAML_LABEL.get(category, category)

        existing_keys = {p.get("prompt", "")[:80].lower() for p in existing["payloads"]}
        new_prompts   = [p for p in prompts if p[:80].lower() not in existing_keys]

        if not new_prompts:
            print(f"[SKIP]  '{CATEGORY_FILE_MAP[category]}' - all prompts already present")
            continue

        entries = _build_entries(category, new_prompts, SOURCE_JAILBREAKLLMS, _next_id(category, existing))
        existing["payloads"].extend(entries)
        _save_yaml(filepath, existing)
        print(f"[OK]    '{CATEGORY_FILE_MAP[category]}' - added {len(entries)} payloads "
              f"(total now: {len(existing['payloads'])})")

    print("\nDone! Run your scan to test new payloads:")
    print("  python cli.py --target http://localhost:5000 --apikey demo123\n")


if __name__ == "__main__":
    main()
