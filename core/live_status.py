"""
core/live_status.py

Tiny helper module for tracking and persisting the live progress of a
running scan to a JSON file (reports/live_status.json), which the web
dashboard polls via GET /api/live-status to drive the exposure-grid UI.

Two functions are used by web_app.py:

    init_status(category_order, target_url) -> dict
        Build a fresh status dict, one entry per category, all zeroed out.

    write_status(status, path) -> None
        Persist the status dict to disk as JSON (atomically where possible).
"""

import json
import os
import tempfile
import threading
from datetime import datetime, timezone

# Guards concurrent writes from the scan thread.
_write_lock = threading.Lock()


def init_status(category_order, target_url):
    """
    Build the initial live-status structure for a new scan.

    category_order: list of category keys in the order they'll be tested,
                     e.g. ["prompt_injection", "jailbreak", ...]
    target_url:      full target URL + endpoint, e.g. "http://host/chat"

    Returns a dict shaped like:
        {
          "target_url": "...",
          "started_at": "2026-08-19T12:00:00Z",
          "categories": {
              "prompt_injection": {
                  "total": 0, "tested": 0, "findings": 0,
                  "safe_count": 0, "state": "pending"
              },
              ...
          },
          "overall_progress": {"tested": 0, "total": 0},
          "finished": False,
        }

    Category "state" is one of: "pending" | "testing" | "safe" | "vulnerable"
    """
    categories = {}
    for cat in category_order:
        if cat in categories:
            continue
        categories[cat] = {
            "total": 0,
            "tested": 0,
            "findings": 0,
            "safe_count": 0,
            "state": "pending",
        }

    return {
        "target_url": target_url,
        "started_at": datetime.now(tz=timezone.utc).isoformat(),
        "categories": categories,
        "overall_progress": {"tested": 0, "total": 0},
        "finished": False,
    }


def write_status(status, path):
    """
    Persist `status` to `path` as JSON.

    Writes to a temp file in the same directory and then replaces the
    target file, so a concurrent GET from the web dashboard never reads a
    half-written / truncated file mid-scan.
    """
    with _write_lock:
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".live_status_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(status, fh, indent=2)
            os.replace(tmp_path, path)
        except Exception:
            # Best-effort cleanup if the atomic replace failed partway through.
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
            raise


def read_status(path):
    """
    Convenience helper (not currently called by web_app.py, but handy for
    debugging / CLI use): read back the live-status JSON, or None if the
    file doesn't exist yet.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
