"""
core/live_status.py

Light-weight helper that writes a "current scan state" JSON file to disk
while a scan is in progress.  The attack_map.html page polls this file
every second to render the live attack map.

Public API
----------
init_status(categories, target_url)  -> dict
    Build and return a fresh status dict (does NOT write it).

write_status(status_dict, path)
    Overwrite the JSON file at `path` with `status_dict`.
    Silently ignores ALL errors -- must never raise.

Design constraints
------------------
* This module has zero mandatory side-effects on import.
* write_status() is wrapped in try/except and will never raise, print, or
  interrupt the calling scan loop under any circumstances.
* If live_map_enabled is False in ScanEngine, none of these functions are
  called at all -- zero overhead on normal scans.
"""

import json
import os
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def init_status(categories: list, target_url: str) -> dict:
    """
    Build and return the initial status dict for a new scan.

    Args:
        categories (list): Ordered list of unique category name strings
                           as they appear in the payload YAML files.
        target_url (str):  Full target URL (base_url + endpoint).

    Returns:
        dict: Initial status dict.  Shape::

            {
                "target_url": "http://...",
                "started_at": "<ISO-8601 UTC>",
                "categories": {
                    "<name>": {
                        "state":    "pending",   # pending|testing|safe|vulnerable
                        "findings": 0,
                        "tested":   0,
                        "total":    0
                    },
                    ...
                },
                "overall_progress": {"tested": 0, "total": 0},
                "finished": false
            }
    """
    category_entries = {}
    for cat in categories:
        category_entries[cat] = {
            "state":    "pending",
            "findings": 0,
            "tested":   0,
            "total":    0,
        }

    return {
        "target_url":  target_url,
        "started_at":  datetime.now(tz=timezone.utc).isoformat(),
        "categories":  category_entries,
        "overall_progress": {"tested": 0, "total": 0},
        "finished":    False,
    }


def write_status(status_dict: dict, path: str = "reports/live_status.json") -> None:
    """
    Atomically overwrite the live-status JSON file.

    Writes to a temporary sibling file first then renames, so the reader
    (attack_map.html) never sees a half-written file.  Falls back to a
    direct write if the rename is not available (unlikely on Windows).

    Args:
        status_dict (dict): The current status to persist.
        path (str):         Destination file path. Parent directory must
                            already exist (the engine ensures this via
                            the reports/ directory creation).

    This function is guaranteed to be a no-op on any error.
    """
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        tmp_path = path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(status_dict, fh, indent=2)
        os.replace(tmp_path, path)
    except Exception:
        pass
