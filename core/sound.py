"""
core/sound.py

Optional audio-feedback module for the LLM Security Scanner.

Provides three beep patterns triggered during a live scan:

    play_safe_sound()       -- short high-pitched blip  (no finding)
    play_vulnerable_sound() -- two quick lower beeps    (finding, non-critical)
    play_critical_sound()   -- three distinct beeps     (CRITICAL severity)

Design:
* Uses winsound from the Python standard library (no extra install needed).
* winsound is Windows-only. The import is wrapped in try/except so the
  module loads silently on Linux/macOS or environments without sound hardware.
* Every public function is wrapped in its own try/except and will NEVER raise,
  print errors, or interrupt the calling scan loop under any circumstances.
* SOUND_ENABLED (default True) lets callers disable all audio globally:
      import core.sound; core.sound.SOUND_ENABLED = False
  ScanEngine sets this flag automatically via its sound_enabled constructor arg.
"""

# -- Try to import winsound (Windows built-in) ---------------------------------
try:
    import winsound as _winsound
    _WINSOUND_AVAILABLE = True
except ImportError:
    _winsound = None
    _WINSOUND_AVAILABLE = False

# -- Module-level kill-switch --------------------------------------------------
# Set to False to silence all beeps globally without modifying call sites.
SOUND_ENABLED = True


# ------------------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------------------

def play_safe_sound():
    """
    Play a short, soft, high-pitched beep when no vulnerability is detected.
    Tone: 1000 Hz for 100 ms -- a quick, unobtrusive blip.
    Guaranteed to be a no-op (never raises) when sound is disabled/unavailable.
    """
    if not SOUND_ENABLED:
        return
    if not _WINSOUND_AVAILABLE:
        return
    try:
        _winsound.Beep(1000, 100)
    except Exception:
        pass


def play_vulnerable_sound():
    """
    Play two quick lower-pitched beeps when a vulnerability is found
    (non-critical severity).
    Tone: 600 Hz x 150 ms, repeated twice.
    Guaranteed to be a no-op (never raises) when sound is disabled/unavailable.
    """
    if not SOUND_ENABLED:
        return
    if not _WINSOUND_AVAILABLE:
        return
    try:
        _winsound.Beep(600, 150)
        _winsound.Beep(600, 150)
    except Exception:
        pass


def play_critical_sound():
    """
    Play a three-beep pattern when a CRITICAL severity finding is detected.
    Tone: 500 Hz x 100 ms, repeated three times.
    Guaranteed to be a no-op (never raises) when sound is disabled/unavailable.
    """
    if not SOUND_ENABLED:
        return
    if not _WINSOUND_AVAILABLE:
        return
    try:
        _winsound.Beep(500, 100)
        _winsound.Beep(500, 100)
        _winsound.Beep(500, 100)
    except Exception:
        pass
