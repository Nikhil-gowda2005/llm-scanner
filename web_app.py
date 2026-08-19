"""
Web Dashboard for LLM Security Scanner.

Run with:
    python web_app.py

Then open http://localhost:8080 in your browser.
Enter target URL + API key, click Run Scan, watch live results.
"""

import json
import os
import queue
import sys
import threading
import uuid
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request, send_from_directory

# Make sure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import ScanEngine
from core.target import Target
from core import live_status as _ls
from reporters.json_report import generate_json_report
from reporters.html_report import generate_html_report

app = Flask(__name__)

_scan_store: dict = {}
_store_lock = threading.Lock()

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
PAYLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payloads")

# ─────────────────────────────────────────────────────────────────────────────
# Dashboard HTML (inline — zero external files needed)
# ─────────────────────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>AI-Xray — AI/LLM Application Security Scanner</title>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">

<script src="https://unpkg.com/lucide@latest"></script>

<style>
/* ============================================================
   AI-Xray — "light box" design system
   A radiograph is read on a lit panel: bright clinical exterior,
   dark backlit film where the actual exposure (the scan) happens.
   That contrast is the whole idea — quiet everywhere, and then a
   single glowing "plate" where results are read off the film.
   ============================================================ */
:root{
  /* exterior — light box room */
  --paper:#f2f4f7;--panel:#ffffff;--sunken:#eaedf2;
  --ink:#12161d;--ink-soft:#565f6c;--ink-faint:#939ca8;
  --line:#dde1e8;--line-soft:#e8ebf0;
  --accent:#0f6e8c;--accent-hover:#0b5a73;--accent-soft:#e6f2f5;

  /* film / backlit panel — where the scan runs */
  --film:#0b0f16;--film-panel:#10161f;--film-line:#212b38;
  --film-text:#dbe3ec;--film-text-dim:#7e8ba0;
  --glow:#5eead4;--glow-dim:rgba(94,234,212,.18);

  /* severity, tuned to read on both paper and film */
  --high:#c0392b;--high-bg:#fbeae7;--high-glow:#ff7a68;
  --medium:#a8641a;--medium-bg:#fbf0dc;--medium-glow:#ffc06b;
  --low:#1f7a5c;--low-bg:#e6f5ee;--low-glow:#6bf0c2;

  --radius-sm:6px;--radius-md:10px;--radius-lg:14px;
  --shadow:0 1px 2px rgba(16,20,29,.04),0 10px 30px -12px rgba(16,20,29,.12);
  --ease:cubic-bezier(.4,0,.2,1);
}
@media (prefers-reduced-motion: reduce){
  *{animation-duration:.001ms !important;animation-iteration-count:1 !important;transition-duration:.001ms !important;}
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;font-size:14px;line-height:1.6;
  background:var(--paper);color:var(--ink);min-height:100vh;
  -webkit-font-smoothing:antialiased}
h1,h2,h3,h4{font-family:'Space Grotesk',sans-serif}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}

/* ── Navbar ─────────────────────────────────────────────────── */
.nav{background:var(--panel);border-bottom:1px solid var(--line);
  padding:0 28px;height:64px;display:flex;align-items:center;justify-content:space-between;
  position:sticky;top:0;z-index:50}
.brand{display:flex;align-items:center;gap:12px}
.brand-mark{width:38px;height:38px;flex-shrink:0;border-radius:var(--radius-sm);
  background:var(--film);color:var(--glow);display:flex;align-items:center;justify-content:center;
  position:relative;overflow:hidden;box-shadow:inset 0 0 0 1px var(--film-line)}
.brand-mark svg{position:relative;z-index:1}
.brand-mark::after{content:'';position:absolute;left:-100%;top:0;bottom:0;width:60%;
  background:linear-gradient(90deg,transparent,rgba(94,234,212,.35),transparent);
  animation:sweep 3.6s ease-in-out infinite}
@keyframes sweep{0%{left:-60%}55%{left:130%}100%{left:130%}}
.brand-text{display:flex;flex-direction:column;line-height:1.15}
.brand-name{font-family:'Space Grotesk',sans-serif;font-size:1.22rem;font-weight:700;letter-spacing:-0.01em;color:var(--ink)}
.brand-sub{font-family:'IBM Plex Mono',monospace;font-size:.66rem;font-weight:500;color:var(--ink-faint);
  letter-spacing:.06em;text-transform:uppercase}

/* ── Layout ─────────────────────────────────────────────────── */
.main{max-width:980px;margin:0 auto;padding:44px 20px 64px}

/* ── Hero ───────────────────────────────────────────────────── */
.hero{margin-bottom:32px;padding-bottom:28px;border-bottom:1px solid var(--line-soft)}
.hero-eyebrow{font-family:'IBM Plex Mono',monospace;font-size:.7rem;font-weight:500;letter-spacing:.12em;
  text-transform:uppercase;color:var(--accent);margin-bottom:10px;display:flex;align-items:center;gap:8px}
.hero-eyebrow::before{content:'';width:7px;height:7px;border-radius:50%;background:var(--accent)}
.hero-title{font-size:2.5rem;font-weight:700;letter-spacing:-0.02em;color:var(--ink);line-height:1.05}
.hero-desc{margin-top:12px;font-size:.96rem;color:var(--ink-soft);max-width:600px}

/* ── Cards ──────────────────────────────────────────────────── */
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius-lg);
  box-shadow:var(--shadow);padding:28px;margin-bottom:20px}
.card-label{font-family:'IBM Plex Mono',monospace;text-transform:uppercase;font-size:.66rem;font-weight:600;
  letter-spacing:.1em;color:var(--accent);margin-bottom:8px}
.card-title{font-size:1.3rem;font-weight:700;letter-spacing:-0.01em;margin-bottom:22px;color:var(--ink)}
.section-title{font-size:1.02rem;font-weight:700;margin-bottom:16px;color:var(--ink)}
.section-subtitle{font-size:.86rem;font-weight:700;margin:24px 0 12px;color:var(--ink);
  text-transform:uppercase;letter-spacing:.04em}

/* ── Form fields ────────────────────────────────────────────── */
.form-group{display:flex;flex-direction:column;gap:16px;margin-bottom:8px}
.input-row{display:grid;grid-template-columns:140px 1fr;align-items:center;gap:16px}
.input-label{font-size:.85rem;font-weight:600;color:var(--ink)}
.input-wrapper{position:relative;display:flex;align-items:center}
.input-wrapper>i{position:absolute;left:14px;color:var(--ink-faint);pointer-events:none}
.input-field{width:100%;height:42px;padding:0 14px 0 42px;border:1px solid var(--line);
  border-radius:var(--radius-md);font-size:.87rem;font-family:'Inter',sans-serif;color:var(--ink);
  background:var(--panel);outline:none;transition:border-color .15s var(--ease),box-shadow .15s var(--ease)}
.input-field.has-toggle{padding-right:42px}
.input-field:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.input-field::placeholder{color:var(--ink-faint)}
.pw-toggle{position:absolute;right:6px;width:30px;height:30px;border:none;background:transparent;
  color:var(--ink-faint);cursor:pointer;border-radius:var(--radius-sm);display:flex;align-items:center;
  justify-content:center;transition:color .15s,background .15s}
.pw-toggle:hover{color:var(--ink);background:var(--sunken)}

.validation-msg{display:none;font-size:.78rem;color:var(--medium);margin:10px 0 4px;padding-left:2px;
  font-weight:500}

/* ── Category pills ─────────────────────────────────────────── */
.security-areas-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.security-areas-title{font-size:.85rem;font-weight:600;color:var(--ink)}
.counter-badge{font-family:'IBM Plex Mono',monospace;font-size:.72rem;font-weight:600;color:var(--ink-soft);
  background:var(--sunken);padding:3px 10px;border-radius:20px;border:1px solid var(--line)}
.pill-grid{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:26px;transition:opacity .2s}
.pill-grid.locked{opacity:.5;pointer-events:none}
.pill-btn{display:inline-flex;align-items:center;gap:7px;padding:7px 14px;font-size:.8rem;
  font-weight:500;color:var(--ink-soft);background:var(--panel);border:1px solid var(--line);
  border-radius:20px;cursor:pointer;user-select:none;transition:all .15s var(--ease);font-family:'Inter',sans-serif}
.pill-btn:hover{border-color:#c3c9d2}
.pill-btn.active{background:var(--accent-soft);border-color:rgba(15,110,140,.35);color:var(--accent);font-weight:600}
.pill-btn .pill-dot{width:6px;height:6px;border-radius:50%;background:var(--ink-faint);transition:background .15s}
.pill-btn.active .pill-dot{background:var(--accent)}

/* ── Buttons ────────────────────────────────────────────────── */
.btn-submit{width:100%;height:46px;background:var(--ink);color:#fff;border:none;
  border-radius:var(--radius-md);font-size:.9rem;font-weight:600;font-family:'Space Grotesk',sans-serif;
  cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px;
  transition:background .15s var(--ease),transform .1s var(--ease)}
.btn-submit:hover{background:var(--accent-hover)}
.btn-submit:active{transform:scale(.99)}
.btn-submit:disabled{background:#c7cbd3;color:#fff;cursor:not-allowed}
.spin{animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.btn-row{display:flex;gap:10px}
.btn-stop{flex:0 0 auto;height:46px;padding:0 22px;background:var(--sunken);color:var(--ink-faint);
  border:1px solid var(--line);border-radius:var(--radius-md);font-size:.9rem;font-weight:600;
  font-family:'Space Grotesk',sans-serif;cursor:not-allowed;display:flex;align-items:center;
  justify-content:center;gap:8px;transition:background .15s,border-color .15s,color .15s;opacity:.5}
.btn-stop.active{background:var(--high-bg);color:var(--high);border-color:rgba(192,57,43,.3);
  cursor:pointer;opacity:1}
.btn-stop.active:hover{background:#f5c6c0;border-color:var(--high)}
.btn-stop.stopping{opacity:.7;cursor:not-allowed}

/* ── Live panel — the "film" ───────────────────────────────────
   Once a scan starts, the interface drops into the backlit panel:
   dark, glowing, instrument-readout typography. This is the one
   place the design spends its accent color. */
.film{display:none;margin-top:22px;background:var(--film);border-radius:var(--radius-md);
  padding:20px 22px;position:relative;overflow:hidden;border:1px solid var(--film-line)}
.film::before{content:'';position:absolute;left:0;right:0;top:0;height:2px;
  background:linear-gradient(90deg,transparent,var(--glow),transparent);
  opacity:.7;animation:filmsweep 2.2s linear infinite}
@keyframes filmsweep{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}
.live-row{display:flex;align-items:center;justify-content:space-between;padding:6px 0;font-size:.82rem}
.live-k{font-family:'IBM Plex Mono',monospace;font-size:.7rem;letter-spacing:.06em;text-transform:uppercase;
  color:var(--film-text-dim)}
.live-v{color:var(--film-text);font-weight:600;font-family:'IBM Plex Mono',monospace;font-size:.8rem}
.live-v.glow{color:var(--glow)}
.progress-track{height:5px;background:var(--film-line);border-radius:99px;overflow:hidden;margin-top:12px;
  position:relative}
.progress-fill{height:100%;width:0%;background:var(--glow);border-radius:99px;
  transition:width .35s var(--ease);box-shadow:0 0 10px var(--glow)}

/* ── Console ────────────────────────────────────────────────── */
.console-box{display:none;background:var(--film-panel);color:var(--film-text-dim);
  border-radius:var(--radius-md);border:1px solid var(--film-line);
  padding:14px 16px;font-family:'IBM Plex Mono',monospace;font-size:.76rem;line-height:1.7;
  max-height:170px;overflow-y:auto;margin-top:14px}
.console-line{display:flex;gap:10px}
.console-time{color:#4a5568;flex-shrink:0}
.c-ok{color:var(--glow)}
.c-err{color:var(--high-glow)}
.c-warn{color:var(--medium-glow)}

/* ── Reports ────────────────────────────────────────────────── */
.reports-section{margin-top:20px}
.reports-list{display:flex;flex-direction:column;gap:12px}
.report-card{display:flex;align-items:center;justify-content:space-between;padding:13px 15px;
  border:1px solid var(--line);border-radius:var(--radius-md);background:var(--sunken)}
.report-info{display:flex;align-items:center;gap:12px}
.report-icon-box{width:34px;height:34px;border-radius:var(--radius-sm);background:var(--accent-soft);
  color:var(--accent);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.report-meta h4{font-size:.86rem;font-weight:600;color:var(--ink)}
.report-meta span{font-size:.73rem;color:var(--ink-faint);font-family:'IBM Plex Mono',monospace}
.download-btn{color:var(--ink-soft);background:var(--panel);border:1px solid var(--line);
  cursor:pointer;padding:7px;border-radius:var(--radius-sm);transition:all .15s;display:inline-flex;
  text-decoration:none}
.download-btn:hover:not(.disabled){color:var(--accent);border-color:rgba(15,110,140,.4);background:var(--accent-soft)}
.download-btn.disabled{opacity:.4;cursor:not-allowed;pointer-events:none}
.report-actions{display:flex;align-items:center;gap:8px}
.open-btn{color:var(--ink-soft);background:var(--panel);border:1px solid var(--line);
  cursor:pointer;padding:7px 11px;border-radius:var(--radius-sm);transition:all .15s;display:inline-flex;
  align-items:center;gap:6px;text-decoration:none;font-size:.75rem;font-weight:600;font-family:'IBM Plex Mono',monospace}
.open-btn:hover:not(.disabled){color:var(--accent);border-color:rgba(15,110,140,.4);background:var(--accent-soft)}
.open-btn.disabled{opacity:.4;cursor:not-allowed;pointer-events:none}

/* ── Results ────────────────────────────────────────────────── */
.summary-cards{display:grid;grid-template-columns:repeat(6,1fr);gap:10px}
.stat{background:var(--sunken);border:1px solid var(--line);border-radius:var(--radius-md);
  padding:14px 10px;text-align:center}
.stat-val{font-family:'Space Grotesk',sans-serif;font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;color:var(--ink)}
.stat-lbl{font-family:'IBM Plex Mono',monospace;font-size:.63rem;font-weight:500;text-transform:uppercase;
  letter-spacing:.06em;color:var(--ink-faint);margin-top:3px}
.stat-high .stat-val{color:var(--high)}
.stat-med .stat-val{color:var(--medium)}
.stat-low .stat-val{color:var(--low)}

/* Findings — read like plates pulled off the film, dark card
   with a soft glow at the edge in the severity color. */
.finding-card{border:1px solid var(--film-line);border-left:3px solid var(--film-line);
  border-radius:var(--radius-sm);padding:12px 14px;margin-bottom:10px;
  background:var(--film-panel);position:relative;overflow:hidden}
.finding-card.sev-high,.finding-card.sev-critical{border-left-color:var(--high-glow);
  box-shadow:inset 40px 0 40px -36px rgba(255,122,104,.18)}
.finding-card.sev-medium{border-left-color:var(--medium-glow);
  box-shadow:inset 40px 0 40px -36px rgba(255,192,107,.16)}
.finding-card.sev-low{border-left-color:var(--low-glow);
  box-shadow:inset 40px 0 40px -36px rgba(107,240,194,.12)}
.finding-top{display:flex;align-items:center;justify-content:space-between;gap:10px}
.finding-name{font-size:.86rem;font-weight:600;color:var(--film-text)}
.sev-badge{font-family:'IBM Plex Mono',monospace;font-size:.62rem;font-weight:600;text-transform:uppercase;
  letter-spacing:.06em;padding:2px 8px;border-radius:4px}
.sev-badge.sev-high,.sev-badge.sev-critical{color:var(--high-glow);background:rgba(255,122,104,.12)}
.sev-badge.sev-medium{color:var(--medium-glow);background:rgba(255,192,107,.12)}
.sev-badge.sev-low{color:var(--low-glow);background:rgba(107,240,194,.12)}
.finding-meta{display:flex;gap:16px;font-size:.73rem;color:var(--film-text-dim);margin-top:6px;
  font-family:'IBM Plex Mono',monospace}
.finding-evidence{margin-top:8px;font-size:.78rem;color:var(--film-text-dim);background:var(--film);
  border:1px solid var(--film-line);border-radius:6px;padding:8px 10px;font-family:'IBM Plex Mono',monospace}
.ev-label{display:block;font-family:'IBM Plex Mono',monospace;font-size:.63rem;font-weight:600;
  text-transform:uppercase;letter-spacing:.08em;color:var(--film-text-dim);margin-bottom:3px;opacity:.7}
.no-findings{display:flex;align-items:center;gap:8px;padding:18px;color:var(--low);font-size:.86rem;
  font-weight:600;background:var(--low-bg);border-radius:var(--radius-md);border:1px solid rgba(31,122,92,.18)}

/* ── Footer ─────────────────────────────────────────────────── */
.footer{text-align:center;padding:24px 0;font-size:.72rem;color:var(--ink-faint);
  font-family:'IBM Plex Mono',monospace;letter-spacing:.03em;
  border-top:1px solid var(--line);background:var(--panel)}

@media(max-width:768px){
  .hero-title{font-size:1.9rem}
  .input-row{grid-template-columns:1fr;gap:6px}
  .summary-cards{grid-template-columns:repeat(3,1fr)}
}
</style>
</head>
<body>

<nav class="nav">
  <div class="brand">
    <div class="brand-mark">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 3 7v6c0 5 4 8.5 9 9 5-.5 9-4 9-9V7z"/><path d="M9 12l2 2 4-4"/></svg>
    </div>
    <div class="brand-text">
      <span class="brand-name">AI-Xray</span>
      <span class="brand-sub">LLM Application Security Scanner</span>
    </div>
  </div>
</nav>

<div class="main">

  <div class="hero">
    <div class="hero-eyebrow">Security Assessment</div>
    <h1 class="hero-title">See through your LLM endpoint.</h1>
    <p class="hero-desc">Run an OWASP LLM Top 10 assessment against a live endpoint and read the results off the plate — structured findings, risk-scored and ready to export.</p>
  </div>

  <div class="card">
    <div class="card-label">Configuration</div>
    <h1 class="card-title">Scan your LLM endpoint</h1>

    <form id="scannerForm">
      <div class="form-group">

        <div class="input-row">
          <label class="input-label" for="targetUrl">Target URL</label>
          <div class="input-wrapper">
            <i data-lucide="link" size="16"></i>
            <input type="text" id="targetUrl" class="input-field" placeholder="http://localhost:5000" value="http://localhost:5000"/>
          </div>
        </div>

        <div class="input-row">
          <label class="input-label" for="apiKey">API Key</label>
          <div class="input-wrapper">
            <i data-lucide="key" size="16"></i>
            <input type="password" id="apiKey" class="input-field has-toggle" placeholder="Enter API key or bearer token" value="demo123"/>
            <button type="button" class="pw-toggle" id="pwToggle" aria-label="Show API key" onclick="togglePwVisibility()">
              <i data-lucide="eye" size="16" id="pwToggleIcon"></i>
            </button>
          </div>
        </div>

        <div class="input-row">
          <label class="input-label" for="endpoint">Endpoint</label>
          <div class="input-wrapper">
            <i data-lucide="terminal" size="16"></i>
            <input type="text" id="endpoint" class="input-field" placeholder="/chat" value="/chat"/>
          </div>
        </div>

      </div>

      <div class="validation-msg" id="validationMsg" role="alert">Enter a target URL and API key to continue.</div>

      <div class="security-areas-header">
        <span class="security-areas-title">Select the security areas to assess</span>
        <span class="counter-badge" id="selectedCount">9/9 selected</span>
      </div>

      <div class="pill-grid" id="pillGrid">
        <button type="button" class="pill-btn active" data-value="prompt_injection" onclick="togglePill(this)">
          <span class="pill-dot"></span> Prompt Injection
        </button>
        <button type="button" class="pill-btn active" data-value="jailbreak" onclick="togglePill(this)">
          <span class="pill-dot"></span> Jailbreak
        </button>
        <button type="button" class="pill-btn active" data-value="data_leakage" onclick="togglePill(this)">
          <span class="pill-dot"></span> Data Leakage
        </button>
        <button type="button" class="pill-btn active" data-value="output_handling" onclick="togglePill(this)">
          <span class="pill-dot"></span> Output Handling
        </button>
        <button type="button" class="pill-btn active" data-value="insecure_plugin_design" onclick="togglePill(this)">
          <span class="pill-dot"></span> Insecure Plugin Design
        </button>
        <button type="button" class="pill-btn active" data-value="model_dos" onclick="togglePill(this)">
          <span class="pill-dot"></span> Model DoS
        </button>
        <button type="button" class="pill-btn active" data-value="excessive_agency" onclick="togglePill(this)">
          <span class="pill-dot"></span> Excessive Agency
        </button>
        <button type="button" class="pill-btn active" data-value="overreliance" onclick="togglePill(this)">
          <span class="pill-dot"></span> Overreliance
        </button>
        <button type="button" class="pill-btn active" data-value="model_theft_leak" onclick="togglePill(this)">
          <span class="pill-dot"></span> Model Theft
        </button>
      </div>

      <div class="btn-row">
        <button type="button" class="btn-submit" id="submitBtn" onclick="startScan()" style="flex:1">
          <i data-lucide="play" size="16"></i>
          <span>Start scan</span>
        </button>
        <button type="button" class="btn-stop" id="stopBtn" onclick="stopScan()" disabled title="Stop current scan">
          <i data-lucide="square" size="16"></i>
          <span>Stop</span>
        </button>
      </div>
    </form>

    <div class="film" id="livePanel">
      <div class="live-row"><span class="live-k">Target</span><span class="live-v" id="liveTarget">—</span></div>
      <div class="live-row"><span class="live-k">Tests completed</span><span class="live-v" id="liveCount">0 / 0</span></div>
      <div class="live-row"><span class="live-k">Current test</span><span class="live-v" id="liveCurrent">—</span></div>
      <div class="live-row"><span class="live-k">Status</span><span class="live-v glow" id="liveStatus">Idle</span></div>
      <div class="progress-track"><div class="progress-fill" id="progressFill"></div></div>
    </div>

    <div class="console-box" id="consoleBox"></div>
  </div>

  <div class="card reports-section">
    <h3 class="section-title">Scan reports</h3>
    <div class="reports-list">

      <div class="report-card">
        <div class="report-info">
          <div class="report-icon-box"><i data-lucide="file-code" size="17"></i></div>
          <div class="report-meta">
            <h4>HTML report</h4>
            <span id="htmlReportStatus">Available after scan</span>
          </div>
        </div>
        <div class="report-actions">
          <a class="open-btn disabled" id="htmlOpenBtn" aria-disabled="true" tabindex="-1" aria-label="Open HTML report in browser" title="Open in browser" target="_blank" rel="noopener">
            <i data-lucide="external-link" size="14"></i> Open
          </a>
          <a class="download-btn disabled" id="htmlDownloadBtn" aria-disabled="true" tabindex="-1" aria-label="Download HTML report" title="Download HTML report">
            <i data-lucide="download" size="16"></i>
          </a>
        </div>
      </div>

      <div class="report-card">
        <div class="report-info">
          <div class="report-icon-box"><i data-lucide="file-json" size="17"></i></div>
          <div class="report-meta">
            <h4>JSON report</h4>
            <span id="jsonReportStatus">Available after scan</span>
          </div>
        </div>
        <a class="download-btn disabled" id="jsonDownloadBtn" aria-disabled="true" tabindex="-1" aria-label="Download JSON report" title="Download JSON report">
          <i data-lucide="download" size="16"></i>
        </a>
      </div>

    </div>
  </div>

  <div class="card" id="resultsCard" style="display:none">
    <h3 class="section-title">Scan results</h3>
    <div class="summary-cards" id="summaryCards"></div>
    <h4 class="section-subtitle">Findings</h4>
    <div id="findingsWrap"></div>
  </div>

</div>

<footer class="footer">AI-Xray · LLM Application Security Scanner</footer>

<script>
lucide.createIcons();

const CATEGORY_LABELS = {
  prompt_injection: "Prompt Injection",
  jailbreak: "Jailbreak",
  data_leakage: "Sensitive Information Disclosure",
  output_handling: "Insecure Output Handling",
  insecure_plugin_design: "Insecure Plugin Design",
  model_dos: "Model Denial of Service",
  excessive_agency: "Excessive Agency",
  overreliance: "Overreliance",
  model_theft_leak: "Model Theft"
};

// Fixed rate limit between requests (no UI control per product decision)
const FIXED_RATE_LIMIT = 0.5;

let eventSource = null;
let currentScanId = null;
let totalPayloads = 0;
let donePayloads  = 0;
let livePollTimer = null;
let pwVisible = false;
let scanning = false;

function togglePwVisibility() {
  const input = document.getElementById('apiKey');
  const icon  = document.getElementById('pwToggleIcon');
  const btn   = document.getElementById('pwToggle');
  pwVisible = !pwVisible;
  input.type = pwVisible ? 'text' : 'password';
  icon.setAttribute('data-lucide', pwVisible ? 'eye-off' : 'eye');
  btn.setAttribute('aria-label', pwVisible ? 'Hide API key' : 'Show API key');
  lucide.createIcons();
}

function togglePill(el) {
  if (scanning) return;
  el.classList.toggle('active');
  updateBadgeCount();
}
function updateBadgeCount() {
  const activeCount = document.querySelectorAll('.pill-btn.active').length;
  const totalCount  = document.querySelectorAll('.pill-btn').length;
  document.getElementById('selectedCount').innerText = `${activeCount}/${totalCount} selected`;
}
function getSelectedCats() {
  return [...document.querySelectorAll('.pill-btn.active')].map(p => p.dataset.value);
}

function validateInputs() {
  const url = document.getElementById('targetUrl').value.trim();
  const key = document.getElementById('apiKey').value.trim();
  const msg = document.getElementById('validationMsg');
  if (!url || !key) { msg.style.display = 'block'; return false; }
  msg.style.display = 'none';
  return true;
}

function term(message, cls = '') {
  const box = document.getElementById('consoleBox');
  const time = new Date().toLocaleTimeString();
  const line = document.createElement('div');
  line.className = 'console-line' + (cls ? ' c-' + cls : '');
  line.innerHTML = `<span class="console-time">[${time}]</span><span>${esc(message)}</span>`;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}
function esc(str) {
  return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function setReportsGenerating() {
  document.getElementById('htmlReportStatus').textContent = 'Generating…';
  document.getElementById('jsonReportStatus').textContent = 'Generating…';
  disableReportBtn('htmlDownloadBtn');
  disableReportBtn('jsonDownloadBtn');
  disableOpenBtn('htmlOpenBtn');
}
function resetReports() {
  document.getElementById('htmlReportStatus').textContent = 'Available after scan';
  document.getElementById('jsonReportStatus').textContent = 'Available after scan';
  disableReportBtn('htmlDownloadBtn');
  disableReportBtn('jsonDownloadBtn');
  disableOpenBtn('htmlOpenBtn');
}
function disableReportBtn(id) {
  const btn = document.getElementById(id);
  btn.classList.add('disabled');
  btn.removeAttribute('href');
  btn.removeAttribute('download');
  btn.setAttribute('aria-disabled', 'true');
  btn.tabIndex = -1;
}
function enableReportBtn(id, href, filename) {
  const btn = document.getElementById(id);
  btn.classList.remove('disabled');
  btn.href = href;
  btn.setAttribute('download', filename);
  btn.removeAttribute('aria-disabled');
  btn.tabIndex = 0;
}
function disableOpenBtn(id) {
  const btn = document.getElementById(id);
  btn.classList.add('disabled');
  btn.removeAttribute('href');
  btn.setAttribute('aria-disabled', 'true');
  btn.tabIndex = -1;
}
function enableOpenBtn(id, href) {
  const btn = document.getElementById(id);
  btn.classList.remove('disabled');
  btn.href = href;
  btn.removeAttribute('aria-disabled');
  btn.tabIndex = 0;
}
function setReportLinks(jsonFile, htmlFile) {
  if (htmlFile) {
    document.getElementById('htmlReportStatus').textContent = 'Ready';
    enableReportBtn('htmlDownloadBtn', `/reports/${htmlFile}`, 'ai-xray-security-report.html');
    enableOpenBtn('htmlOpenBtn', `/reports/${htmlFile}`);
  }
  if (jsonFile) {
    document.getElementById('jsonReportStatus').textContent = 'Ready';
    enableReportBtn('jsonDownloadBtn', `/reports/${jsonFile}`, 'ai-xray-security-report.json');
  }
}

function startLivePolling() {
  stopLivePolling();
  livePollTimer = setInterval(pollLiveStatus, 1000);
  pollLiveStatus();
}
function stopLivePolling() {
  if (livePollTimer) { clearInterval(livePollTimer); livePollTimer = null; }
}
async function pollLiveStatus() {
  try {
    const r = await fetch('/api/live-status?t=' + Date.now(), {cache:'no-store'});
    if (r.ok) {
      const d = await r.json();
      if (!d.error) applyLiveStatus(d);
    }
  } catch(_) {}
}
function applyLiveStatus(d) {
  // Live status polling still works; reserved for future coverage UI.
}

async function startScan() {
  if (scanning) return;
  if (!validateInputs()) return;

  const url      = document.getElementById('targetUrl').value.trim();
  const apikey   = document.getElementById('apiKey').value.trim();
  const endpoint = document.getElementById('endpoint').value.trim() || '/chat';
  const cats     = getSelectedCats();

  scanning = true;
  const submitBtn = document.getElementById('submitBtn');
  submitBtn.disabled = true;
  submitBtn.innerHTML = `<i data-lucide="loader-2" size="16" class="spin"></i><span>Scanning…</span>`;
  const stopBtn = document.getElementById('stopBtn');
  stopBtn.disabled = false;
  stopBtn.classList.add('active');
  stopBtn.classList.remove('stopping');
  stopBtn.innerHTML = `<i data-lucide="square" size="16"></i><span>Stop</span>`;
  lucide.createIcons();

  document.getElementById('pillGrid').classList.add('locked');
  document.getElementById('resultsCard').style.display = 'none';
  document.getElementById('livePanel').style.display = 'block';
  document.getElementById('consoleBox').style.display = 'block';
  document.getElementById('consoleBox').innerHTML = '';
  document.getElementById('progressFill').style.width = '0%';
  document.getElementById('liveTarget').textContent = url + endpoint;
  document.getElementById('liveCount').textContent = '0 / 0';
  document.getElementById('liveCurrent').textContent = '—';
  document.getElementById('liveStatus').textContent = 'Starting…';
  setReportsGenerating();

  donePayloads = 0; totalPayloads = 0;

  term(`Target initialized: ${url}${endpoint}`);
  term(`Loaded ${cats.length} test suite(s). Starting security assessment…`);

  let scanId;
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url, apikey, endpoint, rate_limit: FIXED_RATE_LIMIT,
                            categories: cats.length ? cats : null})
    });
    const data = await res.json();
    if (!res.ok) { term(data.error || 'Failed to start scan', 'err'); finishScan(false); return; }
    scanId = data.scan_id;
    currentScanId = scanId;
  } catch(e) {
    term('Could not connect to the scanner backend: ' + e.message, 'err');
    finishScan(false); return;
  }

  startLivePolling();
  document.getElementById('liveStatus').textContent = 'Testing';

  eventSource = new EventSource(`/api/scan/stream/${scanId}`);

  eventSource.onmessage = (e) => {
    const msg = JSON.parse(e.data);

    if (msg.type === 'total') {
      totalPayloads = msg.value;
      document.getElementById('liveCount').textContent = `0 / ${totalPayloads}`;
      term(`Total payloads: ${totalPayloads}`);
    }
    else if (msg.type === 'progress') {
      donePayloads++;
      const pct = totalPayloads > 0 ? Math.round((donePayloads/totalPayloads)*100) : 0;
      document.getElementById('progressFill').style.width = pct + '%';
      document.getElementById('liveCount').textContent = `${donePayloads}/${totalPayloads}`;
      document.getElementById('liveCurrent').textContent = msg.name;
      term(`[${donePayloads}/${totalPayloads}] ${msg.id}: ${msg.name}`);
    }
    else if (msg.type === 'finding') {
      term(`Finding — ${msg.tag} · ${String(msg.severity).toUpperCase()} · risk ${msg.risk}/100`, 'warn');
    }
    else if (msg.type === 'ok') {
      term('No vulnerability detected', 'ok');
    }
    else if (msg.type === 'error') {
      term(msg.message, 'err');
    }
    else if (msg.type === 'done') {
      term(`Scan complete — ${msg.total_findings} finding(s) · avg risk ${msg.avg_risk}/100`, 'ok');
      document.getElementById('liveStatus').textContent = 'Complete';
      eventSource.close();
      stopLivePolling();
      loadResults(scanId);
      finishScan(true);
    }
  };

  eventSource.onerror = () => {
    term('Stream connection lost.', 'err');
    eventSource.close();
    stopLivePolling();
    finishScan(false);
  };
}

function finishScan(success) {
  scanning = false;
  document.getElementById('pillGrid').classList.remove('locked');
  const stopBtn = document.getElementById('stopBtn');
  stopBtn.disabled = true;
  stopBtn.classList.remove('active', 'stopping');
  stopBtn.innerHTML = `<i data-lucide="square" size="16"></i><span>Stop</span>`;
  lucide.createIcons();
  const submitBtn = document.getElementById('submitBtn');
  submitBtn.disabled = false;
  if (success) {
    submitBtn.innerHTML = `<i data-lucide="check" size="16"></i><span>Scan complete</span>`;
    lucide.createIcons();
    setTimeout(() => {
      submitBtn.innerHTML = `<i data-lucide="play" size="16"></i><span>Start scan</span>`;
      lucide.createIcons();
    }, 4000);
  } else {
    submitBtn.innerHTML = `<i data-lucide="play" size="16"></i><span>Start scan</span>`;
    lucide.createIcons();
    resetReports();
  }
}

async function stopScan() {
  if (!scanning || !currentScanId) return;
  const stopBtn = document.getElementById('stopBtn');
  stopBtn.disabled = true;
  stopBtn.classList.add('stopping');
  stopBtn.innerHTML = `<i data-lucide="loader-2" size="14" class="spin"></i><span>Stopping…</span>`;
  lucide.createIcons();
  try {
    await fetch(`/api/scan/stop/${currentScanId}`, {method: 'POST'});
    term('Stop signal sent — finishing current request…', 'warn');
    document.getElementById('liveStatus').textContent = 'Stopping…';
  } catch(e) {
    term('Failed to send stop signal: ' + e.message, 'err');
    stopBtn.disabled = false;
    stopBtn.classList.remove('stopping');
  }
}

async function loadResults(scanId) {
  try {
    const res  = await fetch(`/api/scan/result/${scanId}`);
    const data = await res.json();
    if (!data.result) return;

    const r   = data.result;
    const sum = r.summary || {};
    const sev = sum.by_severity || {};
    const tested = r.total_payloads_tested || 0;
    const safe = Math.max(tested - (sum.total_findings || 0), 0);

    document.getElementById('summaryCards').innerHTML = `
      <div class="stat"><div class="stat-val">${tested}</div><div class="stat-lbl">Tests</div></div>
      <div class="stat"><div class="stat-val">${sum.total_findings||0}</div><div class="stat-lbl">Findings</div></div>
      <div class="stat"><div class="stat-val">${safe}</div><div class="stat-lbl">Safe</div></div>
      <div class="stat stat-high"><div class="stat-val">${sev.high||0}</div><div class="stat-lbl">High</div></div>
      <div class="stat stat-med"><div class="stat-val">${sev.medium||0}</div><div class="stat-lbl">Medium</div></div>
      <div class="stat stat-low"><div class="stat-val">${sev.low||0}</div><div class="stat-lbl">Low</div></div>
    `;

    const findings = (r.findings || []).slice().sort((a,b) => (b.risk_score||0) - (a.risk_score||0));
    const wrap = document.getElementById('findingsWrap');
    if (!findings.length) {
      wrap.innerHTML = `<div class="no-findings"><i data-lucide="shield-check" size="18"></i> No vulnerabilities detected.</div>`;
    } else {
      wrap.innerHTML = findings.map(f => {
        const sevKey = (f.severity||'low').toLowerCase();
        return `<div class="finding-card sev-${esc(sevKey)}">
          <div class="finding-top">
            <span class="finding-name">${esc(f.name || f.detected_tag || 'Finding')}</span>
            <span class="sev-badge sev-${esc(sevKey)}">${esc(f.severity||'')}</span>
          </div>
          <div class="finding-meta">
            <span>${esc(f.category||'')}</span>
            <span>Confidence ${Math.round((f.confidence||0)*100)}%</span>
            <span>Risk ${Math.round(f.risk_score||0)}/100</span>
          </div>
          ${f.matched_text ? `<div class="finding-evidence"><span class="ev-label">Evidence</span>${esc(f.matched_text)}</div>` : ''}
        </div>`;
      }).join('');
    }
    lucide.createIcons();

    setReportLinks(data.json_file, data.html_file);
    document.getElementById('resultsCard').style.display = 'block';
  } catch(e) {
    term('Could not load scan results: ' + e.message, 'err');
  }
}
</script>
</body>
</html>
"""

# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return DASHBOARD_HTML


@app.route("/favicon.ico")
def favicon():
    return "", 204


@app.route("/api/live-status")
def api_live_status():
    """Serve the live_status.json file content as JSON for the embedded attack map."""
    path = os.path.join(REPORTS_DIR, "live_status.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return jsonify(data)
    except FileNotFoundError:
        return jsonify({"error": "no scan running"}), 404
    except Exception:
        return jsonify({"error": "read error"}), 500


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Start a scan in a background thread, return scan_id immediately."""
    data = request.get_json(force=True, silent=True) or {}

    url        = data.get("url", "").strip()
    apikey     = data.get("apikey", "").strip()
    endpoint   = data.get("endpoint", "/chat").strip() or "/chat"
    rate_limit = float(data.get("rate_limit", 0.5))
    categories = data.get("categories") or None  # None = all

    if not url:
        return jsonify({"error": "Target URL is required"}), 400
    if not apikey:
        return jsonify({"error": "API key is required"}), 400

    scan_id = str(uuid.uuid4())
    q: queue.Queue = queue.Queue()

    stop_event = threading.Event()
    with _store_lock:
        _scan_store[scan_id] = {
            "status":     "running",
            "queue":      q,
            "result":     None,
            "json_file":  None,
            "html_file":  None,
            "stop_event": stop_event,
        }

    # Reset live_status.json IMMEDIATELY so the JS poller never reads stale
    # "finished: true" data from a previous scan.  This is synchronous —
    # by the time the browser first polls /api/live-status (~800ms later)
    # the file already contains finished=False and empty categories.
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        _reset_status = {
            "scan_id":          scan_id,
            "target_url":       url + endpoint,
            "started_at":       datetime.now(timezone.utc).isoformat(),
            "categories":       {},
            "overall_progress": {"tested": 0, "total": 0},
            "finished":         False,
            "initializing":     True,
        }
        with open(os.path.join(REPORTS_DIR, "live_status.json"), "w", encoding="utf-8") as _fh:
            json.dump(_reset_status, _fh, indent=2)
    except Exception:
        pass

    thread = threading.Thread(
        target=_run_scan_thread,
        args=(scan_id, url, endpoint, apikey, rate_limit, categories, stop_event),
        daemon=True,
    )
    thread.start()
    return jsonify({"scan_id": scan_id})


def _run_scan_thread(scan_id, url, endpoint, apikey, rate_limit, categories, stop_event):
    """Background thread: runs the full scan and pushes SSE events to the queue."""
    store = _scan_store[scan_id]
    q: queue.Queue = store["queue"]

    def push(event: dict):
        q.put(json.dumps(event))

    try:
        target = Target(base_url=url, endpoint=endpoint, api_key=apikey)

        # Custom engine subclass that pushes SSE events
        class WebScanEngine(ScanEngine):
            def run_scan(self):
                from datetime import timezone
                from detectors.heuristic import detect_vulnerabilities
                from detectors.scorer import score_finding, aggregate_summary
                import time

                scan_start = datetime.now(tz=timezone.utc)
                payload_list = self.load_payloads()

                push({"type": "total", "value": len(payload_list)})

                all_findings = []
                total_tested = 0

                # -- Live map: init status --
                _lm_status = {}
                _lm_path = os.path.join(REPORTS_DIR, "live_status.json")
                try:
                    _cat_order, _cat_totals = [], {}
                    for _c, _p in payload_list:
                        if _c not in _cat_totals:
                            _cat_order.append(_c); _cat_totals[_c] = 0
                        _cat_totals[_c] += 1
                    _lm_status = _ls.init_status(_cat_order, url + endpoint)
                    for _c in _cat_order:
                        _lm_status["categories"][_c]["total"] = _cat_totals[_c]
                        _lm_status["categories"][_c]["safe_count"] = 0
                    _lm_status["overall_progress"]["total"] = len(payload_list)
                    _ls.write_status(_lm_status, _lm_path)
                except Exception:
                    pass
                _lm_prev_cat = None

                for idx, (category, payload) in enumerate(payload_list, 1):
                    if stop_event.is_set():
                        push({"type": "error", "message": "Scan stopped by user."})
                        break

                    pid   = payload.get("id", f"UNKNOWN-{idx}")
                    pname = payload.get("name", "Unnamed")
                    ptext = payload.get("prompt", "")

                    push({"type": "progress", "id": pid, "name": pname,
                          "idx": idx, "total": len(payload_list)})

                    # -- Live map: category transitions --
                    if _lm_status:
                        try:
                            if category != _lm_prev_cat:
                                if _lm_prev_cat and _lm_prev_cat in _lm_status["categories"]:
                                    pd = _lm_status["categories"][_lm_prev_cat]
                                    pd["state"] = "vulnerable" if pd["findings"] > 0 else "safe"
                                    _ls.write_status(_lm_status, _lm_path)
                                if category in _lm_status["categories"]:
                                    _lm_status["categories"][category]["state"] = "testing"
                                    _ls.write_status(_lm_status, _lm_path)
                                _lm_prev_cat = category
                        except Exception:
                            pass

                    if not ptext:
                        push({"type": "ok"})
                        continue

                    total_tested += 1
                    response = self.target.send_message(ptext)

                    if not response.get("success"):
                        push({"type": "error",
                              "message": response.get("error", "Request failed")})
                        if self.rate_limit_seconds > 0:
                            time.sleep(self.rate_limit_seconds)
                        continue

                    reply = response.get("reply", "")
                    # elapsed_seconds is always present on Target.send_message()'s
                    # return dict now (see core/target.py) — used by the
                    # "model_dos" tag to detect abnormally slow/huge responses.
                    # Every other tag ignores this value.
                    elapsed_seconds = response.get("elapsed_seconds")
                    raw_findings = detect_vulnerabilities(payload, reply, elapsed_seconds)

                    if not raw_findings:
                        push({"type": "ok"})
                    else:
                        for rf in raw_findings:
                            scored = score_finding(payload, rf, category)
                            all_findings.append(scored)
                            push({"type": "finding",
                                  "tag":      scored["detected_tag"],
                                  "severity": scored["severity"],
                                  "risk":     scored["risk_score"],
                                  "matched":  scored["matched_text"]})

                    # -- Live map: per-payload counts --
                    if _lm_status:
                        try:
                            _lm_status["overall_progress"]["tested"] = total_tested
                            if category in _lm_status["categories"]:
                                _lm_status["categories"][category]["tested"] += 1
                                if raw_findings:
                                    _lm_status["categories"][category]["findings"] += len(raw_findings)
                                else:
                                    _lm_status["categories"][category]["safe_count"] = _lm_status["categories"][category].get("safe_count", 0) + 1
                            _ls.write_status(_lm_status, _lm_path)
                        except Exception:
                            pass

                    if self.rate_limit_seconds > 0 and idx < len(payload_list):
                        time.sleep(self.rate_limit_seconds)

                summary = aggregate_summary(all_findings)

                # -- Live map: finalise --
                if _lm_status:
                    try:
                        if _lm_prev_cat and _lm_prev_cat in _lm_status["categories"]:
                            last = _lm_status["categories"][_lm_prev_cat]
                            last["state"] = "vulnerable" if last["findings"] > 0 else "safe"
                        _lm_status["overall_progress"]["tested"] = total_tested
                        _lm_status["finished"] = True
                        _ls.write_status(_lm_status, _lm_path)
                    except Exception:
                        pass

                result = {
                    "target_url":            url + endpoint,
                    "scan_timestamp":        scan_start.isoformat(),
                    "total_payloads_tested": total_tested,
                    "findings":              all_findings,
                    "summary":               summary,
                }

                push({
                    "type":           "done",
                    "total_findings": summary["total_findings"],
                    "avg_risk":       summary["average_risk_score"],
                })
                return result

        engine = WebScanEngine(
            target=target,
            payload_dir=PAYLOAD_DIR,
            categories=categories,
            rate_limit_seconds=rate_limit,
        )
        scan_result = engine.run_scan()

        # Save reports
        os.makedirs(REPORTS_DIR, exist_ok=True)
        basename   = "scan_" + datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path  = os.path.join(REPORTS_DIR, basename + ".json")
        html_path  = os.path.join(REPORTS_DIR, basename + ".html")

        generate_json_report(scan_result, json_path)
        generate_html_report(scan_result, html_path)

        with _store_lock:
            store["status"]    = "done"
            store["result"]    = scan_result
            store["json_file"] = basename + ".json"
            store["html_file"] = basename + ".html"

    except Exception as exc:
        push({"type": "error", "message": str(exc)})
        with _store_lock:
            store["status"] = "error"
    finally:
        q.put(None)  # sentinel — stream ends


@app.route("/api/scan/stream/<scan_id>")
def api_scan_stream(scan_id):
    """Server-Sent Events stream: pushes live scan log lines to the browser."""
    store = _scan_store.get(scan_id)
    if not store:
        return Response("scan not found", status=404)

    def generate():
        q: queue.Queue = store["queue"]
        while True:
            item = q.get()
            if item is None:
                break
            yield f"data: {item}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":  "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/api/scan/result/<scan_id>")
def api_scan_result(scan_id):
    """Return the final scan result JSON for a completed scan."""
    store = _scan_store.get(scan_id)
    if not store:
        return jsonify({"error": "scan not found"}), 404
    return jsonify({
        "status":    store["status"],
        "result":    store["result"],
        "json_file": store["json_file"],
        "html_file": store["html_file"],
    })


@app.route("/api/scan/stop/<scan_id>", methods=["POST"])
def api_scan_stop(scan_id):
    """Signal the running scan thread to stop gracefully."""
    store = _scan_store.get(scan_id)
    if not store:
        return jsonify({"error": "scan not found"}), 404
    stop_event = store.get("stop_event")
    if stop_event:
        stop_event.set()
    return jsonify({"ok": True})


@app.route("/reports/<path:filename>")
def serve_report(filename):
    """Serve files from the reports/ directory (download or view)."""
    return send_from_directory(REPORTS_DIR, filename)


# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Entry point for the 'llm-scanner-web' pip command."""
    import webbrowser
    import threading
    print("\n  [*] AI-Xray — AI/LLM Application Security Scanner")
    print("  -------------------------------------")
    print("  Open in browser:  http://localhost:8080\n")
    threading.Timer(1.5, lambda: webbrowser.open("http://localhost:8080")).start()
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)


if __name__ == "__main__":
    main()