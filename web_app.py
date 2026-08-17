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
from datetime import datetime

from flask import Flask, Response, jsonify, request, send_from_directory

# ── Make sure project root is on the path ────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import ScanEngine
from core.target import Target
from core import live_status as _ls
from reporters.json_report import generate_json_report
from reporters.html_report import generate_html_report

# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)

# In-memory store: scan_id → {status, queue, result, json_path, html_path}
_scan_store: dict = {}
_store_lock = threading.Lock()

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
PAYLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payloads")

# ─────────────────────────────────────────────────────────────────────────────
# Dashboard HTML (inline — zero external files needed)
# ─────────────────────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>LLM Security Scanner — Web Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
/* ── CSS Variables ────────────────────────────────────────────── */
:root[data-theme="dark"]{
  --bg:#0b0d17;--bg2:#111322;--bg3:rgba(255,255,255,0.04);
  --border:rgba(255,255,255,0.08);--border2:rgba(99,179,237,0.25);
  --text:#e8eaf6;--text2:#8892b0;--text3:#4a5568;
  --cyan:#63b3ed;--purple:#9f7aea;--red:#f87171;--orange:#fb923c;
  --yellow:#facc15;--green:#4ade80;
  --nav:rgba(11,13,23,0.95);--card:rgba(255,255,255,0.04);
  --input:#1a1f35;--input-border:rgba(255,255,255,0.12);
  --shadow:0 8px 32px rgba(0,0,0,.5);
  --terminal:#0a0c14;--terminal-text:#a8ff78;
  --btn-primary:linear-gradient(135deg,#3b82f6,#6366f1);
  --btn-danger:linear-gradient(135deg,#ef4444,#b91c1c);
}
:root[data-theme="light"]{
  --bg:#f0f4ff;--bg2:#ffffff;--bg3:#ffffff;
  --border:#e2e8f0;--border2:#93c5fd;
  --text:#1e293b;--text2:#475569;--text3:#94a3b8;
  --cyan:#2563eb;--purple:#7c3aed;--red:#dc2626;--orange:#ea580c;
  --yellow:#ca8a04;--green:#16a34a;
  --nav:rgba(255,255,255,0.97);--card:#ffffff;
  --input:#f8faff;--input-border:#cbd5e1;
  --shadow:0 8px 32px rgba(0,0,0,.1);
  --terminal:#1e293b;--terminal-text:#a8ff78;
  --btn-primary:linear-gradient(135deg,#2563eb,#4f46e5);
  --btn-danger:linear-gradient(135deg,#dc2626,#991b1b);
}

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;font-size:14px;line-height:1.6;
  background:var(--bg);color:var(--text);transition:background .3s,color .3s;min-height:100vh}
::selection{background:var(--cyan);color:#fff}

/* ── Navbar ─────────────────────────────────────────────────── */
.nav{position:sticky;top:0;z-index:100;background:var(--nav);
  border-bottom:1px solid var(--border);backdrop-filter:blur(20px);
  padding:0 2rem;height:60px;display:flex;align-items:center;
  justify-content:space-between;box-shadow:var(--shadow);transition:background .3s}
.nav-brand{display:flex;align-items:center;gap:.6rem;font-weight:800;font-size:1.05rem;
  color:var(--text);letter-spacing:-.02em}
.shield{width:34px;height:34px;background:linear-gradient(135deg,var(--cyan),var(--purple));
  border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:1.1rem;
  box-shadow:0 0 16px rgba(99,179,237,.4)}
.nav-right{display:flex;align-items:center;gap:1rem}
.nav-badge{font-size:.72rem;font-weight:600;color:var(--text2);background:var(--bg3);
  border:1px solid var(--border);border-radius:99px;padding:.25rem .8rem}
.toggle{display:flex;align-items:center;gap:.5rem;cursor:pointer;user-select:none}
.toggle-icon{font-size:.9rem;color:var(--text2)}
.toggle-track{width:44px;height:24px;background:var(--input);border-radius:99px;
  border:1px solid var(--border);position:relative;cursor:pointer;transition:background .3s}
.toggle-knob{position:absolute;top:3px;left:3px;width:16px;height:16px;
  background:var(--cyan);border-radius:50%;transition:transform .3s cubic-bezier(.68,-.55,.27,1.55);
  box-shadow:0 0 8px rgba(99,179,237,.6)}
[data-theme="light"] .toggle-knob{transform:translateX(20px)}

/* ── Main layout ─────────────────────────────────────────────── */
.main{max-width:1100px;margin:0 auto;padding:2.5rem 2rem 4rem}

/* ── Hero ───────────────────────────────────────────────────── */
.hero{text-align:center;margin-bottom:2.5rem}
.hero h1{font-size:2.2rem;font-weight:900;letter-spacing:-.04em;
  background:linear-gradient(135deg,var(--cyan),var(--purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;margin-bottom:.4rem}
.hero p{color:var(--text2);font-size:.92rem}

/* ── Scan Form Card ─────────────────────────────────────────── */
.form-card{background:var(--card);border:1px solid var(--border);border-radius:20px;
  padding:2rem;box-shadow:var(--shadow);margin-bottom:2rem}
.form-title{font-size:.68rem;font-weight:800;text-transform:uppercase;
  letter-spacing:.12em;color:var(--text3);margin-bottom:1.4rem;
  display:flex;align-items:center;gap:.6rem}
.form-title::after{content:'';flex:1;height:1px;background:var(--border)}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:1.2rem}
.form-group{display:flex;flex-direction:column;gap:.4rem}
.form-group.full{grid-column:1/-1}
label{font-size:.75rem;font-weight:700;color:var(--text2);letter-spacing:.04em}
input[type=text],input[type=number],select{
  background:var(--input);border:1px solid var(--input-border);border-radius:10px;
  padding:.7rem 1rem;color:var(--text);font-family:'Inter',sans-serif;font-size:.88rem;
  outline:none;transition:border-color .2s,box-shadow .2s;width:100%}
input[type=text]:focus,input[type=number]:focus,select:focus{
  border-color:var(--cyan);box-shadow:0 0 0 3px rgba(99,179,237,.15)}
input::placeholder{color:var(--text3)}

/* ── Categories ─────────────────────────────────────────────── */
.cats{display:flex;flex-wrap:wrap;gap:.6rem;margin-top:.3rem}
.cat-chip{display:flex;align-items:center;gap:.45rem;cursor:pointer;
  background:var(--input);border:1px solid var(--input-border);border-radius:99px;
  padding:.35rem .9rem;font-size:.78rem;font-weight:600;color:var(--text2);
  transition:all .2s;user-select:none}
.cat-chip:hover{border-color:var(--cyan);color:var(--cyan)}
.cat-chip input{display:none}
.cat-chip.active{background:rgba(99,179,237,.12);border-color:var(--cyan);color:var(--cyan)}
.cat-dot{width:7px;height:7px;border-radius:50%;background:currentColor}

/* ── Rate Limit Slider ───────────────────────────────────────── */
.slider-row{display:flex;align-items:center;gap:.8rem}
input[type=range]{flex:1;accent-color:var(--cyan)}
.slider-val{font-size:.82rem;font-weight:700;color:var(--cyan);
  font-family:'JetBrains Mono',monospace;min-width:40px}

/* ── Buttons ─────────────────────────────────────────────────── */
.btn-row{display:flex;gap:.8rem;margin-top:1.5rem}
.btn{padding:.75rem 1.8rem;border-radius:12px;border:none;cursor:pointer;
  font-family:'Inter',sans-serif;font-size:.88rem;font-weight:700;
  transition:transform .15s,box-shadow .15s;white-space:nowrap}
.btn:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,.3)}
.btn:active{transform:translateY(0)}
.btn-primary{background:var(--btn-primary);color:#fff}
.btn-danger{background:var(--btn-danger);color:#fff;display:none}
.btn:disabled{opacity:.5;cursor:not-allowed;transform:none}

/* ── Status Bar ──────────────────────────────────────────────── */
.status-bar{display:none;align-items:center;gap:.8rem;
  background:var(--card);border:1px solid var(--border);border-radius:12px;
  padding:.8rem 1.2rem;margin-bottom:1.5rem}
.status-dot{width:10px;height:10px;border-radius:50%;background:var(--cyan);
  animation:pulse 1.5s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.8)}}
.status-text{font-size:.85rem;font-weight:600;color:var(--text)}
.status-count{margin-left:auto;font-size:.78rem;color:var(--text2);font-family:'JetBrains Mono',monospace}

/* ── Progress Bar ────────────────────────────────────────────── */
.progress-wrap{margin-bottom:1.5rem;display:none}
.progress-label{font-size:.72rem;font-weight:700;color:var(--text2);
  margin-bottom:.4rem;display:flex;justify-content:space-between}
.progress-track{height:6px;background:var(--border);border-radius:99px;overflow:hidden}
.progress-fill{height:100%;border-radius:99px;width:0%;
  background:linear-gradient(90deg,var(--cyan),var(--purple));
  transition:width .4s ease}

/* ── Terminal ────────────────────────────────────────────────── */
.terminal-wrap{display:none;margin-bottom:2rem}
.terminal-header{display:flex;align-items:center;justify-content:space-between;
  background:#1a1f2e;border-radius:14px 14px 0 0;padding:.7rem 1rem;
  border:1px solid var(--border);border-bottom:none}
.terminal-dots{display:flex;gap:.45rem}
.terminal-dots span{width:12px;height:12px;border-radius:50%}
.dot-red{background:#ff5f57}.dot-yellow{background:#febc2e}.dot-green{background:#28c840}
.terminal-title{font-size:.72rem;color:var(--text3);font-family:'JetBrains Mono',monospace}
.terminal-clear{font-size:.72rem;color:var(--text3);cursor:pointer;padding:.2rem .6rem;
  border-radius:6px;border:1px solid var(--border);background:transparent;
  color:var(--text2);transition:color .2s}
.terminal-clear:hover{color:var(--cyan)}
.terminal{background:var(--terminal);border:1px solid var(--border);border-radius:0 0 14px 14px;
  padding:1rem 1.2rem;min-height:220px;max-height:340px;overflow-y:auto;
  font-family:'JetBrains Mono',monospace;font-size:.78rem;line-height:1.7}
.t-cyan{color:#63b3ed}.t-green{color:#a8ff78}.t-red{color:#f87171}
.t-yellow{color:#facc15}.t-dim{color:#4a5568}.t-white{color:#e8eaf6}

/* ── Results ─────────────────────────────────────────────────── */
.results-section{display:none}
.section-label{font-size:.68rem;font-weight:800;text-transform:uppercase;
  letter-spacing:.12em;color:var(--text3);margin:2rem 0 1rem;
  display:flex;align-items:center;gap:.6rem}
.section-label::after{content:'';flex:1;height:1px;background:var(--border)}

/* ── Summary Cards ───────────────────────────────────────────── */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.9rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;
  padding:1.2rem 1.3rem;position:relative;overflow:hidden;
  transition:transform .2s,box-shadow .2s}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;border-radius:16px 16px 0 0}
.card:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.25)}
.card-lbl{font-size:.62rem;text-transform:uppercase;letter-spacing:.1em;
  color:var(--text3);font-weight:700;margin-bottom:.4rem}
.card-val{font-size:2rem;font-weight:900;letter-spacing:-.04em;line-height:1}
.card-sub{font-size:.68rem;color:var(--text3);margin-top:.2rem}
.c-total::before{background:linear-gradient(90deg,#3b82f6,#6366f1)}
.c-total .card-val{color:#60a5fa}
.c-crit::before{background:linear-gradient(90deg,#ef4444,#dc2626)}
.c-crit .card-val{color:#f87171}
.c-high::before{background:linear-gradient(90deg,#f97316,#ea580c)}
.c-high .card-val{color:#fb923c}
.c-med::before{background:linear-gradient(90deg,#eab308,#ca8a04)}
.c-med .card-val{color:#facc15}
.c-low::before{background:linear-gradient(90deg,#22c55e,#16a34a)}
.c-low .card-val{color:#4ade80}
.c-risk::before{background:linear-gradient(90deg,#a855f7,#7c3aed)}
.c-risk .card-val{color:#c084fc}

/* ── Download Bar ────────────────────────────────────────────── */
.dl-bar{display:flex;gap:.8rem;flex-wrap:wrap;margin-top:1rem}
.btn-dl{padding:.6rem 1.3rem;border-radius:10px;border:1px solid var(--border);
  background:var(--card);color:var(--text2);font-size:.82rem;font-weight:600;
  cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:.5rem;
  transition:all .2s;font-family:'Inter',sans-serif}
.btn-dl:hover{border-color:var(--cyan);color:var(--cyan)}

/* ── Findings Table ──────────────────────────────────────────── */
.tbl-wrap{overflow-x:auto;border-radius:14px;border:1px solid var(--border);margin-top:.5rem}
table{width:100%;border-collapse:collapse;background:var(--card);font-size:.8rem}
thead{background:rgba(99,179,237,.06)}
thead th{padding:.85rem 1rem;text-align:left;font-size:.62rem;font-weight:800;
  text-transform:uppercase;letter-spacing:.1em;color:var(--text3);white-space:nowrap;
  border-bottom:1px solid var(--border)}
tbody td{padding:.8rem 1rem;border-bottom:1px solid var(--border);vertical-align:middle;
  color:var(--text)}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover td{background:rgba(99,179,237,.04)!important}
.rc{background:rgba(239,68,68,.07)}
.rh{background:rgba(249,115,22,.06)}
.rm{background:rgba(234,179,8,.06)}
.rl{background:rgba(34,197,94,.05)}
.badge{display:inline-flex;align-items:center;gap:.3rem;padding:.22rem .7rem;
  border-radius:99px;font-size:.65rem;font-weight:800;text-transform:uppercase;letter-spacing:.07em;white-space:nowrap}
.badge::before{content:'●';font-size:.5rem}
.b-critical{background:rgba(239,68,68,.15);color:#f87171;border:1px solid rgba(239,68,68,.3)}
.b-high{background:rgba(249,115,22,.15);color:#fb923c;border:1px solid rgba(249,115,22,.3)}
.b-medium{background:rgba(234,179,8,.15);color:#fde047;border:1px solid rgba(234,179,8,.3)}
.b-low{background:rgba(34,197,94,.15);color:#4ade80;border:1px solid rgba(34,197,94,.3)}
.mono{font-family:'JetBrains Mono',monospace;font-size:.73rem;
  background:rgba(255,255,255,.05);border:1px solid var(--border);
  border-radius:5px;padding:.15rem .4rem;color:var(--cyan);word-break:break-word;
  display:inline-block;max-width:180px}
.risk-wrap{display:flex;align-items:center;gap:.5rem;min-width:100px}
.risk-num{font-family:'JetBrains Mono',monospace;font-weight:800;font-size:.84rem;min-width:28px;text-align:right}
.risk-track{flex:1;height:5px;background:var(--border);border-radius:99px;overflow:hidden;min-width:45px}
.risk-fill{height:100%;border-radius:99px}

/* -- Attack Map ------------------------------------------------------ */
.map-section{margin-bottom:2rem}
.map-section-label{font-size:.68rem;font-weight:800;text-transform:uppercase;
  letter-spacing:.12em;color:var(--text3);margin:2rem 0 1rem;
  display:flex;align-items:center;gap:.6rem}
.map-section-label::after{content:'';flex:1;height:1px;background:var(--border)}
.map-outer{background:var(--card);border:1px solid var(--border);border-radius:20px;
  padding:1.5rem;box-shadow:var(--shadow)}
.map-status-row{display:flex;align-items:center;justify-content:space-between;
  margin-bottom:1rem;gap:1rem;flex-wrap:wrap}
.map-badge{display:inline-block;padding:4px 16px;border-radius:999px;font-size:.72rem;
  font-weight:700;letter-spacing:.05em;text-transform:uppercase;
  background:rgba(99,179,237,.1);border:1px solid rgba(99,179,237,.3);color:var(--cyan);
  transition:all .5s}
.map-badge.scanning{background:rgba(251,146,60,.1);border-color:rgba(251,146,60,.4);color:#fb923c}
.map-badge.done{background:rgba(74,222,128,.1);border-color:rgba(74,222,128,.4);color:#4ade80}
.map-target-url{font-size:.72rem;color:var(--text2);font-family:'JetBrains Mono',monospace;opacity:.7}
.map-wrap{position:relative;width:100%;max-width:460px;height:460px;margin:0 auto}
.map-wrap svg{position:absolute;inset:0;width:100%;height:100%;pointer-events:none;z-index:0}
.map-center{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
  width:82px;height:82px;background:linear-gradient(135deg,#1e2140,#2a2f5e);
  border:2px solid rgba(99,179,237,.55);border-radius:50%;
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  font-size:.62rem;font-weight:700;color:var(--cyan);letter-spacing:.08em;
  text-transform:uppercase;z-index:2;box-shadow:0 0 20px rgba(99,179,237,.2),0 0 0 5px rgba(99,179,237,.06)}
.map-center .mc-icon{font-size:1.3rem;margin-bottom:2px}
.map-cat{position:absolute;width:82px;height:82px;border-radius:50%;
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  font-size:.52rem;font-weight:600;text-align:center;padding:5px;
  line-height:1.3;z-index:2;transform:translate(-50%,-50%);
  transition:background .5s,border-color .5s,box-shadow .5s}
.map-cat.pending{background:#1a1f35;border:2px solid rgba(136,146,176,.3);color:#8892b0}
.map-cat.testing{background:rgba(251,146,60,.14);border:2px solid #fb923c;color:#fb923c;
  animation:map-pulse 1.1s ease-in-out infinite}
.map-cat.safe{background:rgba(74,222,128,.12);border:2px solid #4ade80;color:#4ade80;
  box-shadow:0 0 14px rgba(74,222,128,.25)}
.map-cat.vulnerable{background:rgba(248,113,113,.14);border:2px solid #f87171;color:#f87171;
  box-shadow:0 0 18px rgba(248,113,113,.35)}
@keyframes map-pulse{
  0%{box-shadow:0 0 8px rgba(251,146,60,.3)}
  50%{box-shadow:0 0 24px rgba(251,146,60,.65)}
  100%{box-shadow:0 0 8px rgba(251,146,60,.3)}}
.map-cat-icon{font-size:.95rem;margin-bottom:1px}
.map-cat-name{max-width:68px;word-break:break-word;text-align:center}
.map-cat-count{font-size:.55rem;font-weight:700;margin-top:3px;opacity:.9;line-height:1.3}
.map-ct-safe{color:#4ade80}
.map-ct-vuln{color:#f87171}
.map-prog-track{height:8px;background:var(--border);border-radius:999px;
  overflow:hidden;margin-top:1.2rem;border:1px solid var(--border)}
.map-prog-fill{height:100%;background:linear-gradient(90deg,var(--cyan),var(--purple));
  border-radius:999px;transition:width .6s cubic-bezier(.4,0,.2,1);width:0%}
.map-prog-label{display:flex;justify-content:space-between;font-size:.72rem;
  color:var(--text2);margin-top:.5rem}
.map-done-banner{display:none;margin-top:1rem;padding:12px 20px;border-radius:12px;
  background:rgba(74,222,128,.1);border:1px solid rgba(74,222,128,.3);
  color:#4ade80;font-size:.88rem;font-weight:700;text-align:center;
  animation:map-celebrate .6s cubic-bezier(.4,0,.2,1)}
@keyframes map-celebrate{
  0%{transform:scale(.88);opacity:0}70%{transform:scale(1.03)}100%{transform:scale(1);opacity:1}}
.map-legend{display:flex;gap:14px;flex-wrap:wrap;justify-content:center;
  margin-top:1rem;font-size:.7rem;color:var(--text2)}
.map-legend-item{display:flex;align-items:center;gap:5px}
.map-legend-dot{width:10px;height:10px;border-radius:50%;border:2px solid;flex-shrink:0}
.map-legend-dot.pending{background:#1a1f35;border-color:rgba(136,146,176,.4)}
.map-legend-dot.testing{background:rgba(251,146,60,.14);border-color:#fb923c}
.map-legend-dot.safe{background:rgba(74,222,128,.12);border-color:#4ade80}
.map-legend-dot.vulnerable{background:rgba(248,113,113,.14);border-color:#f87171}

/* -- Empty state ---------------------------------------------------- */
.no-findings{background:var(--card);border:1px solid rgba(34,197,94,.3);border-radius:14px;
  padding:3rem 2rem;text-align:center;color:var(--green);font-weight:600}

/* ── Scrollbar ───────────────────────────────────────────────── */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:99px}

@media(max-width:640px){
  .form-grid{grid-template-columns:1fr}
  .form-group.full{grid-column:1}
  .hero h1{font-size:1.6rem}
}
</style>
</head>
<body>

<!-- ══ NAVBAR ════════════════════════════════════════ -->
<nav class="nav">
  <div class="nav-brand">
    <div class="shield">🛡</div>
    LLM Scanner
  </div>
  <div class="nav-right">
    <span class="nav-badge">Web Dashboard</span>
    <div class="toggle" id="themeToggle">
      <span class="toggle-icon">🌙</span>
      <div class="toggle-track"><div class="toggle-knob"></div></div>
      <span class="toggle-icon">☀️</span>
    </div>
  </div>
</nav>

<!-- ══ MAIN ══════════════════════════════════════════ -->
<div class="main">

  <!-- Hero -->
  <div class="hero">
    <h1>AI Security Scanner</h1>
    <p>Enter your target URL and API key — run a full OWASP LLM Top 10 scan right here in the browser.</p>
  </div>

  <!-- Scan Form -->
  <div class="form-card">
    <div class="form-title">Scan Configuration</div>
    <div class="form-grid">
      <div class="form-group">
        <label>TARGET URL</label>
        <input type="text" id="targetUrl" placeholder="http://localhost:5000" value="http://localhost:5000"/>
      </div>
      <div class="form-group">
        <label>API KEY</label>
        <input type="text" id="apiKey" placeholder="demo123" value="demo123"/>
      </div>
      <div class="form-group">
        <label>ENDPOINT PATH</label>
        <input type="text" id="endpoint" placeholder="/chat" value="/chat"/>
      </div>
      <div class="form-group">
        <label>RATE LIMIT (seconds between requests)</label>
        <div class="slider-row">
          <input type="range" id="rateLimit" min="0" max="3" step="0.5" value="0.5"
            oninput="document.getElementById('rateVal').textContent=this.value+'s'"/>
          <span class="slider-val" id="rateVal">0.5s</span>
        </div>
      </div>
      <div class="form-group full">
        <label>PAYLOAD CATEGORIES (all selected by default)</label>
        <div class="cats" id="catChips">
          <label class="cat-chip active" data-val="prompt_injection">
            <span class="cat-dot"></span> Prompt Injection
          </label>
          <label class="cat-chip active" data-val="jailbreak">
            <span class="cat-dot"></span> Jailbreak
          </label>
          <label class="cat-chip active" data-val="data_leakage">
            <span class="cat-dot"></span> Data Leakage
          </label>
          <label class="cat-chip active" data-val="output_handling">
            <span class="cat-dot"></span> Output Handling
          </label>
          <label class="cat-chip active" data-val="excessive_agency">
            <span class="cat-dot"></span> Excessive Agency
          </label>
          <label class="cat-chip active" data-val="overreliance">
            <span class="cat-dot"></span> Overreliance
          </label>
          <label class="cat-chip active" data-val="model_theft_leak">
            <span class="cat-dot"></span> Model Theft
          </label>
          <label class="cat-chip active" data-val="model_dos">
            <span class="cat-dot"></span> Model DoS
          </label>
          <label class="cat-chip active" data-val="insecure_plugin_design">
            <span class="cat-dot"></span> Insecure Plugin Design
          </label>
        </div>
      </div>
    </div>
    <div class="btn-row">
      <button class="btn btn-primary" id="btnScan" onclick="startScan()">▶ Run Scan</button>
      <button class="btn btn-danger" id="btnStop" onclick="stopScan()">■ Stop</button>
    </div>
  </div>

  <!-- Status Bar -->
  <div class="status-bar" id="statusBar">
    <div class="status-dot"></div>
    <span class="status-text" id="statusText">Initialising scan…</span>
    <span class="status-count" id="statusCount"></span>
  </div>

  <!-- Progress -->
  <div class="progress-wrap" id="progressWrap">
    <div class="progress-label">
      <span id="progressLabel">Progress</span>
      <span id="progressPct">0%</span>
    </div>
    <div class="progress-track"><div class="progress-fill" id="progressFill"></div></div>
  </div>

  <!-- Terminal -->
  <div class="terminal-wrap" id="termWrap">
    <div class="terminal-header">
      <div class="terminal-dots">
        <span class="dot-red"></span><span class="dot-yellow"></span><span class="dot-green"></span>
      </div>
      <span class="terminal-title">scan output</span>
      <button class="terminal-clear" onclick="clearTerminal()">clear</button>
    </div>
    <div class="terminal" id="terminal"></div>
  </div>

  <!-- Attack Map -->
  <div class="map-section" id="mapSection">
    <div class="map-section-label">&#x1F5FA;&#xFE0F; Live Attack Map</div>
    <div class="map-outer">
      <div class="map-status-row">
        <span class="map-badge" id="mapBadge">Idle</span>
        <span class="map-target-url" id="mapTargetUrl"></span>
      </div>
      <div class="map-wrap" id="mapWrap">
        <svg id="mapSvg"></svg>
        <div class="map-center" id="mapCenter">
          <span class="mc-icon">&#x1F3AF;</span>TARGET
        </div>
      </div>
      <div class="map-prog-track"><div class="map-prog-fill" id="mapProgFill"></div></div>
      <div class="map-prog-label">
        <span>Payloads tested</span>
        <span id="mapProgText">0 / 0</span>
      </div>
      <div class="map-done-banner" id="mapDoneBanner">&#x2705; Scan complete! All payloads tested.</div>
      <div class="map-legend">
        <div class="map-legend-item"><div class="map-legend-dot pending"></div>Pending</div>
        <div class="map-legend-item"><div class="map-legend-dot testing"></div>Testing</div>
        <div class="map-legend-item"><div class="map-legend-dot safe"></div>Safe</div>
        <div class="map-legend-item"><div class="map-legend-dot vulnerable"></div>Vulnerable</div>
      </div>
    </div>
  </div>

  <!-- Results -->
  <div class="results-section" id="resultsSection">
    <div class="section-label">Scan Results</div>
    <div class="cards" id="summaryCards"></div>
    <div class="dl-bar" id="dlBar"></div>
    <div class="section-label">Detailed Findings</div>
    <div id="findingsWrap"></div>
  </div>

</div><!-- /main -->

<script>
const html = document.documentElement;
let eventSource = null;
let currentScanId = null;
let totalPayloads = 0;
let donePayloads  = 0;

// -- Attack Map state --
let _mapPollTimer = null;
let _mapNodes     = {};
let _mapCatOrder  = [];
let _mapDone      = false;

function _stateIcon(s){
  return {pending:'\u23F3',testing:'\u26A1',safe:'\u2705',vulnerable:'\u26A0\uFE0F'}[s]||'';
}
function _escHtml(str){
  return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function _shortCat(cat){
  return cat.replace(/OWASP LLM\\d*[:\\s]*/i,'').trim().substring(0,48);
}

function _buildMap(cats){
  const wrap = document.getElementById('mapWrap');
  const svg  = document.getElementById('mapSvg');
  _mapCatOrder = cats; _mapNodes = {};
  wrap.querySelectorAll('.map-cat').forEach(n=>n.remove());
  svg.innerHTML='';
  const cx=50,cy=50,r=38;
  cats.forEach((cat,i)=>{
    const angle=(2*Math.PI*i/cats.length)-(Math.PI/2);
    const px=cx+r*Math.cos(angle), py=cy+r*Math.sin(angle);
    const line=document.createElementNS('http://www.w3.org/2000/svg','line');
    line.setAttribute('x1',cx+'%');line.setAttribute('y1',cy+'%');
    line.setAttribute('x2',px+'%');line.setAttribute('y2',py+'%');
    line.setAttribute('stroke','rgba(99,179,237,0.15)');
    line.setAttribute('stroke-width','1.5');
    line.setAttribute('stroke-dasharray','4 4');
    svg.appendChild(line);
    const node=document.createElement('div');
    node.className='map-cat pending';
    node.style.left=px+'%'; node.style.top=py+'%';
    node.innerHTML=`<span class="map-cat-icon">${_stateIcon('pending')}</span>`+
      `<span class="map-cat-name">${_escHtml(_shortCat(cat))}</span>`+
      `<span class="map-cat-count">waiting</span>`;
    wrap.appendChild(node);
    _mapNodes[cat]=node;
  });
}

function _mapCountHtml(data){
  const s=data.safe_count||0, v=data.findings||0, t=data.tested||0;
  if(t===0) return 'waiting';
  let parts=[];
  if(s>0) parts.push(`<span class="map-ct-safe">\u2705 ${s} safe</span>`);
  if(v>0) parts.push(`<span class="map-ct-vuln">\u26A0\uFE0F ${v} vuln</span>`);
  if(!parts.length) return `${t} tested`;
  return parts.join(' \u00B7 ');
}

function _updateMapNode(cat,data){
  const node=_mapNodes[cat]; if(!node)return;
  node.className='map-cat '+data.state;
  node.innerHTML=`<span class="map-cat-icon">${_stateIcon(data.state)}</span>`+
    `<span class="map-cat-name">${_escHtml(_shortCat(cat))}</span>`+
    `<span class="map-cat-count">${_mapCountHtml(data)}</span>`;
}

function _applyMapStatus(s){
  const cats=Object.keys(s.categories||{});
  if(!_mapCatOrder.length||cats.join()!==_mapCatOrder.join()) _buildMap(cats);
  cats.forEach(c=>_updateMapNode(c,s.categories[c]));
  const prog=s.overall_progress||{tested:0,total:0};
  const pct=prog.total>0?Math.round(100*prog.tested/prog.total):0;
  document.getElementById('mapProgFill').style.width=pct+'%';
  document.getElementById('mapProgText').textContent=prog.tested+' / '+prog.total;
  document.getElementById('mapTargetUrl').textContent=s.target_url||'';
  const badge=document.getElementById('mapBadge');
  if(s.finished && !s.initializing){
    badge.textContent='Scan complete'; badge.className='map-badge done';
    if(!_mapDone){
      _mapDone=true;
      document.getElementById('mapDoneBanner').style.display='block';
    }
  } else if(prog.tested>0||cats.some(c=>s.categories[c].state!=='pending')){
    badge.textContent='Scanning\u2026'; badge.className='map-badge scanning';
  } else {
    badge.textContent='Initialising\u2026'; badge.className='map-badge';
  }
}

async function _pollMap(){
  try{
    const r=await fetch('/api/live-status?t='+Date.now(),{cache:'no-store'});
    if(r.ok){
      const d=await r.json();
      // Ignore error responses (no scan running yet) or stale finished data
      // that belongs to a previous scan (detected by "initializing" flag or
      // empty categories while we are expecting a live scan).
      if(!d.error && !(d.finished && d.initializing)){
        _applyMapStatus(d);
      }
    }
  }catch(_){}
  if(!_mapDone) _mapPollTimer=setTimeout(_pollMap,1000);
}

function _startMapPolling(){
  _mapDone=false; _mapCatOrder=[]; _mapNodes={};
  document.getElementById('mapDoneBanner').style.display='none';
  document.getElementById('mapProgFill').style.width='0%';
  document.getElementById('mapProgText').textContent='0 / 0';
  document.getElementById('mapSvg').innerHTML='';
  document.getElementById('mapWrap').querySelectorAll('.map-cat').forEach(n=>n.remove());
  document.getElementById('mapBadge').textContent='Initialising\u2026';
  document.getElementById('mapBadge').className='map-badge';
  document.getElementById('mapTargetUrl').textContent='';
  if(_mapPollTimer){clearTimeout(_mapPollTimer);_mapPollTimer=null;}
  _mapPollTimer=setTimeout(_pollMap,800);
}

function _stopMapPolling(){
  if(_mapPollTimer){clearTimeout(_mapPollTimer);_mapPollTimer=null;}
}

// ── Theme toggle ─────────────────────────────────────────────
const saved = localStorage.getItem('llmscanner-theme');
if (saved) html.setAttribute('data-theme', saved);
document.getElementById('themeToggle').addEventListener('click', () => {
  const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('llmscanner-theme', next);
});

// ── Category chips ────────────────────────────────────────────
document.querySelectorAll('.cat-chip').forEach(chip => {
  chip.addEventListener('click', () => chip.classList.toggle('active'));
});

function getSelectedCats() {
  return [...document.querySelectorAll('.cat-chip.active')].map(c => c.dataset.val);
}

// ── Terminal helpers ──────────────────────────────────────────
function term(msg, cls='t-white') {
  const el = document.getElementById('terminal');
  el.innerHTML += `<div class="${cls}">${msg}</div>`;
  el.scrollTop = el.scrollHeight;
}
function clearTerminal() { document.getElementById('terminal').innerHTML = ''; }

// ── Progress helpers ──────────────────────────────────────────
function setProgress(done, total) {
  const pct = total > 0 ? Math.round((done/total)*100) : 0;
  document.getElementById('progressFill').style.width = pct + '%';
  document.getElementById('progressPct').textContent  = pct + '%';
  document.getElementById('progressLabel').textContent = `Payload ${done} of ${total}`;
}

// ── Start Scan ────────────────────────────────────────────────
async function startScan() {
  const url      = document.getElementById('targetUrl').value.trim();
  const apikey   = document.getElementById('apiKey').value.trim();
  const endpoint = document.getElementById('endpoint').value.trim() || '/chat';
  const rate     = parseFloat(document.getElementById('rateLimit').value);
  const cats     = getSelectedCats();

  if (!url)    { alert('Please enter a target URL.'); return; }
  if (!apikey) { alert('Please enter an API key.');    return; }

  // Reset UI
  document.getElementById('btnScan').disabled = true;
  document.getElementById('btnStop').style.display = 'inline-block';
  document.getElementById('statusBar').style.display  = 'flex';
  document.getElementById('progressWrap').style.display = 'block';
  document.getElementById('termWrap').style.display = 'block';
  document.getElementById('resultsSection').style.display = 'none';
  clearTerminal();
  donePayloads = 0; totalPayloads = 0;
  setProgress(0, 1);
  _startMapPolling();

  document.getElementById('statusText').textContent = 'Starting scan…';
  document.getElementById('statusCount').textContent = '';

  term('▶  Scan started', 't-cyan');
  term(`   Target  : ${url}${endpoint}`, 't-dim');
  term(`   API Key : ${'*'.repeat(Math.min(8, apikey.length))}`, 't-dim');
  term(`   Cats    : ${cats.length ? cats.join(', ') : 'all'}`, 't-dim');
  term('─'.repeat(52), 't-dim');

  // POST to /api/scan
  let scanId;
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url, apikey, endpoint, rate_limit: rate,
                            categories: cats.length ? cats : null})
    });
    const data = await res.json();
    if (!res.ok) { term('✖  ' + (data.error || 'Failed to start scan'), 't-red'); resetUI(); return; }
    scanId = data.scan_id;
    currentScanId = scanId;
  } catch(e) {
    term('✖  Could not connect to scanner server: ' + e.message, 't-red');
    resetUI(); return;
  }

  // Open SSE stream
  eventSource = new EventSource(`/api/scan/stream/${scanId}`);

  eventSource.onmessage = (e) => {
    const msg = JSON.parse(e.data);

    if (msg.type === 'total') {
      totalPayloads = msg.value;
      term(`   Total payloads : ${totalPayloads}`, 't-dim');
      term('─'.repeat(52), 't-dim');
    }
    else if (msg.type === 'progress') {
      donePayloads++;
      setProgress(donePayloads, totalPayloads);
      document.getElementById('statusText').textContent  = `Testing: ${msg.name}`;
      document.getElementById('statusCount').textContent = `${donePayloads}/${totalPayloads}`;
      term(`[${donePayloads}/${totalPayloads}] ${msg.id}: ${msg.name}`, 't-cyan');
    }
    else if (msg.type === 'finding') {
      term(`  ⚠  ${msg.tag} | ${msg.severity.toUpperCase()} | Risk ${msg.risk}/100`, 't-red');
      term(`     matched: "${msg.matched}"`, 't-yellow');
    }
    else if (msg.type === 'ok') {
      term(`  ✓  No vulnerability detected`, 't-green');
    }
    else if (msg.type === 'error') {
      term(`  ✖  ${msg.message}`, 't-red');
    }
    else if (msg.type === 'done') {
      term('─'.repeat(52), 't-dim');
      term(`✔  Scan complete — ${msg.total_findings} finding(s) | Avg risk: ${msg.avg_risk}/100`, 't-green');
      document.getElementById('statusText').textContent = 'Scan complete';
      document.getElementById('statusDot') && (document.querySelector('.status-dot').style.animation = 'none');
      eventSource.close();
      loadResults(scanId);
      resetUI(false);
    }
  };

  eventSource.onerror = () => {
    term('✖  Stream connection lost.', 't-red');
    eventSource.close();
    resetUI();
  };
}

// ── Stop scan ─────────────────────────────────────────────────
function stopScan() {
  if (eventSource) { eventSource.close(); eventSource = null; }
  term('■  Scan stopped by user.', 't-yellow');
  resetUI();
}

function resetUI(fully=true) {
  document.getElementById('btnScan').disabled = false;
  document.getElementById('btnStop').style.display = 'none';
  if (fully) {
    document.getElementById('statusBar').style.display = 'none';
    document.getElementById('progressWrap').style.display = 'none';
  }
}

// ── Load Results ──────────────────────────────────────────────
async function loadResults(scanId) {
  const res  = await fetch(`/api/scan/result/${scanId}`);
  const data = await res.json();
  if (!data.result) return;

  const r   = data.result;
  const sum = r.summary || {};
  const sev = sum.by_severity || {};

  // Summary cards
  document.getElementById('summaryCards').innerHTML = `
    <div class="card c-total"><div class="card-lbl">Total Findings</div><div class="card-val">${sum.total_findings||0}</div><div class="card-sub">vulnerabilities</div></div>
    <div class="card c-crit"><div class="card-lbl">Critical</div><div class="card-val">${sev.critical||0}</div><div class="card-sub">immediate</div></div>
    <div class="card c-high"><div class="card-lbl">High</div><div class="card-val">${sev.high||0}</div><div class="card-sub">urgent</div></div>
    <div class="card c-med"><div class="card-lbl">Medium</div><div class="card-val">${sev.medium||0}</div><div class="card-sub">review</div></div>
    <div class="card c-low"><div class="card-lbl">Low</div><div class="card-val">${sev.low||0}</div><div class="card-sub">monitor</div></div>
    <div class="card c-risk"><div class="card-lbl">Avg Risk</div><div class="card-val">${sum.average_risk_score||0}<small style="font-size:.9rem;opacity:.5">/100</small></div><div class="card-sub">score</div></div>
  `;

  // Download bar
  const jname = data.json_file, hname = data.html_file;
  document.getElementById('dlBar').innerHTML = `
    ${jname ? `<a class="btn-dl" href="/reports/${jname}" download>⬇ JSON Report</a>` : ''}
    ${hname ? `<a class="btn-dl" href="/reports/${hname}" target="_blank">↗ Open HTML Report</a>` : ''}
  `;

  // Findings table
  const findings = (r.findings || []).sort((a,b) => b.risk_score - a.risk_score);
  if (!findings.length) {
    document.getElementById('findingsWrap').innerHTML =
      '<div class="no-findings">✅ No vulnerabilities detected.</div>';
  } else {
    const rows = findings.map((f,i) => {
      const sev = (f.severity||'unknown').toLowerCase();
      const rc  = {critical:'rc',high:'rh',medium:'rm',low:'rl'}[sev]||'';
      const rs  = parseFloat(f.risk_score||0);
      const col = rs>=80?'#f87171':rs>=60?'#fb923c':rs>=40?'#facc15':'#4ade80';
      return `<tr class="${rc}">
        <td style="color:var(--text3);font-family:'JetBrains Mono',monospace;font-size:.72rem">${i+1}</td>
        <td><span class="mono">${esc(f.id)}</span></td>
        <td style="font-weight:600;white-space:nowrap">${esc(f.name)}</td>
        <td style="color:var(--text2);font-size:.78rem">${esc(f.category)}</td>
        <td><span class="badge b-${esc(sev)}">${esc(f.severity)}</span></td>
        <td><div class="risk-wrap">
          <span class="risk-num" style="color:${col}">${Math.round(rs)}</span>
          <div class="risk-track"><div class="risk-fill" style="width:${rs}%;background:${col}"></div></div>
        </div></td>
        <td style="font-family:'JetBrains Mono',monospace;font-size:.75rem;color:var(--text2)">${Math.round((f.confidence||0)*100)}%</td>
        <td><span class="mono">${esc(f.detected_tag)}</span></td>
        <td><span class="mono">${esc(f.matched_text)}</span></td>
      </tr>`;
    }).join('');
    document.getElementById('findingsWrap').innerHTML = `
      <div class="tbl-wrap"><table>
        <thead><tr>
          <th>#</th><th>ID</th><th>Name</th><th>Category</th>
          <th>Severity</th><th>Risk Score</th><th>Confidence</th>
          <th>Detected Tag</th><th>Matched Text</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table></div>`;
  }

  document.getElementById('resultsSection').style.display = 'block';
}

function esc(str) {
  return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
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

    with _store_lock:
        _scan_store[scan_id] = {
            "status":    "running",
            "queue":     q,
            "result":    None,
            "json_file": None,
            "html_file": None,
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
            "started_at":       datetime.utcnow().isoformat() + "Z",
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
        args=(scan_id, url, endpoint, apikey, rate_limit, categories),
        daemon=True,
    )
    thread.start()
    return jsonify({"scan_id": scan_id})


def _run_scan_thread(scan_id, url, endpoint, apikey, rate_limit, categories):
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
                    raw_findings = detect_vulnerabilities(payload, reply)

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


@app.route("/reports/<path:filename>")
def serve_report(filename):
    """Serve files from the reports/ directory (download or view)."""
    return send_from_directory(REPORTS_DIR, filename)


# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Entry point for the 'llm-scanner-web' pip command."""
    import webbrowser
    import threading
    print("\n  [*] LLM Scanner Web Dashboard")
    print("  -------------------------------------")
    print("  Open in browser:  http://localhost:8080\n")
    threading.Timer(1.5, lambda: webbrowser.open("http://localhost:8080")).start()
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)


if __name__ == "__main__":
    main()
