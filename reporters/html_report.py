"""
HTML reporter module.
Generates a polished, self-contained HTML security scan report from scan result data.

Design goals:
  - Zero external dependencies at render time (all CSS/JS inline)
  - Dark mode / Light mode toggle with smooth CSS transition
  - Google Fonts loaded via single <link> tag (graceful offline fallback)
  - Safe output: Jinja2 autoescape=True prevents AI response content
    (matched_text, prompt_sent) from injecting HTML into the report layout
  - Findings table sorted by risk_score descending
  - Glassmorphism cards, animated risk bars, modern badge design
"""

import os
from typing import Any, Dict

from jinja2 import Environment, BaseLoader


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>LLM Security Scan Report</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    /* ── CSS Variables — Dark & Light themes ─────────────────────── */
    :root[data-theme="dark"] {
      --bg-primary:    #0b0d17;
      --bg-secondary:  #111322;
      --bg-card:       rgba(255,255,255,0.04);
      --bg-card-hover: rgba(255,255,255,0.07);
      --border:        rgba(255,255,255,0.08);
      --border-accent: rgba(99,179,237,0.3);
      --text-primary:  #e8eaf6;
      --text-secondary:#8892b0;
      --text-muted:    #4a5568;
      --accent-cyan:   #63b3ed;
      --accent-purple: #9f7aea;
      --header-bg:     linear-gradient(135deg,#0d1b3e 0%,#0b0d17 60%,#1a0533 100%);
      --nav-bg:        rgba(11,13,23,0.95);
      --shadow:        0 8px 32px rgba(0,0,0,0.5);
      --shadow-card:   0 4px 20px rgba(0,0,0,0.4);
      --toggle-bg:     #1e2235;
      --toggle-knob:   #63b3ed;
      --table-header:  rgba(99,179,237,0.08);
      --table-row-alt: rgba(255,255,255,0.02);
      --mono-bg:       rgba(255,255,255,0.06);
      --mono-border:   rgba(255,255,255,0.1);
      --row-critical:  rgba(239,68,68,0.07);
      --row-high:      rgba(249,115,22,0.06);
      --row-medium:    rgba(234,179,8,0.06);
      --row-low:       rgba(34,197,94,0.05);
      --pill-bg:       rgba(99,179,237,0.1);
      --pill-border:   rgba(99,179,237,0.25);
    }
    :root[data-theme="light"] {
      --bg-primary:    #f0f4ff;
      --bg-secondary:  #ffffff;
      --bg-card:       #ffffff;
      --bg-card-hover: #f8faff;
      --border:        #e2e8f0;
      --border-accent: #93c5fd;
      --text-primary:  #1e293b;
      --text-secondary:#475569;
      --text-muted:    #94a3b8;
      --accent-cyan:   #2563eb;
      --accent-purple: #7c3aed;
      --header-bg:     linear-gradient(135deg,#1e3a8a 0%,#1e40af 60%,#4c1d95 100%);
      --nav-bg:        rgba(255,255,255,0.97);
      --shadow:        0 8px 32px rgba(0,0,0,0.12);
      --shadow-card:   0 4px 20px rgba(0,0,0,0.08);
      --toggle-bg:     #e2e8f0;
      --toggle-knob:   #2563eb;
      --table-header:  #f1f5ff;
      --table-row-alt: #fafbff;
      --mono-bg:       #f1f5f9;
      --mono-border:   #e2e8f0;
      --row-critical:  #fff5f5;
      --row-high:      #fff7ed;
      --row-medium:    #fefce8;
      --row-low:       #f0fdf4;
      --pill-bg:       #eff6ff;
      --pill-border:   #bfdbfe;
    }

    /* ── Reset & Base ────────────────────────────────────────────── */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 14px;
      line-height: 1.6;
      background: var(--bg-primary);
      color: var(--text-primary);
      transition: background 0.3s ease, color 0.3s ease;
      min-height: 100vh;
    }
    ::selection { background: var(--accent-cyan); color: #fff; }

    /* ── Top Navigation Bar ──────────────────────────────────────── */
    .navbar {
      position: sticky;
      top: 0;
      z-index: 100;
      background: var(--nav-bg);
      border-bottom: 1px solid var(--border);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      padding: 0 2rem;
      height: 60px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: var(--shadow);
      transition: background 0.3s ease;
    }
    .navbar-brand {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      font-weight: 800;
      font-size: 1.05rem;
      color: var(--text-primary);
      letter-spacing: -0.02em;
    }
    .navbar-brand .shield {
      width: 32px; height: 32px;
      background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      font-size: 1rem;
      box-shadow: 0 0 16px rgba(99,179,237,0.4);
    }
    .navbar-brand .version {
      font-size: 0.68rem;
      font-weight: 500;
      color: var(--text-muted);
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 99px;
      padding: 0.1rem 0.5rem;
    }
    .navbar-right { display: flex; align-items: center; gap: 1rem; }
    .navbar-badge {
      font-size: 0.72rem;
      font-weight: 600;
      color: var(--text-secondary);
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 99px;
      padding: 0.25rem 0.8rem;
    }

    /* ── Dark/Light Mode Toggle ──────────────────────────────────── */
    .theme-toggle {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      cursor: pointer;
      user-select: none;
    }
    .theme-toggle .icon { font-size: 0.9rem; color: var(--text-secondary); }
    .toggle-track {
      width: 44px; height: 24px;
      background: var(--toggle-bg);
      border-radius: 99px;
      border: 1px solid var(--border);
      position: relative;
      transition: background 0.3s ease;
      cursor: pointer;
    }
    .toggle-knob {
      position: absolute;
      top: 3px; left: 3px;
      width: 16px; height: 16px;
      background: var(--toggle-knob);
      border-radius: 50%;
      transition: transform 0.3s cubic-bezier(.68,-.55,.27,1.55), background 0.3s ease;
      box-shadow: 0 0 8px rgba(99,179,237,0.6);
    }
    [data-theme="light"] .toggle-knob { transform: translateX(20px); }

    /* ── Hero Header ─────────────────────────────────────────────── */
    .hero {
      background: var(--header-bg);
      padding: 3rem 2.5rem 2.5rem;
      position: relative;
      overflow: hidden;
    }
    .hero::before {
      content: '';
      position: absolute; inset: 0;
      background-image:
        radial-gradient(circle at 20% 50%, rgba(99,179,237,0.08) 0%, transparent 50%),
        radial-gradient(circle at 80% 20%, rgba(159,122,234,0.08) 0%, transparent 50%);
      pointer-events: none;
    }
    .hero::after {
      content: '';
      position: absolute; inset: 0;
      background-image: repeating-linear-gradient(
        0deg, transparent, transparent 39px, rgba(255,255,255,0.02) 39px, rgba(255,255,255,0.02) 40px
      ), repeating-linear-gradient(
        90deg, transparent, transparent 39px, rgba(255,255,255,0.02) 39px, rgba(255,255,255,0.02) 40px
      );
      pointer-events: none;
    }
    .hero-content { position: relative; z-index: 1; max-width: 1300px; margin: 0 auto; }
    .hero-title {
      font-size: 2rem;
      font-weight: 900;
      color: #fff;
      letter-spacing: -0.03em;
      margin-bottom: 0.5rem;
      display: flex;
      align-items: center;
      gap: 0.7rem;
    }
    .hero-title .title-icon {
      background: rgba(255,255,255,0.1);
      border: 1px solid rgba(255,255,255,0.15);
      border-radius: 12px;
      padding: 0.35rem 0.5rem;
      font-size: 1.4rem;
      backdrop-filter: blur(10px);
    }
    .hero-subtitle {
      font-size: 0.85rem;
      color: rgba(255,255,255,0.55);
      font-weight: 400;
      margin-bottom: 2rem;
      letter-spacing: 0.02em;
    }
    .hero-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
    }
    .hero-meta-item {
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 10px;
      padding: 0.7rem 1.1rem;
      backdrop-filter: blur(10px);
      min-width: 160px;
    }
    .hero-meta-label {
      font-size: 0.62rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: rgba(255,255,255,0.4);
      font-weight: 600;
      margin-bottom: 0.2rem;
    }
    .hero-meta-value {
      font-size: 0.92rem;
      font-weight: 600;
      color: rgba(255,255,255,0.9);
      word-break: break-all;
    }

    /* ── Main Content ────────────────────────────────────────────── */
    .content { max-width: 1300px; margin: 0 auto; padding: 2.5rem 2.5rem 4rem; }

    /* ── Section Title ───────────────────────────────────────────── */
    .section-label {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      font-size: 0.68rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: var(--text-muted);
      margin: 2.5rem 0 1rem;
    }
    .section-label::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border);
    }

    /* ── Summary Cards Grid ──────────────────────────────────────── */
    .cards-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
    }
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 1.3rem 1.4rem;
      box-shadow: var(--shadow-card);
      transition: background 0.2s ease, transform 0.2s ease, box-shadow 0.2s ease;
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      border-radius: 16px 16px 0 0;
    }
    .card:hover {
      background: var(--bg-card-hover);
      transform: translateY(-2px);
      box-shadow: 0 8px 30px rgba(0,0,0,0.3);
    }
    .card-label {
      font-size: 0.65rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--text-muted);
      font-weight: 700;
      margin-bottom: 0.5rem;
    }
    .card-value {
      font-size: 2.2rem;
      font-weight: 900;
      line-height: 1;
      letter-spacing: -0.03em;
    }
    .card-sub { font-size: 0.72rem; color: var(--text-muted); margin-top: 0.25rem; }

    .card.total::before   { background: linear-gradient(90deg,#3b82f6,#6366f1); }
    .card.total .card-value { color: #60a5fa; }
    .card.critical::before{ background: linear-gradient(90deg,#ef4444,#dc2626); }
    .card.critical .card-value { color: #f87171; }
    .card.high::before    { background: linear-gradient(90deg,#f97316,#ea580c); }
    .card.high .card-value { color: #fb923c; }
    .card.medium::before  { background: linear-gradient(90deg,#eab308,#ca8a04); }
    .card.medium .card-value { color: #facc15; }
    .card.low::before     { background: linear-gradient(90deg,#22c55e,#16a34a); }
    .card.low .card-value { color: #4ade80; }
    .card.risk::before    { background: linear-gradient(90deg,#a855f7,#7c3aed); }
    .card.risk .card-value { color: #c084fc; }
    .card.tested::before  { background: linear-gradient(90deg,#06b6d4,#0891b2); }
    .card.tested .card-value { color: #22d3ee; }

    /* ── Top Finding Alert ───────────────────────────────────────── */
    .top-alert {
      background: var(--bg-card);
      border: 1px solid rgba(239,68,68,0.3);
      border-left: 4px solid #ef4444;
      border-radius: 14px;
      padding: 1.2rem 1.5rem;
      margin-top: 0.5rem;
      display: flex;
      align-items: center;
      gap: 1.2rem;
      box-shadow: 0 4px 20px rgba(239,68,68,0.1);
      animation: pulseRed 3s ease-in-out infinite;
    }
    @keyframes pulseRed {
      0%,100% { box-shadow: 0 4px 20px rgba(239,68,68,0.1); }
      50%      { box-shadow: 0 4px 28px rgba(239,68,68,0.22); }
    }
    .top-alert-icon { font-size: 1.8rem; }
    .top-alert-body { flex: 1; }
    .top-alert-eyebrow {
      font-size: 0.62rem;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: #f87171;
      font-weight: 700;
      margin-bottom: 0.2rem;
    }
    .top-alert-name { font-size: 1rem; font-weight: 700; color: var(--text-primary); }
    .top-alert-detail { font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem; }
    .top-alert-detail code {
      background: var(--mono-bg);
      border: 1px solid var(--mono-border);
      border-radius: 5px;
      padding: 0.05rem 0.35rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      color: var(--accent-cyan);
    }
    .top-alert-score {
      font-size: 2rem;
      font-weight: 900;
      color: #f87171;
      white-space: nowrap;
      letter-spacing: -0.04em;
    }
    .top-alert-score small {
      font-size: 0.9rem;
      font-weight: 500;
      color: rgba(248,113,113,0.5);
    }

    /* ── OWASP Category Pills ────────────────────────────────────── */
    .pills-wrap {
      display: flex;
      flex-wrap: wrap;
      gap: 0.6rem;
      margin-top: 0.5rem;
    }
    .pill {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      background: var(--pill-bg);
      border: 1px solid var(--pill-border);
      border-radius: 99px;
      padding: 0.35rem 0.9rem;
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--accent-cyan);
      transition: transform 0.15s ease, box-shadow 0.15s ease;
    }
    .pill:hover {
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(99,179,237,0.15);
    }
    .pill-count {
      background: var(--accent-cyan);
      color: #fff;
      border-radius: 99px;
      font-size: 0.68rem;
      font-weight: 800;
      padding: 0.05rem 0.5rem;
      min-width: 22px;
      text-align: center;
    }

    /* ── Severity Badges ─────────────────────────────────────────── */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.3rem;
      padding: 0.25rem 0.75rem;
      border-radius: 99px;
      font-size: 0.68rem;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      white-space: nowrap;
    }
    .badge::before { content: '●'; font-size: 0.55rem; }
    .badge-critical { background: rgba(239,68,68,0.15);  color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
    .badge-high     { background: rgba(249,115,22,0.15); color: #fb923c; border: 1px solid rgba(249,115,22,0.3); }
    .badge-medium   { background: rgba(234,179,8,0.15);  color: #fde047; border: 1px solid rgba(234,179,8,0.3); }
    .badge-low      { background: rgba(34,197,94,0.15);  color: #4ade80; border: 1px solid rgba(34,197,94,0.3); }
    .badge-unknown  { background: rgba(107,114,128,0.15);color: #9ca3af; border: 1px solid rgba(107,114,128,0.3); }

    /* ── Risk Score Bar ──────────────────────────────────────────── */
    .risk-wrap { display: flex; align-items: center; gap: 0.6rem; min-width: 120px; }
    .risk-num  { font-weight: 800; font-size: 0.88rem; min-width: 32px; text-align: right; font-family: 'JetBrains Mono', monospace; }
    .risk-track { flex: 1; height: 6px; background: var(--border); border-radius: 99px; overflow: hidden; min-width: 55px; }
    .risk-fill  { height: 100%; border-radius: 99px; transition: width 0.6s cubic-bezier(.34,1.56,.64,1); }

    /* ── Confidence Bar ──────────────────────────────────────────── */
    .conf-wrap { display: flex; align-items: center; gap: 0.4rem; }
    .conf-track { width: 45px; height: 4px; background: var(--border); border-radius: 99px; overflow: hidden; }
    .conf-fill  { height: 100%; background: linear-gradient(90deg, var(--accent-purple), var(--accent-cyan)); border-radius: 99px; }
    .conf-pct   { font-size: 0.78rem; font-weight: 700; color: var(--text-secondary); font-family: 'JetBrains Mono', monospace; }

    /* ── Findings Table ──────────────────────────────────────────── */
    .table-wrap {
      overflow-x: auto;
      border-radius: 16px;
      border: 1px solid var(--border);
      box-shadow: var(--shadow-card);
      margin-top: 0.5rem;
    }
    table { width: 100%; border-collapse: collapse; background: var(--bg-card); font-size: 0.82rem; }
    thead { background: var(--table-header); }
    thead th {
      padding: 0.9rem 1rem;
      text-align: left;
      font-size: 0.63rem;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--text-muted);
      white-space: nowrap;
      border-bottom: 1px solid var(--border);
    }
    tbody td {
      padding: 0.85rem 1rem;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
      max-width: 240px;
      color: var(--text-primary);
      transition: background 0.15s ease;
    }
    tbody tr:last-child td { border-bottom: none; }
    tbody tr.row-critical { background: var(--row-critical); }
    tbody tr.row-high     { background: var(--row-high); }
    tbody tr.row-medium   { background: var(--row-medium); }
    tbody tr.row-low      { background: var(--row-low); }
    tbody tr:hover td     { background: var(--bg-card-hover) !important; }
    .row-num { font-size: 0.72rem; color: var(--text-muted); font-weight: 700; font-family: 'JetBrains Mono', monospace; }

    /* ── Monospace Code Snippets ─────────────────────────────────── */
    .mono {
      font-family: 'JetBrains Mono', 'Consolas', monospace;
      font-size: 0.75rem;
      background: var(--mono-bg);
      border: 1px solid var(--mono-border);
      border-radius: 6px;
      padding: 0.18rem 0.45rem;
      color: var(--accent-cyan);
      word-break: break-word;
      display: inline-block;
      max-width: 100%;
    }

    /* ── Empty State ─────────────────────────────────────────────── */
    .no-findings {
      background: var(--bg-card);
      border: 1px solid rgba(34,197,94,0.3);
      border-radius: 16px;
      padding: 3.5rem 2rem;
      text-align: center;
      color: #4ade80;
      font-size: 1.05rem;
      font-weight: 600;
      margin-top: 0.5rem;
    }
    .no-findings .icon { font-size: 3rem; margin-bottom: 0.75rem; display: block; }

    /* ── Footer ──────────────────────────────────────────────────── */
    footer {
      margin-top: 4rem;
      padding: 1.5rem 2.5rem;
      background: var(--bg-secondary);
      border-top: 1px solid var(--border);
      text-align: center;
      font-size: 0.78rem;
      color: var(--text-muted);
    }
    footer strong { color: var(--text-secondary); }

    /* ── Scrollbar ───────────────────────────────────────────────── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 99px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

    /* ── Validation Status Badges ────────────────────────────────── */
    .vbadge {
      display: inline-flex; align-items: center; gap: 0.25rem;
      padding: 0.18rem 0.6rem;
      border-radius: 99px;
      font-size: 0.62rem;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      white-space: nowrap;
    }
    .vbadge-CONFIRMED    { background:rgba(239,68,68,0.15);  color:#f87171; border:1px solid rgba(239,68,68,0.35); }
    .vbadge-POTENTIAL    { background:rgba(249,115,22,0.15); color:#fb923c; border:1px solid rgba(249,115,22,0.35); }
    .vbadge-FALSE_POSITIVE{ background:rgba(34,197,94,0.15); color:#4ade80; border:1px solid rgba(34,197,94,0.35); }
    .vbadge-INCONCLUSIVE { background:rgba(99,179,237,0.12); color:#63b3ed; border:1px solid rgba(99,179,237,0.3); }
    .vbadge-HEURISTIC    { background:rgba(159,122,234,0.12);color:#a78bfa; border:1px solid rgba(159,122,234,0.3); }

    /* ── Validation Summary Strip ────────────────────────────────── */
    .val-strip {
      display: flex; flex-wrap: wrap; gap: 0.75rem;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1rem 1.4rem;
      margin-top: 0.5rem;
      align-items: center;
    }
    .val-strip-label {
      font-size: 0.62rem; font-weight: 800;
      text-transform: uppercase; letter-spacing: 0.1em;
      color: var(--text-muted); margin-right: 0.5rem;
    }
    .val-item {
      display: flex; align-items: center; gap: 0.4rem;
      font-size: 0.78rem; font-weight: 700;
    }
    .val-dot { width: 8px; height: 8px; border-radius: 50%; }
    .val-dot-CONFIRMED    { background: #f87171; }
    .val-dot-POTENTIAL    { background: #fb923c; }
    .val-dot-FALSE_POSITIVE { background: #4ade80; }
    .val-dot-INCONCLUSIVE { background: #63b3ed; }

    /* ── Judge Panel (expandable per-finding) ────────────────────── */
    .judge-toggle {
      display: inline-flex; align-items: center; gap: 0.35rem;
      background: rgba(99,179,237,0.08);
      border: 1px solid rgba(99,179,237,0.2);
      border-radius: 8px;
      padding: 0.2rem 0.6rem;
      font-size: 0.68rem; font-weight: 700;
      color: var(--accent-cyan);
      cursor: pointer;
      user-select: none;
      transition: background 0.15s, box-shadow 0.15s;
      white-space: nowrap;
    }
    .judge-toggle:hover { background:rgba(99,179,237,0.16); box-shadow:0 2px 8px rgba(99,179,237,0.15); }
    .judge-panel {
      display: none;
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.1rem 1.3rem;
      margin-top: 0.6rem;
      animation: fadeSlide 0.2s ease;
    }
    .judge-panel.open { display: block; }
    @keyframes fadeSlide {
      from { opacity:0; transform:translateY(-6px); }
      to   { opacity:1; transform:translateY(0); }
    }
    .judge-cards-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 0.8rem;
      margin-bottom: 0.9rem;
    }
    .judge-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.85rem 1rem;
      position: relative;
      overflow: hidden;
    }
    .judge-card::before {
      content: ''; position: absolute;
      top: 0; left: 0; right: 0; height: 3px;
      border-radius: 10px 10px 0 0;
    }
    .judge-card.vuln::before { background: linear-gradient(90deg,#ef4444,#f97316); }
    .judge-card.safe::before { background: linear-gradient(90deg,#22c55e,#06b6d4); }
    .judge-card.unavail::before { background: rgba(107,114,128,0.5); }
    .judge-card-header {
      display: flex; justify-content: space-between; align-items: flex-start;
      margin-bottom: 0.5rem;
    }
    .judge-card-name { font-size: 0.68rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); }
    .judge-card-model { font-size: 0.72rem; font-weight: 600; color: var(--accent-cyan); margin-top: 0.1rem; }
    .judge-verdict {
      font-size: 0.82rem; font-weight: 800;
      padding: 0.1rem 0.55rem;
      border-radius: 6px;
      white-space: nowrap;
    }
    .judge-verdict.VULNERABLE { background:rgba(239,68,68,0.15); color:#f87171; }
    .judge-verdict.SAFE       { background:rgba(34,197,94,0.15);  color:#4ade80; }
    .judge-verdict.UNAVAIL    { background:rgba(107,114,128,0.12);color:#9ca3af; }
    .judge-conf-row { display:flex; align-items:center; gap:0.5rem; margin:0.45rem 0 0.5rem; }
    .judge-conf-label { font-size:0.65rem; color:var(--text-muted); font-weight:600; }
    .judge-reason { font-size:0.75rem; color:var(--text-secondary); line-height:1.5; border-top:1px solid var(--border); padding-top:0.45rem; }

    /* ── Superior Judge Block ────────────────────────────────────── */
    .superior-block {
      background: var(--bg-card);
      border: 1px solid rgba(99,179,237,0.25);
      border-left: 3px solid var(--accent-cyan);
      border-radius: 10px;
      padding: 0.9rem 1.1rem;
    }
    .superior-header {
      display: flex; align-items: center; gap: 0.8rem;
      margin-bottom: 0.5rem; flex-wrap: wrap;
    }
    .superior-label { font-size:0.62rem; font-weight:800; text-transform:uppercase; letter-spacing:0.1em; color:var(--accent-cyan); }
    .superior-model { font-size:0.72rem; color:var(--text-secondary); }
    .superior-not-invoked { font-size:0.78rem; color:var(--text-muted); font-style:italic; }
    .superior-reason { font-size:0.77rem; color:var(--text-secondary); line-height:1.5; margin-top:0.4rem; }
    .superior-evidence {
      font-size:0.75rem; color:var(--text-muted);
      background:var(--mono-bg); border:1px solid var(--mono-border);
      border-radius:6px; padding:0.4rem 0.7rem; margin-top:0.4rem;
      font-family:'JetBrains Mono',monospace; line-height:1.6;
    }
  </style>
</head>
<body>

<!-- ══ NAVBAR ══════════════════════════════════════════════════ -->
<nav class="navbar">
  <div class="navbar-brand">
    <div class="shield">🛡</div>
    LLM Scanner
    <span class="version">v1.0</span>
  </div>
  <div class="navbar-right">
    <span class="navbar-badge">OWASP LLM Top 10</span>
    <div class="theme-toggle" id="themeToggle" title="Toggle dark/light mode">
      <span class="icon">🌙</span>
      <div class="toggle-track">
        <div class="toggle-knob"></div>
      </div>
      <span class="icon">☀️</span>
    </div>
  </div>
</nav>

<!-- ══ HERO HEADER ═════════════════════════════════════════════ -->
<div class="hero">
  <div class="hero-content">
    <h1 class="hero-title">
      <span class="title-icon">🔍</span>
      Security Scan Report
    </h1>
    <p class="hero-subtitle">AI Red-Teaming Toolkit &nbsp;·&nbsp; Automated Vulnerability Assessment</p>
    <div class="hero-meta">
      <div class="hero-meta-item">
        <div class="hero-meta-label">Target URL</div>
        <div class="hero-meta-value">{{ target_url }}</div>
      </div>
      <div class="hero-meta-item">
        <div class="hero-meta-label">Scan Timestamp</div>
        <div class="hero-meta-value">{{ scan_timestamp }}</div>
      </div>
      <div class="hero-meta-item">
        <div class="hero-meta-label">Payloads Tested</div>
        <div class="hero-meta-value">{{ total_payloads_tested }}</div>
      </div>
      <div class="hero-meta-item">
        <div class="hero-meta-label">Total Findings</div>
        <div class="hero-meta-value">{{ summary.total_findings }}</div>
      </div>
    </div>
  </div>
</div>

<!-- ══ MAIN CONTENT ════════════════════════════════════════════ -->
<div class="content">

  <!-- Summary Cards -->
  <div class="section-label">Scan Summary</div>
  <div class="cards-grid">
    <div class="card total">
      <div class="card-label">Total Findings</div>
      <div class="card-value">{{ summary.total_findings }}</div>
      <div class="card-sub">vulnerabilities detected</div>
    </div>
    <div class="card critical">
      <div class="card-label">Critical</div>
      <div class="card-value">{{ summary.by_severity.critical }}</div>
      <div class="card-sub">immediate action</div>
    </div>
    <div class="card high">
      <div class="card-label">High</div>
      <div class="card-value">{{ summary.by_severity.high }}</div>
      <div class="card-sub">urgent review</div>
    </div>
    <div class="card medium">
      <div class="card-label">Medium</div>
      <div class="card-value">{{ summary.by_severity.medium }}</div>
      <div class="card-sub">warrants review</div>
    </div>
    <div class="card low">
      <div class="card-label">Low</div>
      <div class="card-value">{{ summary.by_severity.low }}</div>
      <div class="card-sub">monitor</div>
    </div>
    <div class="card risk">
      <div class="card-label">Avg Risk Score</div>
      <div class="card-value">{{ summary.average_risk_score }}<small style="font-size:1rem;font-weight:500;opacity:.5">/100</small></div>
      <div class="card-sub">weighted severity</div>
    </div>
    <div class="card tested">
      <div class="card-label">Payloads Tested</div>
      <div class="card-value">{{ total_payloads_tested }}</div>
      <div class="card-sub">attack vectors</div>
    </div>
  </div>

  <!-- Multi-Judge Validation Summary (shown only when any multi-judge data present) -->
  {% set vs = summary.get('validation_summary', {}) %}
  {% if vs and (vs.get('CONFIRMED',0) + vs.get('POTENTIAL',0) + vs.get('FALSE_POSITIVE',0) + vs.get('INCONCLUSIVE',0)) > 0 %}
  <div class="section-label">Multi-Judge Validation Summary</div>
  <div class="val-strip">
    <span class="val-strip-label">AI Panel Verdicts</span>
    {% for key, label, clr in [('CONFIRMED','Confirmed','#f87171'),('POTENTIAL','Potential','#fb923c'),('FALSE_POSITIVE','False Positive','#4ade80'),('INCONCLUSIVE','Inconclusive','#63b3ed')] %}
    <div class="val-item">
      <div class="val-dot" style="background:{{ clr }}"></div>
      <span style="color:{{ clr }};font-weight:800">{{ vs.get(key, 0) }}</span>
      <span style="color:var(--text-muted);font-size:0.75rem">{{ label }}</span>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <!-- Top Finding -->
  {% if summary.highest_risk_finding %}
  {% set top = summary.highest_risk_finding %}
  <div class="section-label">Highest Risk Finding</div>
  <div class="top-alert">
    <div class="top-alert-icon">⚠️</div>
    <div class="top-alert-body">
      <div class="top-alert-eyebrow">Highest Risk Finding</div>
      <div class="top-alert-name">[{{ top.id }}] {{ top.name }}</div>
      <div class="top-alert-detail">
        Category: {{ top.category }} &nbsp;·&nbsp;
        Severity: {{ top.severity | upper }} &nbsp;·&nbsp;
        Confidence: {{ (top.confidence * 100) | int }}% &nbsp;·&nbsp;
        Tag: <code>{{ top.detected_tag }}</code>
      </div>
    </div>
    <div class="top-alert-score">{{ top.risk_score }}<small>/100</small></div>
  </div>
  {% endif %}

  <!-- OWASP Categories -->
  <div class="section-label">OWASP Category Breakdown</div>
  {% if summary.by_category %}
  <div class="pills-wrap">
    {% for cat, count in summary.by_category.items() %}
    <div class="pill">
      <span>{{ cat }}</span>
      <span class="pill-count">{{ count }}</span>
    </div>
    {% endfor %}
  </div>
  {% else %}
  <p style="color:var(--text-muted);font-style:italic;padding:0.5rem 0;">No categories to display.</p>
  {% endif %}

  <!-- Findings Table -->
  <div class="section-label">Detailed Findings — sorted by risk score</div>
  {% if findings %}
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>ID</th>
          <th>Name</th>
          <th>Category</th>
          <th>Severity</th>
          <th>Risk Score</th>
          <th>Confidence</th>
          <th>Validation</th>
          <th>Detected Tag</th>
          <th>Matched Text</th>
          <th>Prompt Sent</th>
          <th>Judge Review</th>
        </tr>
      </thead>
      <tbody>
        {% for f in findings %}
        {% set sev = f.severity | lower %}
        {% set val_status = f.get('validation_status', '') %}
        {% set has_judges = f.get('judge_evaluations') %}
        <tr class="row-{{ sev }}">
          <td class="row-num">{{ loop.index }}</td>
          <td><span class="mono">{{ f.id }}</span></td>
          <td style="font-weight:600;white-space:nowrap;">{{ f.name }}</td>
          <td style="color:var(--text-secondary);font-size:0.8rem;">{{ f.category }}</td>
          <td>
            <span class="badge badge-{% if sev in ['critical','high','medium','low'] %}{{ sev }}{% else %}unknown{% endif %}">
              {{ f.severity }}
            </span>
          </td>
          <td>
            {% set rs = f.risk_score | float %}
            {% if rs >= 80 %}{% set rc = "#f87171" %}
            {% elif rs >= 60 %}{% set rc = "#fb923c" %}
            {% elif rs >= 40 %}{% set rc = "#facc15" %}
            {% else %}{% set rc = "#4ade80" %}{% endif %}
            <div class="risk-wrap">
              <span class="risk-num" style="color:{{ rc }}">{{ rs | int }}</span>
              <div class="risk-track">
                <div class="risk-fill" style="width:{{ rs }}%;background:linear-gradient(90deg,{{ rc }},{{ rc }}88)"></div>
              </div>
            </div>
          </td>
          <td>
            {% set pct = (f.confidence * 100) | int %}
            <div class="conf-wrap">
              <span class="conf-pct">{{ pct }}%</span>
              <div class="conf-track">
                <div class="conf-fill" style="width:{{ pct }}%"></div>
              </div>
            </div>
          </td>
          <td>
            {% if val_status %}
            <span class="vbadge vbadge-{{ val_status }}">{{ val_status.replace('_',' ') }}</span>
            {% else %}
            <span class="vbadge vbadge-HEURISTIC">Heuristic</span>
            {% endif %}
          </td>
          <td><span class="mono">{{ f.detected_tag }}</span></td>
          <td><span class="mono">{{ f.matched_text }}</span></td>
          <td><span class="mono">{{ f.prompt_sent }}</span></td>
          <td>
            {% if has_judges %}
            <span class="judge-toggle" onclick="toggleJudge('jp-{{ loop.index }}', this)">🔍 View Judges ▾</span>
            {% else %}
            <span style="color:var(--text-muted);font-size:0.72rem">—</span>
            {% endif %}
          </td>
        </tr>
        {% if has_judges %}
        <tr id="jp-{{ loop.index }}-row" style="display:none;">
          <td colspan="12" style="padding:0.6rem 1rem 1rem;">
            <div class="judge-panel" id="jp-{{ loop.index }}">
              <div class="judge-cards-row">
                {% for ev in f.judge_evaluations %}
                {% set jv = ev.get('verdict','SAFE') %}
                {% set jst = ev.get('status','unavailable') %}
                {% set jconf = (ev.get('confidence',0) * 100) | int %}
                <div class="judge-card {% if jst != 'success' %}unavail{% elif jv == 'VULNERABLE' %}vuln{% else %}safe{% endif %}">
                  <div class="judge-card-header">
                    <div>
                      <div class="judge-card-name">{{ ev.get('judge','?').replace('_',' ') }}</div>
                      <div class="judge-card-model">{{ ev.get('model','unknown') }}</div>
                    </div>
                    {% if jst != 'success' %}
                    <span class="judge-verdict UNAVAIL">UNAVAILABLE</span>
                    {% else %}
                    <span class="judge-verdict {{ jv }}">{{ jv }}</span>
                    {% endif %}
                  </div>
                  {% if jst == 'success' %}
                  <div class="judge-conf-row">
                    <span class="judge-conf-label">Confidence</span>
                    <div class="conf-track" style="width:60px">
                      <div class="conf-fill" style="width:{{ jconf }}%"></div>
                    </div>
                    <span class="conf-pct">{{ jconf }}%</span>
                  </div>
                  <div class="judge-reason">{{ ev.get('reason','') }}</div>
                  {% else %}
                  <div class="judge-reason" style="color:var(--text-muted)">Error: {{ ev.get('error','unknown') }}</div>
                  {% endif %}
                </div>
                {% endfor %}
              </div>

              <!-- Superior Judge block -->
              {% set sup = f.get('superior_judge', {}) %}
              <div class="superior-block">
                <div class="superior-header">
                  <span class="superior-label">⚖️ Superior Judge</span>
                  {% if sup.get('invoked') %}
                  <span class="superior-model">{{ sup.get('model','?') }} via {{ sup.get('provider','?') }}</span>
                  {% set sv = sup.get('final_verdict','SAFE') %}
                  {% set svs = sup.get('validation_status','INCONCLUSIVE') %}
                  <span class="judge-verdict {{ sv }}">{{ sv }}</span>
                  <span class="vbadge vbadge-{{ svs }}">{{ svs.replace('_',' ') }}</span>
                  {% set sconf = (sup.get('confidence',0) * 100) | int %}
                  <div class="conf-wrap">
                    <span class="conf-pct">{{ sconf }}%</span>
                    <div class="conf-track">
                      <div class="conf-fill" style="width:{{ sconf }}%"></div>
                    </div>
                  </div>
                  {% else %}
                  <span class="superior-not-invoked">Not invoked — judges unanimous</span>
                  {% endif %}
                </div>
                {% if sup.get('invoked') %}
                {% if sup.get('reason') %}
                <div class="superior-reason"><strong>Reasoning:</strong> {{ sup.get('reason','') }}</div>
                {% endif %}
                {% if sup.get('evidence') %}
                <div class="superior-evidence">Evidence: {{ sup.get('evidence','') }}</div>
                {% endif %}
                {% endif %}
              </div>

              <!-- Consensus summary -->
              {% set con = f.get('judge_consensus', {}) %}
              {% if con %}
              <div style="display:flex;gap:1rem;margin-top:0.7rem;flex-wrap:wrap;align-items:center;">
                <span style="font-size:0.62rem;font-weight:800;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-muted);">Panel consensus</span>
                <span style="color:#f87171;font-weight:700;font-size:0.8rem">{{ con.get('vulnerable',0) }} VULNERABLE</span>
                <span style="color:#4ade80;font-weight:700;font-size:0.8rem">{{ con.get('safe',0) }} SAFE</span>
                {% if con.get('unavailable',0) > 0 %}
                <span style="color:#9ca3af;font-weight:700;font-size:0.8rem">{{ con.get('unavailable',0) }} UNAVAILABLE</span>
                {% endif %}
                {% if f.get('disagreement') %}
                <span style="color:#fb923c;font-size:0.72rem;font-weight:600">⚡ Disagreement — Superior Judge arbitrated</span>
                {% endif %}
              </div>
              {% endif %}

            </div>
          </td>
        </tr>
        {% endif %}
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <div class="no-findings">
    <span class="icon">✅</span>
    No vulnerabilities detected.<br>
    <span style="font-size:0.9rem;font-weight:400;color:var(--text-secondary);">
      The target responded safely to all {{ total_payloads_tested }} tested payload(s).
    </span>
  </div>
  {% endif %}

</div><!-- /content -->

<!-- ══ FOOTER ══════════════════════════════════════════════════ -->
<footer>
  Generated by <strong>LLM Security Scanner v1.0</strong>
  &nbsp;—&nbsp;
  OWASP LLM Top 10 Red-Teaming Toolkit
  &nbsp;—&nbsp;
  {{ scan_timestamp }}
</footer>

<script>
  // ── Dark / Light Mode Toggle ─────────────────────────────────
  const html   = document.documentElement;
  const toggle = document.getElementById('themeToggle');

  // Restore saved preference
  const saved = localStorage.getItem('llmscanner-theme');
  if (saved) html.setAttribute('data-theme', saved);

  toggle.addEventListener('click', () => {
    const current = html.getAttribute('data-theme');
    const next    = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('llmscanner-theme', next);
  });

  // ── Animate risk bars on load ────────────────────────────────
  document.querySelectorAll('.risk-fill').forEach(bar => {
    const target = bar.style.width;
    bar.style.width = '0%';
    requestAnimationFrame(() => {
      setTimeout(() => { bar.style.width = target; }, 120);
    });
  });

  // ── Toggle judge panel per finding ───────────────────────────
  function toggleJudge(panelId, btn) {
    const panel = document.getElementById(panelId);
    const row   = document.getElementById(panelId + '-row');
    if (!panel || !row) return;
    const isOpen = panel.classList.contains('open');
    panel.classList.toggle('open', !isOpen);
    row.style.display = isOpen ? 'none' : 'table-row';
    btn.textContent = isOpen ? '🔍 View Judges ▾' : '🔍 Hide Judges ▲';
    // Animate conf bars inside the newly opened panel
    if (!isOpen) {
      panel.querySelectorAll('.conf-fill').forEach(bar => {
        const w = bar.style.width; bar.style.width = '0%';
        requestAnimationFrame(() => setTimeout(() => { bar.style.width = w; }, 60));
      });
    }
  }
</script>

</body>
</html>
"""


# ──────────────────────────────────────────────────────────────────────────────
# Report generator
# ──────────────────────────────────────────────────────────────────────────────

def generate_html_report(scan_result: Dict[str, Any], output_path: str) -> str:
    """
    Renders the scan result into a modern, self-contained HTML report file.

    Features:
        - Dark mode / Light mode toggle (persisted in localStorage)
        - Glassmorphism summary cards with animated risk bars
        - Sticky navbar with shield branding
        - OWASP category pills, severity badges with glow effects
        - Jinja2 autoescape=True for XSS-safe chatbot content output

    Args:
        scan_result (dict): Complete scan result returned by ScanEngine.run_scan().
                            Expected keys: target_url, scan_timestamp,
                            total_payloads_tested, findings, summary.
        output_path (str):  File path where the HTML report will be written.
                            Parent directories are created automatically if absent.

    Returns:
        str: The output_path that was written (unchanged, for caller convenience).
    """
    # ── Prepare data ──────────────────────────────────────────────────────────
    summary = dict(scan_result.get("summary", {}))
    by_severity = dict(summary.get("by_severity", {}))
    for key in ("critical", "high", "medium", "low"):
        by_severity.setdefault(key, 0)
    summary["by_severity"] = by_severity
    summary.setdefault("total_findings", 0)
    summary.setdefault("average_risk_score", 0.0)
    summary.setdefault("by_category", {})
    summary.setdefault("highest_risk_finding", None)

    # Sort findings by risk_score descending (highest first)
    raw_findings = scan_result.get("findings", [])
    sorted_findings = sorted(
        raw_findings,
        key=lambda f: float(f.get("risk_score", 0)),
        reverse=True,
    )

    # ── Render ─────────────────────────────────────────────────────────────────
    env = Environment(
        loader=BaseLoader(),
        autoescape=True,
    )
    template = env.from_string(_HTML_TEMPLATE)

    rendered = template.render(
        target_url=scan_result.get("target_url", "N/A"),
        scan_timestamp=scan_result.get("scan_timestamp", "N/A"),
        total_payloads_tested=scan_result.get("total_payloads_tested", 0),
        findings=sorted_findings,
        summary=summary,
    )

    # ── Write to disk ──────────────────────────────────────────────────────────
    output_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(rendered)

    return output_path
