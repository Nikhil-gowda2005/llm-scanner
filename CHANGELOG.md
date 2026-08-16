# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.0.0] - 2026-08-16
### Added
- 119 real-world attack payloads across 8 OWASP LLM Top 10 categories
- LLM-as-a-Judge secondary detection layer (Groq GPT-OSS 120B)
- Web UI dashboard at `http://localhost:8080`
- HTML and JSON report generation
- Auto-retry with exponential backoff
- Secure API key storage (`~/.llm-scanner/config.json`)
- `llm-scanner`, `llm-scanner-config`, and `llm-scanner-web` CLI commands
