# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SurfaceMap is an LLM-driven attack surface discovery tool. Given a company name or domain, it runs 48+ discovery modules concurrently to enumerate subdomains, IPs, ports, cloud buckets, certificates, vulnerabilities, and more. Results are deduplicated, risk-scored, and output as terminal trees, JSON, CSV, SARIF, HTML mindmaps, or Mermaid diagrams.

## Build & Run Commands

```bash
# Install (editable, all extras)
pip install -e ".[all]"

# Install core only (no API/LLM/Slack)
pip install -e .

# Run CLI
surfacemap discover "Target Corp" --domain target.com --tree --json

# Run with SARIF output for CI/CD
surfacemap discover target.com --sarif --json --output ./results

# Run API server
uvicorn surfacemap.api.server:app --host 0.0.0.0 --port 8000

# Run web UI dashboard
surfacemap ui

# Continuous monitoring
surfacemap monitor target.com --interval 24h

# Compare two scans
surfacemap diff scan1.json scan2.json

# Run config viewer
surfacemap config
```

There is no test suite, linter, or formatter configured yet. The `tests/` directory exists but is empty.

## Architecture

### Execution Flow

CLI (`cli/main.py`) or API (`api/server.py`) → `DiscoveryEngine` → 4-phase pipeline:
1. **Phase 0**: LLM Brainstorm (optional) — identifies subsidiaries, infrastructure hints
2. **Phase 1**: Passive Recon — 20+ modules run concurrently via `asyncio.gather()`
3. **Phase 2**: Active Probing — split into two sub-phases:
   - **2a**: 14 modules concurrent (HTTP probe, port scan, CORS, cloud, takeover, etc.)
   - **2b**: 3 modules that depend on live hosts from 2a (web crawler, Nuclei, screenshots)
4. **Phase 3**: LLM Analysis — risk scoring, attack path generation

### Module System

All discovery modules extend `DiscoveryModule` ABC in `discovery/base.py`:
- Must implement `name`, `description` properties and `discover(target, result)` async method
- `safe_discover()` wraps execution with timeout (120s default) and error handling
- Modules can override `module_timeout` for longer-running tasks (e.g. Nuclei uses 600s)
- Module failures are isolated — they don't crash the pipeline

Modules are organized by category across files in `discovery/`:
- `dns.py` — DNS records, subdomains, zone transfers, cloud detection, subdomain takeover
- `http.py` — HTTP probing, port scanning (nmap)
- `web.py` — Wayback, cert transparency, URL scanning, web tech detection
- `osint.py` — WHOIS, ASN, reverse DNS, SSL analysis, email security
- `active.py` — Sensitive paths, JS analysis, CORS, cookie security
- `enrichment.py` — VirusTotal, Shodan, GitHub dorks, email harvesting
- `external_apis.py` — Censys, BinaryEdge, FullHunt, PassiveTotal
- `crawler.py` — Web crawling/spidering (Katana CLI or built-in BFS)
- `nuclei.py` — Nuclei template-based vulnerability scanning
- `screenshot.py` — Headless browser screenshot capture (Playwright or Chrome)

### Plugin System

- `plugins/loader.py` — Loads plugins from `~/.surfacemap/plugins/` and `importlib.metadata` entry points
- `plugins/registry.py` — Singleton registry, modules declare `plugin_phase = "passive"` or `"active"`
- Plugins are auto-loaded into the engine when `config.enable_plugins` is True

### Scheduler & Monitoring

- `scheduler/scheduler.py` — `run_scheduled_scan()` loop: scan → diff → Slack alert on changes
- `scheduler/differ.py` — `compute_diff()` compares two `ScanResult` objects by fingerprint

### Data Model

`core/models.py` defines the asset-centric model:
- **Asset**: type (29 `AssetType` enums including VULNERABILITY, FORM, PARAMETER), value, status, severity, metadata dict
- **ScanResult**: container with fingerprint-based deduplication (SHA256 of type:value)
- Assets are added via `ScanResult.add_asset()` which handles dedup automatically

### LLM Integration

`core/llm.py` — `LLMBrain` class with provider fallback chain: Gemini → Anthropic → OpenAI. Used for brainstorming targets, risk scoring, and false-positive filtering. Entirely optional — tool works without any LLM key.

### Configuration

`core/config.py` — `SurfaceMapConfig` dataclass, singleton via `get_config()`. All settings come from environment variables (auto-loads `.env` file). Key prefixes: `SURFACEMAP_*` for tool settings, plus API keys for: Gemini, VirusTotal, Shodan, GitHub, Hunter, Censys, BinaryEdge, FullHunt, PassiveTotal.

### Storage & Output

- `storage/db.py` — async SQLite via aiosqlite, stores scans and assets
- `output/mindmap.py` — generates standalone HTML with D3.js force-directed graph
- `output/formatters.py` — JSON, CSV, Rich tree, Mermaid export
- `output/sarif.py` — SARIF 2.1.0 output for GitHub/GitLab security tabs

### Web UI

- `ui/app.py` — FastAPI dashboard with scan history and detail views, filterable asset table

## Key Conventions

- **Async-first**: All discovery, HTTP, DNS, and DB operations are async. Use `asyncio` patterns.
- **Fault tolerance**: Every module runs inside `safe_discover()` with per-module timeouts. Never let one module failure affect others.
- **No secrets in code**: All API keys via env vars. The `.env` file is gitignored.
- **External tools are optional**: `dig`, `nmap`, `subfinder`, `nuclei`, `katana`, `playwright` enhance results but the tool must work without them (check availability before calling).
- **Sub-phase ordering**: Modules that depend on live host data (crawler, nuclei, screenshots) must run after HTTP probe completes, not in parallel with it.
- Python 3.11+ required. Build system is Hatch/Hatchling.
