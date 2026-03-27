<p align="center">
  <img src="https://img.shields.io/badge/version-2.1.1-blue" alt="Version">
  <img src="https://img.shields.io/badge/python-3.11+-green" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/modules-40+-orange" alt="Modules">
</p>

# SurfaceMap

**LLM-driven attack surface discovery by [BreachLine Labs](https://breachline.io)**

Find every external asset from just a company name. SurfaceMap combines 40+ OSINT data sources, DNS enumeration, HTTP probing, port scanning, vulnerability scanning (Nuclei), web crawling, screenshot capture, and LLM intelligence to build a complete map of an organization's attack surface.

---

## Features

- **Phase 0: LLM Brainstorm** - Deep intelligence gathering with web search enrichment (DuckDuckGo)
- **Phase 1: Passive Recon** - 20+ concurrent OSINT sources (AnubisDB, CertSpotter, crt.sh, RapidDNS, SubdomainCenter, HackerTarget, Wayback, URLScan, CommonCrawl, and more)
- **Phase 2: Active Probing** - HTTP probe, port scan (nmap), SSL/TLS analysis, sensitive path fuzzing (60+ paths), JS analysis, CORS check, cookie security, cloud bucket enumeration, subdomain takeover (30 providers + NXDOMAIN detection), web crawling, Nuclei vulnerability scanning (6000+ templates), screenshot capture
- **Phase 3: LLM Analysis** - Risk scoring (A-F grade), attack path analysis, executive summary, false positive filtering, Google dorks
- **Interactive Mindmap** - D3.js visualization with zoom/pan, collapsible nodes, dark theme
- **Dashboard View** - Searchable/filterable/sortable asset table with TXT/CSV/JSON export
- **Web UI** - `surfacemap ui` launches a web dashboard to browse scan history and results
- **Scheduled Monitoring** - `surfacemap monitor` runs continuous scans with diff alerts via Slack
- **CI/CD Integration** - SARIF output for GitHub/GitLab security tabs
- **Plugin System** - Drop custom modules in `~/.surfacemap/plugins/` or install via entry points
- **Zero-config start** - Just provide a domain, no API keys required for core features

## Quick Start

```bash
# Install
pip install surfacemap[all]

# Set your LLM API key (optional but recommended)
surfacemap set-key GEMINI_API_KEY your-key-here

# Discover everything about a target
surfacemap discover facebook.com --json --mindmap

# Passive only (faster, no active probing)
surfacemap discover example.com --passive-only --json

# With enrichment APIs (VirusTotal, Shodan, GitHub)
surfacemap discover target.com --enrich --json --mindmap
```

## Installation

```bash
# Core (CLI + discovery)
pip install surfacemap

# With all extras (API server, LLM, notifications)
pip install surfacemap[all]

# From source
git clone https://github.com/BreachLine/surfacemap.git
cd surfacemap
pip install -e ".[all]"
```

**Requirements:** Python 3.11+, optional: `dig`, `nmap`, `subfinder`, `nuclei`, `katana`, `playwright`

## CLI Commands

| Command | Description |
|---------|-------------|
| `surfacemap discover <target>` | Run attack surface scan |
| `surfacemap export <scan.json>` | Export assets (txt/csv/json/domains/live/subdomains) |
| `surfacemap config` | Show all configuration settings |
| `surfacemap set-config <key> <value>` | Change any config setting |
| `surfacemap set-key <name> <value>` | Set an API key in .env |
| `surfacemap show-keys` | Show configured API keys |
| `surfacemap monitor <target>` | Start continuous monitoring with diff alerts |
| `surfacemap diff <old.json> <new.json>` | Compare two scan results |
| `surfacemap ui` | Start the web UI dashboard |
| `surfacemap plugins` | List loaded plugins |
| `surfacemap version` | Show version + check for updates |
| `surfacemap update` | Auto-update from GitHub |

## Scan Options

```bash
surfacemap discover <target> [options]

Options:
  -d, --domain TEXT        Primary domain (if target is a company name)
  -o, --output TEXT        Output directory
  -t, --tree              Display results as a tree
  -m, --mindmap           Generate interactive HTML mindmap
  -j, --json              Export results to JSON
  --csv                   Export results to CSV
  --sarif                 Export SARIF for GitHub/GitLab security tabs
  -e, --enrich            Enable enrichment modules (requires API keys)
  --passive-only          Skip active probing
  --no-analysis           Skip LLM analysis phase
```

## Export Examples

```bash
# Export live hosts to a text file
surfacemap export output/scan.json --format live -o live_hosts.txt

# Export all subdomains
surfacemap export output/scan.json --format subdomains -o subs.txt

# Export all domains (main + subsidiaries)
surfacemap export output/scan.json --format domains

# Export full CSV
surfacemap export output/scan.json --format csv -o assets.csv
```

## API Keys

All core features work without API keys. Optional keys unlock additional data sources:

| Key | Purpose | Free Tier |
|-----|---------|-----------|
| `GEMINI_API_KEY` | LLM intelligence (brainstorm, analysis, dorks) | Free |
| `VIRUSTOTAL_API_KEY` | Subdomain + IP enrichment | 4 req/min |
| `SHODAN_API_KEY` | Host enrichment, banners, vulns | Free tier |
| `GITHUB_TOKEN` | GitHub secret/code search | 30 req/min |
| `HUNTER_API_KEY` | Email harvesting | 25/month |
| `SECURITYTRAILS_API_KEY` | Subdomain history | 50/month |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | Host/cert search | 250/month |
| `BINARYEDGE_API_KEY` | Subdomain enumeration | 250/month |
| `FULLHUNT_API_KEY` | Subdomain + host data | 100/month |
| `PASSIVETOTAL_USERNAME` + `PASSIVETOTAL_API_KEY` | Passive DNS enrichment | 15/day |

```bash
# Set keys via CLI (persists to .env)
surfacemap set-key GEMINI_API_KEY your-key
surfacemap set-key SHODAN_API_KEY your-key

# Or add to .env file
cp .env.example .env
# Edit .env with your keys
```

## Discovery Modules (40+)

### Phase 0: LLM Brainstorm
| Module | Description |
|--------|-------------|
| Web Search | DuckDuckGo search for current company intel |
| Domain Discovery | LLM identifies all related domains |
| Subsidiary Discovery | Acquisitions, brands, joint ventures |
| Infrastructure Intel | Tech stack, cloud providers, services |

### Phase 1: Passive Recon (concurrent)
| Module | Source | Key Required |
|--------|--------|-------------|
| DNS Records | dig (A/AAAA/MX/NS/TXT/CNAME/SOA) | No |
| Subdomain Discovery | subfinder + crt.sh + brute force + LLM | No |
| AnubisDB | jldc.me (massive subdomain DB) | No |
| SubdomainCenter | subdomain.center | No |
| CertSpotter | Certificate transparency API | No |
| CertTransparency | crt.sh | No |
| HackerTarget | Host search + reverse IP | No |
| RapidDNS | Subdomain enumeration | No |
| URLScan | urlscan.io search | No |
| CommonCrawl | Web crawl URL index | No |
| Wayback Machine | Historical URLs (streaming) | No |
| AlienVault URLs | OTX URL history | No |
| WHOIS/RDAP | Domain registration info | No |
| DNS Zone Transfer | AXFR attempt | No |
| Email Security | SPF/DKIM/DMARC analysis | No |
| Subdomain Permutation | altdns-style generation | No |
| ASN Discovery | Team Cymru IP-to-ASN | No |
| VirusTotal | Subdomain + IP enrichment | Optional |
| GitHub Dorking | Secret/code search | Optional |
| Email Harvest | Hunter.io + regex fallback | Optional |
| Censys | Host and certificate search | Optional |
| BinaryEdge | Subdomain enumeration | Optional |
| FullHunt | Subdomain + host data | Optional |
| PassiveTotal | Passive DNS enrichment | Optional |

### Phase 2: Active Probing (concurrent)
| Module | Description | Key Required |
|--------|-------------|-------------|
| HTTP Probe | Technology/CDN/WAF detection, security headers | No |
| Port Scan | nmap service detection | No |
| SSL/TLS Analysis | Cert details, cipher suites, TLS version | No |
| Sensitive Paths | 60+ paths (.git, .env, admin, actuator, etc.) | No |
| JS Analysis | API endpoints, secrets, subdomains from JS | No |
| CORS Check | Origin reflection, wildcard, credentials | No |
| Cookie Security | Secure/HttpOnly/SameSite flags | No |
| Cloud Storage | S3/Azure/GCS bucket enumeration | No |
| Subdomain Takeover | 30 providers + NXDOMAIN + NS delegation | No |
| Reverse DNS | PTR lookups | No |
| Reverse IP | Find domains sharing IPs | No |
| Shodan InternetDB | Ports, vulns, hostnames (free, no key) | No |
| IPInfo | IP geolocation, ASN, org | No |
| Web Crawler | Crawls live sites for hidden pages, forms, params (Katana or built-in) | No |
| Nuclei Scanner | 6000+ vulnerability templates | No |
| Screenshot Capture | Headless browser screenshots of live hosts (Playwright or Chrome) | No |
| Shodan (full) | Banner data, CVEs | Optional |

### Phase 3: LLM Analysis
| Module | Description |
|--------|-------------|
| False Positive Filter | LLM reviews findings to reduce noise |
| Risk Scorer | Algorithmic + LLM-refined scoring (A-F grade) |
| Attack Path Analysis | Chains findings into attack narratives |
| Executive Summary | Non-technical summary with recommendations |
| Google Dorks | Targeted search queries |

## Output Formats

- **Interactive HTML Mindmap** - D3.js tree with collapsible nodes, dark theme, BreachLine Labs branding
- **Dashboard View** - Filterable asset table with search, sort, export (TXT/CSV/JSON)
- **JSON** - Full structured scan results
- **CSV** - Spreadsheet-compatible export
- **CLI Tree** - Rich terminal tree display
- **SARIF** - GitHub/GitLab Security tab integration
- **Screenshots** - PNG screenshots of live hosts

## Configuration

```bash
# View all settings
surfacemap config

# Change settings
surfacemap set-config SURFACEMAP_LLM_MODEL gemini-2.0-flash
surfacemap set-config SURFACEMAP_LLM_MAX_TOKENS 32768
surfacemap set-config SURFACEMAP_MAX_CONCURRENT_DNS 500
surfacemap set-config SURFACEMAP_HTTP_TIMEOUT 30
```

All settings are configurable via environment variables or `.env` file. See `surfacemap config` for the full list.

## REST API

```bash
# Start the API server
pip install surfacemap[api]
uvicorn surfacemap.api.server:app --host 0.0.0.0 --port 8000

# Endpoints
POST /discover          # Start a scan
GET  /scans/{scan_id}   # Get scan results
GET  /scans             # List recent scans
GET  /health            # Health check
```

## Architecture

```
Phase 0: LLM Brainstorm (web search + deep thinking)
    |
    v
Phase 1: Passive Recon (20+ modules concurrent)
    |-- DNS + Subdomain Discovery
    |-- Certificate Transparency
    |-- OSINT APIs (AnubisDB, CertSpotter, RapidDNS, etc.)
    |-- WHOIS, ASN, Zone Transfer, Email Security
    |-- Subsidiary deep recon (DNS + subs + CT per subsidiary)
    |-- Subdomain Permutation + ASN Discovery
    |
    v
Phase 2a: Active Probing (14 modules concurrent)
    |-- HTTP Probe (shared client, connection pooling)
    |-- Port Scan (nmap)
    |-- SSL/TLS, Sensitive Paths, JS Analysis
    |-- CORS, Cookies, Cloud, Takeover (30 providers)
    |-- Reverse DNS/IP, Shodan InternetDB, IPInfo
    |
Phase 2b: Post-Probe (depends on live hosts from 2a)
    |-- Web Crawler (Katana or built-in BFS spider)
    |-- Nuclei Vulnerability Scanner (6000+ templates)
    |-- Screenshot Capture (Playwright or headless Chrome)
    |
    v
Phase 3: LLM Analysis (sequential)
    |-- False Positive Filter
    |-- Risk Scoring (A-F grade)
    |-- Attack Path Analysis
    |-- Executive Summary
    |-- Google Dorks
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**BreachLine Labs** - [breachline.io](https://breachline.io) - hello@breachline.io

