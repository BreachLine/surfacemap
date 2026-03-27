# SurfaceMap

**LLM-driven attack surface discovery. Find every external asset from just a company name.**

SurfaceMap combines passive OSINT techniques, DNS enumeration, HTTP probing, port scanning, cloud bucket enumeration, and LLM intelligence to build a complete map of an organization's attack surface.

---

## Quick Start

```bash
# Install
pip install -e ".[all]"

# Set your LLM API key
export GEMINI_API_KEY="your-key-here"

# Discover everything about a company
surfacemap discover "Acme Corp" --domain acme.com --tree --json

# Or just scan a domain
surfacemap discover example.com --mindmap
```

## Installation

```bash
# Core (CLI + discovery)
pip install -e .

# With API server
pip install -e ".[api]"

# With LLM intelligence
pip install -e ".[llm]"

# With Slack notifications
pip install -e ".[notifications]"

# Everything
pip install -e ".[all]"
```

### External Tools (Optional)

SurfaceMap works without these, but they enhance discovery:

| Tool | Purpose | Install |
|------|---------|---------|
| `dig` | DNS record enumeration | Included with most OS |
| `nmap` | Port scanning | `brew install nmap` / `apt install nmap` |
| `subfinder` | Passive subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |

## CLI Usage

```bash
# Full discovery with tree output
surfacemap discover "Google" --domain google.com --tree

# Export to JSON and CSV
surfacemap discover example.com --json --csv --output ./results

# Generate interactive HTML mindmap
surfacemap discover "Acme Corp" -d acme.com --mindmap

# Check version
surfacemap version
```

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `--domain` | `-d` | Primary domain (if target is a company name) |
| `--output` | `-o` | Output directory for results |
| `--tree` | `-t` | Display results as a rich tree in terminal |
| `--mindmap` | `-m` | Generate interactive D3.js HTML mindmap |
| `--json` | `-j` | Export results to JSON |
| `--csv` | | Export results to CSV |

## API Server

```bash
# Start the API server
uvicorn surfacemap.api.server:app --host 0.0.0.0 --port 8000

# Start a scan
curl -X POST "http://localhost:8000/discover?target=example.com"

# Get scan results
curl "http://localhost:8000/scans/{scan_id}"

# Health check
curl "http://localhost:8000/health"
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/discover` | Start a new discovery scan |
| `GET` | `/scans/{id}` | Get scan results by ID |
| `GET` | `/scans` | List recent scans |
| `GET` | `/health` | Health check |

## Discovery Modules

SurfaceMap runs discovery in 6 phases:

| # | Phase | Module | Description |
|---|-------|--------|-------------|
| 1 | Company Intel | LLM Brain | Discover domains, subsidiaries, and related entities via LLM |
| 1 | Company Intel | Subsidiary Discovery | Identify acquisitions, brands, and child companies |
| 2 | DNS | DNS Records | Enumerate A, AAAA, MX, NS, TXT, CNAME, SOA records |
| 2 | DNS | Subdomain - subfinder | Passive subdomain enumeration via subfinder |
| 2 | DNS | Subdomain - crt.sh | Certificate transparency log mining |
| 2 | DNS | Subdomain - Brute Force | DNS brute force with 100+ common prefixes |
| 2 | DNS | Subdomain - LLM | AI-suggested subdomain candidates |
| 3 | HTTP | HTTP Probe | Probe all hosts for HTTP/HTTPS services |
| 3 | HTTP | Technology Detection | Identify web servers, frameworks, CMS from headers |
| 3 | HTTP | Security Headers | Check for missing HSTS, CSP, X-Frame-Options, etc. |
| 3 | HTTP | CDN Detection | Identify Cloudflare, CloudFront, Fastly, Akamai, etc. |
| 3 | HTTP | WAF Detection | Detect web application firewalls |
| 4 | Ports | Port Scan | nmap service version detection on discovered IPs |
| 5 | Cloud | S3 Bucket Enum | Check for public/existing AWS S3 buckets |
| 5 | Cloud | Azure Blob Enum | Check for Azure Blob Storage containers |
| 5 | Cloud | GCS Bucket Enum | Check for Google Cloud Storage buckets |
| 5 | Takeover | Subdomain Takeover | Detect dangling CNAMEs across 17 providers |
| 6 | Dorks | Google Dorks | LLM-generated targeted search queries |

### Asset Types

| Type | Description |
|------|-------------|
| `domain` | Root domains |
| `subdomain` | Discovered subdomains |
| `ip` | IP addresses |
| `port` | Open ports |
| `service` | Running services with version info |
| `cloud_bucket` | S3, Azure Blob, GCS buckets |
| `email_server` | MX record mail servers |
| `nameserver` | NS record nameservers |
| `cdn` | Content delivery networks |
| `waf` | Web application firewalls |
| `certificate` | TLS/SSL certificates |
| `github_repo` | GitHub repositories |
| `social_media` | Social media profiles |
| `url` | Discovered URLs |
| `technology` | Detected technologies |
| `subsidiary` | Subsidiaries and acquisitions |

## Configuration

All settings are configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_API_KEY` | | Google Gemini API key |
| `ANTHROPIC_API_KEY` | | Anthropic Claude API key |
| `SURFACEMAP_LLM_PROVIDER` | `gemini` | LLM provider (`gemini` or `anthropic`) |
| `SURFACEMAP_LLM_MODEL` | `gemini-2.5-flash` | LLM model name |
| `SURFACEMAP_HTTP_TIMEOUT` | `15` | HTTP probe timeout (seconds) |
| `SURFACEMAP_DNS_TIMEOUT` | `10` | DNS lookup timeout (seconds) |
| `SURFACEMAP_SCAN_TIMEOUT` | `300` | nmap scan timeout (seconds) |
| `SURFACEMAP_OUTPUT_DIR` | `./output` | Default output directory |
| `SURFACEMAP_DB_PATH` | `./surfacemap.db` | SQLite database path |
| `SURFACEMAP_SLACK_WEBHOOK` | | Slack webhook URL for notifications |
| `SURFACEMAP_SLACK_TOKEN` | | Slack Bot Token for notifications |
| `SURFACEMAP_SLACK_CHANNEL` | `#security` | Slack channel for notifications |
| `SURFACEMAP_MAX_SUBDOMAINS` | `500` | Maximum subdomains to enumerate |
| `SURFACEMAP_MAX_PROBES` | `20` | Concurrent HTTP probes |
| `SURFACEMAP_MAX_DNS` | `50` | Concurrent DNS lookups |
| `SURFACEMAP_NMAP_ARGS` | `-sV -T4 --top-ports 100` | nmap arguments |

## Output Formats

- **Terminal Tree** — Rich tree display with color-coded statuses
- **JSON** — Full scan data with metadata
- **CSV** — Flat export for spreadsheet analysis
- **HTML Mindmap** — Interactive D3.js force-directed graph with dark theme, zoom, drag, and tooltips
- **Mermaid** — Mermaid.js mindmap diagram for embedding in docs

## Architecture

```
surfacemap/
  core/
    config.py      — Environment-based configuration
    models.py      — Asset, ScanResult, enums
    llm.py         — LLM integration (Gemini/Claude)
  discovery/
    base.py        — DiscoveryModule ABC
    dns.py         — DNS, subdomain, takeover, cloud modules
    http.py        — HTTP probe, port scan modules
    engine.py      — 6-phase orchestration engine
  cli/
    main.py        — Typer CLI application
  output/
    mindmap.py     — D3.js HTML and Mermaid export
  api/
    server.py      — FastAPI REST API
  notifications/
    slack.py       — Slack Block Kit notifications
  storage/
    db.py          — SQLite persistence with aiosqlite
```

## License

MIT License. Copyright (c) 2026 Yash Korat.

---

Built by [BreachLine Labs](https://breachline.io)
