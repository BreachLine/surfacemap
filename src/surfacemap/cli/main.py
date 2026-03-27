"""SurfaceMap CLI — command-line interface for attack surface discovery.

Usage:
    surfacemap discover "Acme Corp" --domain acme.com
    surfacemap discover acme.com --tree --json
    surfacemap version
"""

from __future__ import annotations

import asyncio
import csv
import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from surfacemap import __version__
from surfacemap.core.config import get_config
from surfacemap.core.models import AssetType, ScanResult

app = typer.Typer(
    name="surfacemap",
    help="LLM-driven attack surface discovery. Find every asset from just a company name.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


def _build_tree(result: ScanResult) -> Tree:
    """Build a rich Tree visualization of the scan results."""
    config = get_config()

    grade_color = {
        "A": "green", "B": "cyan", "C": "yellow", "D": "red", "F": "bold red",
    }
    grade_str = ""
    if result.risk_grade:
        gc = grade_color.get(result.risk_grade, "white")
        grade_str = f" [{gc}]Risk: {result.risk_grade} ({result.risk_score}/100)[/{gc}]"

    tree = Tree(
        f"[bold cyan]{result.target}[/] [dim]({result.scan_id})[/]{grade_str}"
    )

    # Group assets by type
    type_groups: dict[str, list[dict]] = {}
    for asset in result.assets:
        type_name = asset.type.value
        if type_name not in type_groups:
            type_groups[type_name] = []
        type_groups[type_name].append(asset.to_dict())

    display_limit = config.cli_asset_display_limit

    status_colors = {
        "live": "green", "down": "red", "redirect": "yellow",
        "filtered": "magenta", "unknown": "dim",
        "takeover_possible": "bold red", "vulnerable": "bold red",
        "misconfigured": "red",
    }
    sev_colors = {
        "critical": "bold red", "high": "red", "medium": "yellow", "low": "blue",
    }

    for type_name, assets in sorted(type_groups.items(), key=lambda x: -len(x[1])):
        branch = tree.add(
            f"[bold yellow]{type_name}[/] [dim]({len(assets)})[/]"
        )
        for asset in assets[:display_limit]:
            sc = status_colors.get(asset["status"], "dim")
            severity_badge = ""
            if asset["severity"] not in ("info", "unknown"):
                svc = sev_colors.get(asset["severity"], "dim")
                severity_badge = f" [{svc}][{asset['severity'].upper()}][/{svc}]"

            label = (
                f"[{sc}]{asset['value']}[/{sc}]"
                f" [{sc}]({asset['status']})[/{sc}]"
                f"{severity_badge}"
            )
            if asset.get("source"):
                label += f" [dim]via {asset['source']}[/]"
            branch.add(label)

        if len(assets) > display_limit:
            branch.add(f"[dim]... and {len(assets) - display_limit} more[/]")

    return tree


def _print_stats(result: ScanResult) -> None:
    """Print scan statistics as a rich table."""
    stats = result.compute_stats()

    console.print()
    console.print("[bold cyan]Scan Statistics[/]")
    console.print()

    # Summary table
    summary = Table(show_header=False, box=None, padding=(0, 2))
    summary.add_column("Key", style="bold")
    summary.add_column("Value")
    summary.add_row("Total Assets", str(stats["total_assets"]))
    summary.add_row("Live Assets", str(stats["live_assets"]))
    summary.add_row("Scan ID", result.scan_id)
    summary.add_row("Started", result.started_at or "N/A")
    summary.add_row("Completed", result.completed_at or "N/A")

    if result.risk_score is not None:
        grade_color = {
            "A": "green", "B": "cyan", "C": "yellow", "D": "red", "F": "bold red",
        }
        gc = grade_color.get(result.risk_grade or "", "white")
        summary.add_row(
            "Risk Score",
            f"[{gc}]{result.risk_score}/100 (Grade: {result.risk_grade})[/{gc}]",
        )
    console.print(summary)

    # By type table
    if stats["by_type"]:
        console.print()
        type_table = Table(title="Assets by Type")
        type_table.add_column("Type", style="cyan")
        type_table.add_column("Count", justify="right", style="green")
        for type_name, count in sorted(
            stats["by_type"].items(), key=lambda x: x[1], reverse=True
        ):
            type_table.add_row(type_name, str(count))
        console.print(type_table)

    # By severity table
    if stats["by_severity"]:
        console.print()
        sev_table = Table(title="Assets by Severity")
        sev_table.add_column("Severity", style="cyan")
        sev_table.add_column("Count", justify="right")
        severity_order = ["critical", "high", "medium", "low", "info"]
        severity_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }
        for sev in severity_order:
            count = stats["by_severity"].get(sev, 0)
            if count > 0:
                color = severity_colors.get(sev, "white")
                sev_table.add_row(
                    f"[{color}]{sev.upper()}[/{color}]",
                    f"[{color}]{count}[/{color}]",
                )
        console.print(sev_table)

    # Technologies
    if stats["unique_technologies"]:
        console.print()
        console.print(
            f"[bold]Technologies:[/] {', '.join(stats['unique_technologies'])}"
        )

    # Executive Summary
    if result.executive_summary:
        console.print()
        console.print(Panel(
            result.executive_summary,
            title="[bold cyan]Executive Summary[/]",
            border_style="cyan",
        ))

    # Attack Paths
    if result.attack_paths:
        console.print()
        console.print("[bold red]Attack Paths Identified:[/]")
        for i, path in enumerate(result.attack_paths, 1):
            name = path.get("name", f"Path {i}")
            sev = path.get("severity", "unknown")
            steps = path.get("steps", [])
            console.print(f"\n  [bold]{i}. {name}[/] [dim]({sev})[/]")
            for j, step in enumerate(steps, 1):
                console.print(f"     {j}. {step}")


def _export_json(result: ScanResult, output_path: Path) -> Path:
    """Export scan results to JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)
    return output_path


def _export_csv(result: ScanResult, output_path: Path) -> Path:
    """Export scan results to CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "value", "type", "status", "severity", "parent",
            "source", "technologies", "notes", "fingerprint",
        ])
        for asset in result.assets:
            writer.writerow([
                asset.value,
                asset.type.value,
                asset.status.value,
                asset.severity.value,
                asset.parent or "",
                asset.source,
                "|".join(asset.technologies),
                asset.notes,
                asset.fingerprint,
            ])
    return output_path


@app.command()
def discover(
    target: str = typer.Argument(
        help="Company name or primary domain to discover"
    ),
    domain: str = typer.Option(
        None, "--domain", "-d",
        help="Primary domain (if target is a company name)",
    ),
    output: str = typer.Option(
        None, "--output", "-o",
        help="Output directory for results",
    ),
    tree: bool = typer.Option(
        False, "--tree", "-t",
        help="Display results as a tree",
    ),
    mindmap: bool = typer.Option(
        False, "--mindmap", "-m",
        help="Generate interactive HTML mindmap",
    ),
    export_json: bool = typer.Option(
        False, "--json", "-j",
        help="Export results to JSON",
    ),
    export_csv: bool = typer.Option(
        False, "--csv",
        help="Export results to CSV",
    ),
    sarif: bool = typer.Option(
        False, "--sarif",
        help="Export results in SARIF format for CI/CD integration",
    ),
    enrich: bool = typer.Option(
        False, "--enrich", "-e",
        help="Enable enrichment modules (VirusTotal, Shodan, GitHub — requires API keys)",
    ),
    passive_only: bool = typer.Option(
        False, "--passive-only",
        help="Skip active probing (passive recon only)",
    ),
    no_analysis: bool = typer.Option(
        False, "--no-analysis",
        help="Skip LLM analysis phase (risk scoring, attack paths, summary)",
    ),
) -> None:
    """Discover the attack surface of a company or domain.

    Examples:
        surfacemap discover "Google" --domain google.com
        surfacemap discover example.com --tree --json
        surfacemap discover "Acme Corp" -d acme.com --mindmap --enrich
    """
    from surfacemap.discovery.engine import DiscoveryEngine

    config = get_config()

    # If target looks like a domain, use it as both
    effective_domain = domain or target

    engine = DiscoveryEngine(
        target=target,
        domain=effective_domain,
        enrich=enrich,
        passive_only=passive_only,
        skip_analysis=no_analysis,
    )

    try:
        result = asyncio.run(engine.run())
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user[/]")
        sys.exit(1)

    # Always print stats
    _print_stats(result)

    # Tree display
    if tree:
        console.print()
        console.print(_build_tree(result))

    # Determine output directory
    output_dir = Path(output) if output else config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    # JSON export
    if export_json:
        json_path = output_dir / f"{result.scan_id}.json"
        _export_json(result, json_path)
        console.print(f"\n[green]JSON saved to:[/] {json_path}")

    # CSV export
    if export_csv:
        csv_path = output_dir / f"{result.scan_id}.csv"
        _export_csv(result, csv_path)
        console.print(f"\n[green]CSV saved to:[/] {csv_path}")

    # SARIF export
    if sarif:
        from surfacemap.output.sarif import generate_sarif
        sarif_data = generate_sarif(result)
        sarif_path = output_dir / f"{result.scan_id}.sarif.json"
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        with open(sarif_path, "w") as f:
            json.dump(sarif_data, f, indent=2)
        console.print(f"\n[green]SARIF saved to:[/] {sarif_path}")

    # Mindmap
    if mindmap:
        try:
            from surfacemap.output.mindmap import generate_html_mindmap
            import webbrowser

            mindmap_path = output_dir / f"{result.scan_id}_mindmap.html"
            generate_html_mindmap(result, mindmap_path)
            console.print(f"\n[green]Mindmap saved to:[/] {mindmap_path}")
            # Auto-open in browser
            webbrowser.open(str(mindmap_path.resolve()))
            console.print("[dim]Opened mindmap in browser[/]")
        except Exception as e:
            console.print(f"\n[red]Mindmap generation failed:[/] {e}")

    console.print()


@app.command()
def version() -> None:
    """Show version info and check for updates."""
    console.print()
    console.print("[bold cyan]SurfaceMap[/] [dim]by[/] [bold]BreachLine Labs[/]")
    console.print(f"  Version:    v{__version__}")
    console.print(f"  Developer:  BreachLine Labs")
    console.print(f"  Repository: github.com/BreachLine/surfacemap")
    console.print(f"  License:    MIT")
    console.print()

    # Check for updates from GitHub
    try:
        import httpx
        resp = httpx.get(
            "https://api.github.com/repos/BreachLine/surfacemap/releases/latest",
            timeout=5,
            follow_redirects=True,
        )
        if resp.status_code == 200:
            data = resp.json()
            latest = data.get("tag_name", "").lstrip("v")
            if latest and latest != __version__:
                console.print(f"  [yellow]Update available: v{latest}[/]")
                console.print(f"  Run: [bold]surfacemap update[/]")
            else:
                console.print("  [green]Up to date[/]")
        else:
            console.print("  [dim]Could not check for updates[/]")
    except Exception:
        console.print("  [dim]Could not check for updates (offline)[/]")
    console.print()


@app.command()
def update() -> None:
    """Update SurfaceMap to the latest version from GitHub."""
    import subprocess
    import sys

    console.print("[bold cyan]Checking for updates...[/]")

    try:
        import httpx
        resp = httpx.get(
            "https://api.github.com/repos/BreachLine/surfacemap/releases/latest",
            timeout=10,
            follow_redirects=True,
        )
        if resp.status_code == 200:
            latest = resp.json().get("tag_name", "").lstrip("v")
            if latest and latest != __version__:
                console.print(f"  Current: v{__version__} -> Latest: v{latest}")
                console.print("[bold]Updating...[/]")
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--upgrade",
                     "git+https://github.com/BreachLine/surfacemap.git"],
                    capture_output=True, text=True,
                )
                if result.returncode == 0:
                    console.print("[green]Updated successfully![/]")
                else:
                    console.print(f"[red]Update failed:[/] {result.stderr[:200]}")
            else:
                console.print(f"[green]Already on latest version (v{__version__})[/]")
        else:
            console.print("[red]Could not check for updates[/]")
    except Exception as e:
        console.print(f"[red]Update failed:[/] {e}")


@app.command(name="set-key")
def set_key(
    name: str = typer.Argument(help="API key name (e.g. GEMINI_API_KEY, SHODAN_API_KEY)"),
    value: str = typer.Argument(help="API key value"),
) -> None:
    """Set an API key in the .env file.

    Examples:
        surfacemap set-key GEMINI_API_KEY sk-abc123
        surfacemap set-key SHODAN_API_KEY xyz789
        surfacemap set-key VIRUSTOTAL_API_KEY abc
        surfacemap set-key GITHUB_TOKEN ghp_xxx
        surfacemap set-key HUNTER_API_KEY xxx
        surfacemap set-key SECURITYTRAILS_API_KEY xxx
    """
    env_path = Path(".env")
    lines: list[str] = []
    found = False

    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                if line.strip().startswith(f"{name}="):
                    lines.append(f"{name}={value}\n")
                    found = True
                else:
                    lines.append(line)

    if not found:
        lines.append(f"{name}={value}\n")

    with open(env_path, "w") as f:
        f.writelines(lines)

    console.print(f"[green]Set {name}[/] in .env")


@app.command(name="show-keys")
def show_keys() -> None:
    """Show configured API keys and their status.

    Example:
        surfacemap show-keys
    """
    config = get_config()

    keys = [
        ("GEMINI_API_KEY", config.gemini_api_key, "LLM (Gemini)"),
        ("ANTHROPIC_API_KEY", config.anthropic_api_key, "LLM (Anthropic)"),
        ("OPENAI_API_KEY", config.openai_api_key, "LLM (OpenAI)"),
        ("VIRUSTOTAL_API_KEY", config.virustotal_api_key, "VirusTotal enrichment"),
        ("SHODAN_API_KEY", config.shodan_api_key, "Shodan enrichment"),
        ("GITHUB_TOKEN", config.github_token, "GitHub dorking"),
        ("HUNTER_API_KEY", config.hunter_api_key, "Hunter.io email harvest"),
        ("CENSYS_API_ID", config.censys_api_id, "Censys search"),
        ("CENSYS_API_SECRET", config.censys_api_secret, "Censys search"),
        ("BINARYEDGE_API_KEY", config.binaryedge_api_key, "BinaryEdge subdomains"),
        ("FULLHUNT_API_KEY", config.fullhunt_api_key, "FullHunt subdomains"),
        ("PASSIVETOTAL_USERNAME", config.passivetotal_username, "PassiveTotal enrichment"),
        ("PASSIVETOTAL_API_KEY", config.passivetotal_api_key, "PassiveTotal enrichment"),
        ("SECURITYTRAILS_API_KEY", "", "SecurityTrails subdomains"),
    ]

    import os
    # Check SecurityTrails from env since it's not in config
    st_key = os.environ.get("SECURITYTRAILS_API_KEY", "")

    table = Table(title="API Keys")
    table.add_column("Key", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Purpose", style="dim")

    for name, val, purpose in keys:
        if name == "SECURITYTRAILS_API_KEY":
            val = st_key
        if val:
            masked = val[:4] + "..." + val[-4:] if len(val) > 8 else "***"
            status = f"[green]{masked}[/]"
        else:
            status = "[red]not set[/]"
        table.add_row(name, status, purpose)

    console.print(table)
    console.print()
    console.print("[dim]Set keys with:[/] surfacemap set-key KEY_NAME value")
    console.print("[dim]Or add to .env file / export in shell[/]")


@app.command(name="config")
def show_config() -> None:
    """Show all LLM and scan configuration settings.

    Example:
        surfacemap config
    """
    config = get_config()

    console.print()
    console.print("[bold cyan]LLM Configuration[/]")
    llm_table = Table(show_header=True, box=None, padding=(0, 2))
    llm_table.add_column("Setting", style="cyan")
    llm_table.add_column("Value")
    llm_table.add_column("Env Var", style="dim")

    llm_settings = [
        ("Provider", config.llm_provider, "SURFACEMAP_LLM_PROVIDER"),
        ("Primary Model", config.llm_model, "SURFACEMAP_LLM_MODEL"),
        ("Fallback Model", config.gemini_fallback_model, "SURFACEMAP_GEMINI_FALLBACK_MODEL"),
        ("Anthropic Model", config.anthropic_model, "SURFACEMAP_ANTHROPIC_MODEL"),
        ("OpenAI Model", config.openai_model, "SURFACEMAP_OPENAI_MODEL"),
        ("Max Tokens", str(config.llm_max_tokens), "SURFACEMAP_LLM_MAX_TOKENS"),
        ("Temperature", str(config.llm_temperature), "SURFACEMAP_LLM_TEMPERATURE"),
        ("Timeout", f"{config.llm_timeout}s", "SURFACEMAP_LLM_TIMEOUT"),
        ("Max Retries", str(config.llm_max_retries), "SURFACEMAP_LLM_MAX_RETRIES"),
        ("Retry Delay", f"{config.llm_retry_delay}s", "SURFACEMAP_LLM_RETRY_DELAY"),
    ]
    for name, val, env in llm_settings:
        llm_table.add_row(name, f"[bold]{val}[/]", env)
    console.print(llm_table)

    console.print()
    console.print("[bold cyan]Timeouts[/]")
    timeout_table = Table(show_header=True, box=None, padding=(0, 2))
    timeout_table.add_column("Setting", style="cyan")
    timeout_table.add_column("Value")
    timeout_table.add_column("Env Var", style="dim")

    timeout_settings = [
        ("HTTP Probe", f"{config.http_timeout}s", "SURFACEMAP_HTTP_TIMEOUT"),
        ("OSINT APIs", f"{config.osint_timeout}s", "SURFACEMAP_OSINT_TIMEOUT"),
        ("OSINT Connect", f"{config.osint_connect_timeout}s", "SURFACEMAP_OSINT_CONNECT_TIMEOUT"),
        ("DNS", f"{config.dns_timeout}s", "SURFACEMAP_DNS_TIMEOUT"),
        ("SSL/TLS", f"{config.ssl_timeout}s", "SURFACEMAP_SSL_TIMEOUT"),
        ("Subfinder", f"{config.subfinder_timeout}s", "SURFACEMAP_SUBFINDER_TIMEOUT"),
        ("Nmap Scan", f"{config.scan_timeout}s", "SURFACEMAP_SCAN_TIMEOUT"),
    ]
    for name, val, env in timeout_settings:
        timeout_table.add_row(name, f"[bold]{val}[/]", env)
    console.print(timeout_table)

    console.print()
    console.print("[bold cyan]Concurrency[/]")
    conc_table = Table(show_header=True, box=None, padding=(0, 2))
    conc_table.add_column("Setting", style="cyan")
    conc_table.add_column("Value")
    conc_table.add_column("Env Var", style="dim")

    conc_settings = [
        ("HTTP Probes", str(config.max_concurrent_probes), "SURFACEMAP_MAX_PROBES"),
        ("DNS Lookups", str(config.max_concurrent_dns), "SURFACEMAP_MAX_DNS"),
        ("SSL Checks", str(config.max_concurrent_ssl), "SURFACEMAP_MAX_SSL"),
        ("Path Probes", str(config.max_concurrent_paths), "SURFACEMAP_MAX_PATHS"),
        ("JS Analysis", str(config.max_concurrent_js), "SURFACEMAP_MAX_JS"),
    ]
    for name, val, env in conc_settings:
        conc_table.add_row(name, f"[bold]{val}[/]", env)
    console.print(conc_table)

    console.print()
    console.print("[bold cyan]Discovery Limits[/]")
    limit_table = Table(show_header=True, box=None, padding=(0, 2))
    limit_table.add_column("Setting", style="cyan")
    limit_table.add_column("Value")
    limit_table.add_column("Env Var", style="dim")

    limit_settings = [
        ("Max Subdomains", str(config.max_subdomains), "SURFACEMAP_MAX_SUBDOMAINS"),
        ("Max Extra Domains", str(config.max_extra_domains), "SURFACEMAP_MAX_EXTRA_DOMAINS"),
        ("Max Permutations", str(config.max_permutations), "SURFACEMAP_MAX_PERMUTATIONS"),
        ("Max IPs to Scan", str(config.max_ips_to_scan), "SURFACEMAP_MAX_IPS_TO_SCAN"),
        ("Nmap Args", config.nmap_args, "SURFACEMAP_NMAP_ARGS"),
        ("Output Dir", str(config.output_dir), "SURFACEMAP_OUTPUT_DIR"),
    ]
    for name, val, env in limit_settings:
        limit_table.add_row(name, f"[bold]{val}[/]", env)
    console.print(limit_table)

    console.print()
    console.print("[dim]Override any setting via environment variable or .env file[/]")
    console.print("[dim]Example: surfacemap set-key SURFACEMAP_LLM_MAX_TOKENS 32768[/]")
    console.print()


@app.command(name="set-config")
def set_config_value(
    name: str = typer.Argument(help="Config name (e.g. SURFACEMAP_LLM_MAX_TOKENS)"),
    value: str = typer.Argument(help="Value to set"),
) -> None:
    """Set a configuration value in the .env file.

    Examples:
        surfacemap set-config SURFACEMAP_LLM_MODEL gemini-2.0-flash
        surfacemap set-config SURFACEMAP_LLM_MAX_TOKENS 32768
        surfacemap set-config SURFACEMAP_MAX_CONCURRENT_DNS 500
        surfacemap set-config SURFACEMAP_HTTP_TIMEOUT 30
    """
    env_path = Path(".env")
    lines: list[str] = []
    found = False

    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                if line.strip().startswith(f"{name}="):
                    lines.append(f"{name}={value}\n")
                    found = True
                else:
                    lines.append(line)

    if not found:
        lines.append(f"{name}={value}\n")

    with open(env_path, "w") as f:
        f.writelines(lines)

    console.print(f"[green]Set {name}={value}[/] in .env")
    console.print("[dim]Restart surfacemap for changes to take effect[/]")


@app.command(name="export")
def export_assets(
    scan_file: str = typer.Argument(help="Path to scan JSON file (e.g. output/abc123.json)"),
    format: str = typer.Option("txt", "--format", "-f", help="Export format: txt, csv, json, domains, live, subdomains"),
    output: str = typer.Option(None, "--output", "-o", help="Output file path (default: stdout)"),
) -> None:
    """Export assets from a completed scan in various formats.

    Examples:
        surfacemap export output/abc123.json --format domains
        surfacemap export output/abc123.json --format live -o live_hosts.txt
        surfacemap export output/abc123.json --format subdomains
        surfacemap export output/abc123.json --format csv -o assets.csv
    """
    import json as _json

    try:
        with open(scan_file) as f:
            data = _json.load(f)
    except Exception as e:
        console.print(f"[red]Error loading {scan_file}:[/] {e}")
        raise typer.Exit(1)

    assets = data.get("assets", [])

    if format == "domains":
        lines = sorted({a["value"] for a in assets if a["type"] in ("domain", "subdomain")})
    elif format == "live":
        hosts: set[str] = set()
        for a in assets:
            if a["type"] == "url" and a["status"] in ("live", "redirect"):
                host = a["value"].split("://", 1)[-1].split("/", 1)[0]
                hosts.add(host)
            elif a["status"] == "live" and a["type"] in ("domain", "subdomain"):
                hosts.add(a["value"])
        lines = sorted(hosts)
    elif format == "subdomains":
        lines = sorted({a["value"] for a in assets if a["type"] == "subdomain"})
    elif format == "txt":
        lines = [a["value"] for a in assets]
    elif format == "csv":
        header = "value,type,status,severity,source"
        rows = [f'"{a["value"]}","{a["type"]}","{a["status"]}","{a["severity"]}","{a["source"]}"' for a in assets]
        lines = [header] + rows
    elif format == "json":
        content = _json.dumps(assets, indent=2)
        if output:
            Path(output).write_text(content)
            console.print(f"[green]Exported {len(assets)} assets to {output}[/]")
        else:
            print(content)
        return
    else:
        console.print(f"[red]Unknown format:[/] {format}")
        console.print("[dim]Available: txt, csv, json, domains, live, subdomains[/]")
        raise typer.Exit(1)

    content = "\n".join(lines)
    if output:
        Path(output).write_text(content)
        console.print(f"[green]Exported {len(lines)} items to {output}[/]")
    else:
        print(content)


@app.command()
def monitor(
    target: str = typer.Argument(help="Target to monitor"),
    domain: str = typer.Option(None, "--domain", "-d", help="Primary domain"),
    interval: str = typer.Option("24h", "--interval", "-i", help="Scan interval (e.g. 24h, 30m, 1d)"),
    enrich: bool = typer.Option(False, "--enrich", "-e", help="Enable enrichment"),
    passive_only: bool = typer.Option(False, "--passive-only", help="Passive only"),
) -> None:
    """Start continuous monitoring with diff alerts."""
    from surfacemap.scheduler.scheduler import run_scheduled_scan

    console.print(f"[bold cyan]Starting monitor for {target} every {interval}[/]")
    console.print("[dim]Press Ctrl+C to stop[/]")

    try:
        asyncio.run(run_scheduled_scan(
            target=target, domain=domain, interval=interval,
            enrich=enrich, passive_only=passive_only,
        ))
    except KeyboardInterrupt:
        console.print("\n[bold red]Monitor stopped[/]")


@app.command(name="diff")
def diff_scans(
    scan1: str = typer.Argument(help="Path to first scan JSON"),
    scan2: str = typer.Argument(help="Path to second scan JSON"),
) -> None:
    """Compare two scan results and show differences."""
    import json as _json
    from surfacemap.core.models import Asset, AssetType, AssetStatus, Severity, ScanResult
    from surfacemap.scheduler.differ import compute_diff, format_diff_summary

    def _load_scan(path: str) -> ScanResult:
        with open(path) as f:
            data = _json.load(f)
        sr = ScanResult(target=data["target"], scan_id=data["scan_id"])
        for a in data.get("assets", []):
            sr.add_asset(Asset(
                value=a["value"],
                type=AssetType(a["type"]),
                status=AssetStatus(a.get("status", "unknown")),
                severity=Severity(a.get("severity", "info")),
                source=a.get("source", ""),
            ))
        return sr

    try:
        old = _load_scan(scan1)
        new = _load_scan(scan2)
    except Exception as e:
        console.print(f"[red]Error loading scans:[/] {e}")
        raise typer.Exit(1)

    result = compute_diff(old, new)

    console.print()
    console.print(f"[bold cyan]Scan Diff[/]")
    console.print(f"  Old: {result['old_scan_id']} ({result['old_total']} assets)")
    console.print(f"  New: {result['new_scan_id']} ({result['new_total']} assets)")
    console.print()
    console.print(f"  [green]+{result['added_count']} added[/]  [red]-{result['removed_count']} removed[/]  [yellow]~{result['changed_count']} changed[/]")

    if result["new_critical_findings"]:
        console.print(f"\n  [bold red]New Critical/High Findings:[/]")
        for f_item in result["new_critical_findings"]:
            console.print(f"    [{f_item['severity']}] {f_item['type']}: {f_item['value']}")
    console.print()


@app.command()
def ui(
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to bind"),
) -> None:
    """Start the web UI dashboard."""
    try:
        import uvicorn
        from surfacemap.ui.app import ui_app
    except ImportError:
        console.print("[red]Install UI dependencies:[/] pip install 'surfacemap[ui]'")
        raise typer.Exit(1)

    console.print(f"[bold cyan]SurfaceMap Dashboard[/] starting at http://{host}:{port}")
    uvicorn.run(ui_app, host=host, port=port)


@app.command(name="plugins")
def list_plugins() -> None:
    """List all loaded plugins."""
    from surfacemap.plugins.loader import load_plugins
    from surfacemap.plugins.registry import get_registry

    load_plugins()
    registry = get_registry()
    plugins = registry.list_plugins()

    if not plugins:
        console.print("[dim]No plugins loaded.[/]")
        console.print("[dim]Place .py files in ~/.surfacemap/plugins/ or install packages with surfacemap.modules entry points.[/]")
        return

    table = Table(title="Loaded Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Phase")
    table.add_column("Description", style="dim")

    for p in plugins:
        table.add_row(p["name"], p["phase"], p["description"])

    console.print(table)


if __name__ == "__main__":
    app()
