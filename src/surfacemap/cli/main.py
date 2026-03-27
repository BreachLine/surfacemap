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
from rich.table import Table
from rich.tree import Tree

from surfacemap import __version__
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
    tree = Tree(
        f"[bold cyan]{result.target}[/] [dim]({result.scan_id})[/]"
    )

    # Group assets by type
    type_groups: dict[str, list[dict]] = {}
    for asset in result.assets:
        type_name = asset.type.value
        if type_name not in type_groups:
            type_groups[type_name] = []
        type_groups[type_name].append(asset.to_dict())

    # Add each type as a branch
    type_icons = {
        "domain": "globe",
        "subdomain": "link",
        "ip": "desktop_computer",
        "port": "electric_plug",
        "service": "gear",
        "cloud_bucket": "cloud",
        "email_server": "envelope",
        "nameserver": "satellite",
        "cdn": "rocket",
        "waf": "shield",
        "certificate": "lock",
        "github_repo": "file_folder",
        "social_media": "bust_in_silhouette",
        "url": "globe_with_meridians",
        "technology": "wrench",
        "subsidiary": "office_building",
    }

    for type_name, assets in sorted(type_groups.items()):
        icon = type_icons.get(type_name, "")
        branch = tree.add(
            f"[bold yellow]{type_name}[/] [dim]({len(assets)})[/]"
        )
        for asset in assets[:50]:  # Limit display
            status_color = {
                "live": "green",
                "down": "red",
                "redirect": "yellow",
                "filtered": "magenta",
                "unknown": "dim",
                "takeover_possible": "bold red",
            }.get(asset["status"], "dim")

            severity_badge = ""
            if asset["severity"] not in ("info", "unknown"):
                sev_color = {
                    "critical": "bold red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                }.get(asset["severity"], "dim")
                severity_badge = f" [{sev_color}][{asset['severity'].upper()}][/{sev_color}]"

            label = (
                f"[{status_color}]{asset['value']}[/{status_color}]"
                f" [{status_color}]({asset['status']})[/{status_color}]"
                f"{severity_badge}"
            )
            if asset.get("source"):
                label += f" [dim]via {asset['source']}[/]"
            branch.add(label)

        if len(assets) > 50:
            branch.add(f"[dim]... and {len(assets) - 50} more[/]")

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
) -> None:
    """Discover the attack surface of a company or domain.

    Examples:
        surfacemap discover "Google" --domain google.com
        surfacemap discover example.com --tree --json
        surfacemap discover "Acme Corp" -d acme.com --mindmap
    """
    from surfacemap.discovery.engine import DiscoveryEngine

    # If target looks like a domain, use it as both
    effective_domain = domain or target

    engine = DiscoveryEngine(target=target, domain=effective_domain)

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
    output_dir = Path(output) if output else Path("./output")
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

    # Mindmap
    if mindmap:
        try:
            from surfacemap.output.mindmap import generate_html_mindmap

            mindmap_path = output_dir / f"{result.scan_id}_mindmap.html"
            generate_html_mindmap(result, mindmap_path)
            console.print(f"\n[green]Mindmap saved to:[/] {mindmap_path}")
        except Exception as e:
            console.print(f"\n[red]Mindmap generation failed:[/] {e}")

    console.print()


@app.command()
def version() -> None:
    """Show the current SurfaceMap version."""
    console.print(f"[bold cyan]SurfaceMap[/] v{__version__}")


if __name__ == "__main__":
    app()
