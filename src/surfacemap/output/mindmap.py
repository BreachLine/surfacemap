"""Interactive HTML mindmap generator for SurfaceMap scan results."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

from surfacemap.core.models import AssetType, ScanResult


def _markdown_to_html(text: str) -> str:
    """Convert basic markdown to HTML for the mindmap panels."""
    lines = text.strip().split("\n")
    result_lines: list[str] = []
    in_list = False

    for line in lines:
        stripped = line.strip()
        if not stripped:
            if in_list:
                result_lines.append("</ol>")
                in_list = False
            result_lines.append("<br>")
            continue

        # Headers
        if stripped.startswith("### "):
            result_lines.append(f'<h4>{html.escape(stripped[4:])}</h4>')
            continue
        if stripped.startswith("## "):
            result_lines.append(f'<h3 style="color:#58a6ff;margin:12px 0 6px">{html.escape(stripped[3:])}</h3>')
            continue
        if stripped.startswith("# "):
            result_lines.append(f'<h2 style="color:#58a6ff;margin:12px 0 6px">{html.escape(stripped[2:])}</h2>')
            continue

        # Numbered list items
        list_match = re.match(r'^(\d+)\.\s+', stripped)
        if list_match:
            if not in_list:
                result_lines.append('<ol style="margin:4px 0;padding-left:20px">')
                in_list = True
            content = stripped[list_match.end():]
            content = _inline_markdown(content)
            result_lines.append(f"<li>{content}</li>")
            continue

        if in_list:
            result_lines.append("</ol>")
            in_list = False

        # Regular paragraph with inline formatting
        result_lines.append(f"<p>{_inline_markdown(stripped)}</p>")

    if in_list:
        result_lines.append("</ol>")

    return "\n".join(result_lines)


def _inline_markdown(text: str) -> str:
    """Convert inline markdown (bold, italic, code) to HTML."""
    # Escape HTML first
    text = html.escape(text)
    # Bold: **text** or __text__
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong style="color:#f0f6fc">\1</strong>', text)
    text = re.sub(r'__(.+?)__', r'<strong style="color:#f0f6fc">\1</strong>', text)
    # Italic: *text* or _text_
    text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
    # Code: `text`
    text = re.sub(r'`(.+?)`', r'<code style="background:#21262d;padding:1px 4px;border-radius:3px;color:#f0883e">\1</code>', text)
    return text


# ---------------------------------------------------------------------------
# Category mapping: which AssetTypes go into which tree branches
# ---------------------------------------------------------------------------

_CATEGORY_MAP: dict[str, list[AssetType]] = {
    "Domains & Subdomains": [AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.NAMESERVER, AssetType.CERTIFICATE],
    "Infrastructure": [AssetType.IP, AssetType.ASN, AssetType.IP_RANGE, AssetType.PORT, AssetType.SERVICE, AssetType.EMAIL_SERVER],
    "Web Assets": [AssetType.URL, AssetType.API_ENDPOINT, AssetType.TECHNOLOGY, AssetType.CDN, AssetType.WAF],
    "Cloud": [AssetType.CLOUD_BUCKET],
    "Security Findings": [AssetType.SENSITIVE_FILE, AssetType.CORS_MISCONFIGURATION, AssetType.COOKIE_ISSUE, AssetType.DNS_ISSUE, AssetType.SECRET_LEAK],
    "People & Social": [AssetType.EMAIL, AssetType.SOCIAL_MEDIA],
    "Intelligence": [AssetType.SUBSIDIARY, AssetType.WHOIS_RECORD, AssetType.GITHUB_REPO],
}

# Reverse lookup
_TYPE_TO_CATEGORY: dict[AssetType, str] = {}
for _cat, _types in _CATEGORY_MAP.items():
    for _t in _types:
        _TYPE_TO_CATEGORY[_t] = _cat

_CATEGORY_ICONS: dict[str, str] = {
    "Domains & Subdomains": "\U0001f310",
    "Infrastructure": "\U0001f5a7",
    "Web Assets": "\U0001f4bb",
    "Cloud": "\u2601\ufe0f",
    "Security Findings": "\U0001f6a8",
    "People & Social": "\U0001f465",
    "Intelligence": "\U0001f50d",
}


def _build_tree(result: ScanResult) -> dict[str, Any]:
    """Build a hierarchical tree from scan results using semantic categories.

    Within "Domains & Subdomains", subdomains are grouped under their
    parent domain when the *parent* field is set.
    """

    # Bucket assets by category then by type
    cat_type_assets: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for asset in result.assets:
        cat = _TYPE_TO_CATEGORY.get(asset.type, "Other")
        type_label = asset.type.value.replace("_", " ").title()
        node: dict[str, Any] = {
            "name": html.escape(asset.value),
            "severity": asset.severity.value,
            "status": asset.status.value,
            "source": asset.source,
            "notes": asset.notes or "",
            "parent_asset": asset.parent or "",
            "asset_type": asset.type.value,
            "metadata": {k: str(v) for k, v in (asset.metadata or {}).items()},
        }
        cat_type_assets.setdefault(cat, {}).setdefault(type_label, []).append(node)

    # Build children per category
    category_children: list[dict[str, Any]] = []
    for cat_name, type_list in _CATEGORY_MAP.items():
        if cat_name not in cat_type_assets:
            continue
        cat_data = cat_type_assets[cat_name]
        cat_total = sum(len(v) for v in cat_data.values())

        # Special handling for Domains & Subdomains: group subdomains under parent
        if cat_name == "Domains & Subdomains":
            type_children = _build_domain_subtree(cat_data)
        else:
            type_children = _build_flat_subtree(cat_data)

        category_children.append({
            "name": f"{cat_name} ({cat_total})",
            "category": cat_name,
            "children": type_children,
        })

    # Handle any uncategorised assets
    if "Other" in cat_type_assets:
        other = cat_type_assets["Other"]
        n = sum(len(v) for v in other.values())
        category_children.append({
            "name": f"Other ({n})",
            "category": "Other",
            "children": _build_flat_subtree(other),
        })

    # Risk grade badge on root
    grade = result.risk_grade or "?"
    root_name = html.escape(result.target)

    return {
        "name": root_name,
        "grade": grade,
        "children": category_children,
    }


def _build_domain_subtree(cat_data: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Group subdomains under their parent domain."""
    domains: dict[str, dict[str, Any]] = {}
    orphans: list[dict[str, Any]] = []

    # First pass: collect domains
    for a in cat_data.get("Domain", []):
        key = a["name"]
        domains[key] = {**a, "_sub": []}

    # Second pass: attach subdomains
    for a in cat_data.get("Subdomain", []):
        parent = a.get("parent_asset", "")
        if parent and parent in domains:
            domains[parent]["_sub"].append(_leaf(a))
        else:
            orphans.append(_leaf(a))

    # Build domain nodes (cap subs per domain for mindmap performance)
    children: list[dict[str, Any]] = []
    for dname, dinfo in sorted(domains.items()):
        subs = dinfo.pop("_sub")
        node = _leaf(dinfo)
        if subs:
            displayed = subs[:_MAX_LEAVES_PER_GROUP]
            remaining = len(subs) - len(displayed)
            if remaining > 0:
                displayed.append({
                    "name": f"... and {remaining} more",
                    "severity": "info", "status": "unknown", "source": "",
                    "notes": "", "metadata": {}, "size": 1,
                })
            node["children"] = displayed
            node["name"] = f"{dname} ({len(subs)} subs)"
        children.append(node)

    # Cap orphans too
    if len(orphans) > _MAX_LEAVES_PER_GROUP:
        remaining = len(orphans) - _MAX_LEAVES_PER_GROUP
        orphans = orphans[:_MAX_LEAVES_PER_GROUP]
        orphans.append({
            "name": f"... and {remaining} more",
            "severity": "info", "status": "unknown", "source": "",
            "notes": "", "metadata": {}, "size": 1,
        })
    children.extend(orphans)

    # Other types (nameserver, certificate)
    for type_label, assets in cat_data.items():
        if type_label in ("Domain", "Subdomain"):
            continue
        displayed = assets[:_MAX_LEAVES_PER_GROUP]
        type_node = {
            "name": f"{type_label} ({len(assets)})",
            "children": [_leaf(a) for a in displayed],
        }
        children.append(type_node)

    return children


_MAX_LEAVES_PER_GROUP = 200  # Cap for mindmap performance; full data in JSON export


def _build_flat_subtree(cat_data: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Build a flat type-grouped subtree."""
    children: list[dict[str, Any]] = []
    for type_label, assets in sorted(cat_data.items(), key=lambda x: -len(x[1])):
        if len(assets) == 1:
            node = _leaf(assets[0])
            node["name"] = f"{type_label}: {node['name']}"
            children.append(node)
        else:
            displayed = assets[:_MAX_LEAVES_PER_GROUP]
            remaining = len(assets) - len(displayed)
            leaf_nodes = [_leaf(a) for a in displayed]
            if remaining > 0:
                leaf_nodes.append({
                    "name": f"... and {remaining} more (see JSON export)",
                    "severity": "info", "status": "unknown", "source": "",
                    "notes": "", "metadata": {}, "size": 1,
                })
            children.append({
                "name": f"{type_label} ({len(assets)})",
                "children": leaf_nodes,
            })
    return children


def _leaf(a: dict[str, Any]) -> dict[str, Any]:
    """Create a leaf node dict for the D3 tree."""
    return {
        "name": a["name"],
        "severity": a.get("severity", "info"),
        "status": a.get("status", "unknown"),
        "source": a.get("source", ""),
        "notes": a.get("notes", ""),
        "metadata": a.get("metadata", {}),
        "size": 1,
    }


_SEVERITY_COLORS = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#3498db",
    "info": "#95a5a6",
}

_GRADE_COLORS = {
    "A": "#2ecc71",
    "B": "#00bcd4",
    "C": "#f1c40f",
    "D": "#e67e22",
    "F": "#e74c3c",
}

_STATUS_COLORS = {
    "live": "#2ecc71",
    "down": "#95a5a6",
    "redirect": "#3498db",
    "filtered": "#8b949e",
    "unknown": "#6e7681",
    "takeover_possible": "#e74c3c",
    "vulnerable": "#ff1744",
    "misconfigured": "#ff9800",
}

# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<title>SurfaceMap &mdash; {target}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: #09090b;
    color: #a1a1aa;
    overflow: hidden;
    -webkit-font-smoothing: antialiased;
  }}

  /* ---- Header ---- */
  #header {{
    position: fixed; top: 0; left: 0; right: 0; z-index: 10;
    background: rgba(9,9,11,0.85); backdrop-filter: blur(16px) saturate(180%);
    padding: 12px 28px; display: flex; align-items: center; gap: 20px;
    border-bottom: 1px solid rgba(255,255,255,0.06);
  }}
  #header h1 {{ font-size: 14px; color: #e4e4e7; font-weight: 500; white-space: nowrap; letter-spacing: -0.3px; }}
  #header .stats {{ font-size: 12px; color: #71717a; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
  #header .stat-pill {{
    display: inline-flex; align-items: center; gap: 4px;
    background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.06);
    border-radius: 6px; padding: 3px 10px; font-size: 11px;
  }}
  .grade-badge {{
    display: inline-flex; align-items: center; justify-content: center;
    width: 28px; height: 28px; border-radius: 6px; font-weight: 600;
    font-size: 14px; color: #09090b;
  }}
  .risk-label {{ font-size: 10px; color: #52525b; margin-right: -4px; text-transform: uppercase; letter-spacing: 0.5px; }}

  /* ---- Legend ---- */
  #legend {{
    position: fixed; bottom: 16px; left: 16px; z-index: 10;
    background: rgba(9,9,11,0.88); border: 1px solid rgba(255,255,255,0.06);
    border-radius: 10px; padding: 14px 18px; font-size: 11px;
    backdrop-filter: blur(16px) saturate(180%);
  }}
  #legend .section-title {{ color: #a1a1aa; font-weight: 500; margin: 8px 0 4px; font-size: 9px; text-transform: uppercase; letter-spacing: 1px; }}
  #legend .section-title:first-child {{ margin-top: 0; }}
  #legend .item {{ display: flex; align-items: center; gap: 6px; margin: 3px 0; color: #71717a; }}
  #legend .dot {{ width: 7px; height: 7px; border-radius: 50%; display: inline-block; flex-shrink: 0; }}

  /* ---- Tooltip ---- */
  #tooltip {{
    position: absolute; pointer-events: none; display: none;
    background: rgba(24,24,27,0.96); border: 1px solid rgba(255,255,255,0.08);
    border-radius: 10px; padding: 12px 16px; font-size: 12px;
    max-width: 420px; min-width: 180px;
    box-shadow: 0 12px 40px rgba(0,0,0,0.6); z-index: 30;
    backdrop-filter: blur(12px);
  }}
  #tooltip .tip-name {{ color: #fafafa; font-weight: 500; word-break: break-all; margin-bottom: 8px; letter-spacing: -0.2px; }}
  #tooltip .tip-row {{ color: #a1a1aa; margin: 3px 0; display: flex; gap: 6px; font-size: 11px; }}
  #tooltip .tip-row .label {{ color: #52525b; min-width: 58px; }}
  #tooltip .tip-severity {{
    display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 9px;
    font-weight: 600; text-transform: uppercase; color: #09090b;
  }}
  #tooltip .tip-status {{
    display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 9px;
    font-weight: 600; color: #09090b;
  }}

  /* ---- Technologies panel ---- */
  #tech-panel {{
    position: fixed; top: 52px; right: 16px; z-index: 10;
    background: rgba(9,9,11,0.88); border: 1px solid rgba(255,255,255,0.06);
    border-radius: 10px; padding: 14px 16px; font-size: 11px;
    max-width: 260px; max-height: 40vh; overflow-y: auto;
    backdrop-filter: blur(16px) saturate(180%); display: {tech_display};
  }}
  #tech-panel .panel-title {{
    color: #a1a1aa; font-weight: 500; font-size: 9px; margin-bottom: 10px;
    text-transform: uppercase; letter-spacing: 1px;
  }}
  #tech-panel .badges {{ display: flex; flex-wrap: wrap; gap: 4px; }}
  .tech-badge {{
    display: inline-block; padding: 3px 8px; border-radius: 4px;
    background: rgba(161,161,170,0.08); color: #a1a1aa; font-size: 10px;
    border: 1px solid rgba(255,255,255,0.06); white-space: nowrap;
    font-family: 'JetBrains Mono', 'SF Mono', monospace;
  }}

  /* ---- Collapsible panels ---- */
  .panel-collapsible {{
    position: fixed; z-index: 10;
    background: rgba(9,9,11,0.92); border: 1px solid rgba(255,255,255,0.06);
    border-radius: 10px; backdrop-filter: blur(16px) saturate(180%);
    overflow: hidden; transition: max-height 0.3s ease;
  }}
  .panel-header {{
    padding: 10px 16px; cursor: pointer; display: flex;
    align-items: center; justify-content: space-between;
    border-bottom: 1px solid rgba(255,255,255,0.04);
  }}
  .panel-header:hover {{ background: rgba(255,255,255,0.02); }}
  .panel-header .panel-title {{ color: #e4e4e7; font-weight: 500; font-size: 10px; text-transform: uppercase; letter-spacing: 0.8px; }}
  .panel-header .chevron {{ color: #52525b; transition: transform 0.2s; font-size: 12px; }}
  .panel-body {{ padding: 12px 16px; font-size: 12px; color: #a1a1aa; max-height: 300px; overflow-y: auto; line-height: 1.6; }}
  .panel-body.collapsed {{ display: none; }}

  /* Executive summary */
  #exec-panel {{
    bottom: 16px; left: 50%; transform: translateX(-50%);
    width: min(700px, 80vw); display: {exec_display};
  }}
  #exec-panel .panel-body p {{ margin: 6px 0; line-height: 1.6; }}

  /* Attack paths */
  #attack-panel {{
    top: 52px; right: 16px; width: min(340px, 35vw); display: {attack_display};
    margin-top: {attack_top_offset};
  }}
  #attack-panel .path-item {{
    margin: 8px 0; padding: 10px 12px; border-radius: 8px;
    background: rgba(255,255,255,0.02); border-left: 2px solid rgba(255,255,255,0.1);
  }}
  #attack-panel .path-header {{
    display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;
  }}
  #attack-panel .path-name {{ font-weight: 600; color: #f0f6fc; }}
  #attack-panel .path-sev {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 9px; font-weight: 700; text-transform: uppercase;
    color: #0a0e17; flex-shrink: 0;
  }}
  #attack-panel .path-steps {{
    margin: 6px 0 4px; padding-left: 20px; color: #8b949e;
    font-size: 11px; line-height: 1.6;
  }}
  #attack-panel .path-steps li {{ margin: 2px 0; }}
  #attack-panel .path-assets {{
    margin-top: 6px; display: flex; flex-wrap: wrap; gap: 4px;
  }}
  #attack-panel .path-asset {{
    background: #21262d; padding: 1px 6px; border-radius: 3px;
    font-size: 10px; color: #f0883e; font-family: monospace;
  }}
  /* Executive summary styling */
  #exec-body p {{ margin: 6px 0; line-height: 1.5; }}
  #exec-body h2, #exec-body h3, #exec-body h4 {{ margin: 10px 0 4px; }}
  #exec-body ol {{ margin: 4px 0; }}
  #exec-body li {{ margin: 3px 0; line-height: 1.5; }}

  /* Live domains table */
  #live-panel {{
    position: fixed; top: 52px; left: 16px; z-index: 10;
    width: 420px; max-height: 50vh;
    background: rgba(9,9,11,0.90); border: 1px solid rgba(255,255,255,0.06);
    border-radius: 10px; font-size: 12px; overflow: hidden;
    backdrop-filter: blur(16px) saturate(180%);
  }}
  .live-table {{ width: 100%; border-collapse: collapse; }}
  .live-table th {{
    text-align: left; padding: 6px 10px; color: #52525b;
    border-bottom: 1px solid rgba(255,255,255,0.04); font-size: 9px;
    text-transform: uppercase; letter-spacing: 0.8px;
  }}
  .live-table td {{ padding: 4px 10px; border-bottom: 1px solid rgba(255,255,255,0.03); }}
  .live-table td:first-child {{ color: #e4e4e7; font-family: 'JetBrains Mono', monospace; font-size: 10px; }}
  .live-table tr:hover {{ background: rgba(255,255,255,0.02); }}
  .live-table .status-live {{ color: #22c55e; font-size: 10px; }}
  .live-table .status-redirect {{ color: #eab308; font-size: 10px; }}
  .live-table .tech-tag {{
    background: rgba(255,255,255,0.04); padding: 1px 5px; border-radius: 3px;
    font-size: 9px; color: #71717a; margin-right: 2px;
    border: 1px solid rgba(255,255,255,0.04);
  }}
  #live-body {{ max-height: 40vh; overflow-y: auto; }}

  /* ---- View Toggle ---- */
  #view-toggle {{
    position: fixed; top: 52px; left: 50%; transform: translateX(-50%);
    z-index: 15; display: flex; gap: 0;
    background: rgba(9,9,11,0.9); border: 1px solid rgba(255,255,255,0.06);
    border-radius: 8px; padding: 3px; backdrop-filter: blur(16px);
  }}
  .view-btn {{
    padding: 6px 20px; border: none; background: transparent;
    color: #71717a; font-size: 11px; font-weight: 500; cursor: pointer;
    border-radius: 6px; font-family: inherit; letter-spacing: 0.3px;
    transition: all 0.2s;
  }}
  .view-btn.active {{ background: rgba(255,255,255,0.08); color: #e4e4e7; }}
  .view-btn:hover {{ color: #e4e4e7; }}

  /* ---- Dashboard View ---- */
  #dashboard-view {{
    padding: 70px 28px 28px; min-height: 100vh; overflow-y: auto;
  }}
  .dash-grid {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;
    margin-bottom: 20px;
  }}
  .dash-card {{
    background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06);
    border-radius: 10px; padding: 16px 20px;
  }}
  .dash-card-title {{
    font-size: 10px; color: #52525b; text-transform: uppercase;
    letter-spacing: 0.8px; margin-bottom: 6px;
  }}
  .dash-card-value {{ font-size: 28px; font-weight: 600; color: #e4e4e7; }}
  .dash-card-breakdown {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 4px; }}
  .sev-chip {{
    display: flex; align-items: center; gap: 4px; font-size: 11px;
    padding: 2px 8px; border-radius: 4px;
    background: rgba(255,255,255,0.03);
  }}
  .sev-chip .sev-dot {{ width: 6px; height: 6px; border-radius: 50%; }}

  /* Table */
  .dash-table-section {{
    background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06);
    border-radius: 10px; overflow: hidden;
  }}
  .dash-table-header {{
    padding: 12px 16px; display: flex; gap: 8px; align-items: center;
    border-bottom: 1px solid rgba(255,255,255,0.04); flex-wrap: wrap;
  }}
  .dash-table-header input, .dash-table-header select {{
    background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08);
    border-radius: 6px; padding: 6px 10px; color: #e4e4e7; font-size: 12px;
    font-family: inherit; outline: none;
  }}
  .dash-table-header input {{ flex: 1; min-width: 200px; }}
  .dash-table-header input::placeholder {{ color: #52525b; }}
  .dash-table-header input:focus, .dash-table-header select:focus {{
    border-color: rgba(255,255,255,0.15);
  }}
  .dash-table-wrap {{ max-height: 70vh; overflow-y: auto; }}
  #asset-table {{ width: 100%; border-collapse: collapse; }}
  #asset-table th {{
    text-align: left; padding: 8px 12px; color: #52525b; font-size: 9px;
    text-transform: uppercase; letter-spacing: 0.8px; cursor: pointer;
    border-bottom: 1px solid rgba(255,255,255,0.04); position: sticky; top: 0;
    background: rgba(9,9,11,0.98); user-select: none;
  }}
  #asset-table th:hover {{ color: #a1a1aa; }}
  #asset-table td {{
    padding: 6px 12px; border-bottom: 1px solid rgba(255,255,255,0.02);
    font-size: 12px; color: #a1a1aa;
  }}
  #asset-table td:first-child {{
    font-family: 'JetBrains Mono', 'SF Mono', monospace; font-size: 11px;
    color: #e4e4e7; max-width: 400px; overflow: hidden; text-overflow: ellipsis;
    white-space: nowrap;
  }}
  #asset-table tr:hover {{ background: rgba(255,255,255,0.02); }}
  #asset-table tr.hidden {{ display: none; }}
  .dash-table-footer {{
    padding: 8px 16px; font-size: 11px; color: #52525b;
    border-top: 1px solid rgba(255,255,255,0.04);
  }}
  .sev-tag {{
    display: inline-block; padding: 1px 6px; border-radius: 3px;
    font-size: 9px; font-weight: 600; text-transform: uppercase;
  }}
  .sev-tag-critical {{ background: rgba(239,68,68,0.15); color: #ef4444; }}
  .sev-tag-high {{ background: rgba(249,115,22,0.15); color: #f97316; }}
  .sev-tag-medium {{ background: rgba(234,179,8,0.15); color: #eab308; }}
  .sev-tag-low {{ background: rgba(59,130,246,0.15); color: #3b82f6; }}
  .sev-tag-info {{ background: rgba(161,161,170,0.08); color: #71717a; }}
  .status-tag {{ font-size: 10px; }}
  .status-tag-live {{ color: #22c55e; }}
  .status-tag-down {{ color: #ef4444; }}
  .status-tag-redirect {{ color: #eab308; }}
  .status-tag-unknown {{ color: #52525b; }}
  .status-tag-takeover_possible {{ color: #ef4444; font-weight: 600; }}
  .status-tag-vulnerable {{ color: #ef4444; font-weight: 600; }}

  .export-btn {{
    padding: 5px 12px; border: 1px solid rgba(255,255,255,0.1);
    background: rgba(255,255,255,0.04); color: #a1a1aa; font-size: 10px;
    border-radius: 5px; cursor: pointer; font-family: inherit;
    font-weight: 500; letter-spacing: 0.3px; transition: all 0.15s;
  }}
  .export-btn:hover {{ background: rgba(255,255,255,0.08); color: #e4e4e7; }}

  @media (max-width: 768px) {{
    .dash-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .dash-table-header {{ flex-direction: column; }}
    .dash-table-header input {{ min-width: 100%; }}
  }}

  /* ---- SVG / D3 tree ---- */
  #tree-svg {{ width: 100vw; height: 100vh; }}
  .link {{ fill: none; stroke: rgba(255,255,255,0.06); stroke-width: 1; }}
  .node circle {{ cursor: pointer; stroke-width: 1.5; transition: r 0.2s; }}
  .node circle:hover {{ r: 8; }}
  .node text {{ font-size: 11px; fill: #a1a1aa; pointer-events: none; font-family: 'JetBrains Mono', 'SF Mono', monospace; font-weight: 400; }}
  .sev-badge {{
    font-size: 8px; font-weight: 600; text-transform: uppercase;
    pointer-events: none; letter-spacing: 0.3px;
  }}

  /* ---- Scrollbar ---- */
  ::-webkit-scrollbar {{ width: 4px; }}
  ::-webkit-scrollbar-track {{ background: transparent; }}
  ::-webkit-scrollbar-thumb {{ background: rgba(255,255,255,0.08); border-radius: 4px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: rgba(255,255,255,0.15); }}
</style>
</head>
<body>

<!-- Header -->
<div id="header">
  <div style="display:flex;align-items:center;gap:10px">
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
      <path d="M12 2L2 7v10l10 5 10-5V7L12 2z" stroke="#e4e4e7" stroke-width="1.5" fill="none"/>
      <path d="M12 7l-5 2.5v5L12 17l5-2.5v-5L12 7z" fill="#e4e4e7" opacity="0.15"/>
      <circle cx="12" cy="12" r="2" fill="#e4e4e7"/>
    </svg>
    <div>
      <h1 style="font-size:13px;color:#e4e4e7;font-weight:500;letter-spacing:-0.3px">SurfaceMap</h1>
      <div style="font-size:9px;color:#52525b;letter-spacing:0.5px;margin-top:1px">BY BREACHLINE LABS</div>
    </div>
  </div>
  <div style="width:1px;height:24px;background:rgba(255,255,255,0.06)"></div>
  <div class="stats">
    <span style="color:#a1a1aa;font-weight:500">{target}</span>
    <span class="stat-pill">Assets <strong>{total}</strong></span>
    <span class="stat-pill">Live <strong style="color:#22c55e">{live}</strong></span>
    {risk_html}
  </div>
</div>

<!-- Legend -->
<div id="legend">
  <div class="section-title">Severity</div>
  <div class="item"><span class="dot" style="background:#e74c3c"></span> Critical</div>
  <div class="item"><span class="dot" style="background:#e67e22"></span> High</div>
  <div class="item"><span class="dot" style="background:#f1c40f"></span> Medium</div>
  <div class="item"><span class="dot" style="background:#3498db"></span> Low</div>
  <div class="item"><span class="dot" style="background:#95a5a6"></span> Info</div>
  <div class="section-title">Status</div>
  <div class="item"><span class="dot" style="background:#2ecc71"></span> Live</div>
  <div class="item"><span class="dot" style="background:#ff1744"></span> Vulnerable</div>
  <div class="item"><span class="dot" style="background:#ff9800"></span> Misconfigured</div>
  <div class="item"><span class="dot" style="background:#e74c3c"></span> Takeover</div>
  <div class="item"><span class="dot" style="background:#3498db"></span> Redirect</div>
  <div class="item"><span class="dot" style="background:#6e7681"></span> Unknown</div>
</div>

<!-- Live Domains Dashboard -->
<div id="live-panel" style="display:{live_panel_display}">
  <div class="panel-header" onclick="togglePanel('live-body')">
    <span class="panel-title">Live Domains ({live_count})</span>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="panel-body collapsed" id="live-body">
    <table class="live-table">
      <thead><tr><th>Host</th><th>Status</th><th>Tech</th></tr></thead>
      <tbody>{live_rows_html}</tbody>
    </table>
  </div>
</div>

<!-- Watermark -->
<div style="position:fixed;bottom:16px;right:16px;z-index:5;display:flex;align-items:center;gap:6px;opacity:0.3">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
    <path d="M12 2L2 7v10l10 5 10-5V7L12 2z" stroke="#a1a1aa" stroke-width="1.5" fill="none"/>
    <circle cx="12" cy="12" r="2" fill="#a1a1aa"/>
  </svg>
  <span style="font-size:9px;color:#52525b;letter-spacing:0.5px;font-family:Inter,sans-serif">BREACHLINE LABS</span>
</div>

<!-- Tooltip -->
<div id="tooltip">
  <div class="tip-name"></div>
  <div class="tip-details"></div>
</div>

<!-- Technologies panel -->
<div id="tech-panel">
  <div class="panel-title">Technologies</div>
  <div class="badges">{tech_badges}</div>
</div>

<!-- Executive Summary panel -->
<div id="exec-panel" class="panel-collapsible">
  <div class="panel-header" onclick="togglePanel('exec-body')">
    <span class="panel-title">Executive Summary</span>
    <span class="chevron" id="exec-chevron">&#9660;</span>
  </div>
  <div class="panel-body collapsed" id="exec-body">{exec_summary_html}</div>
</div>

<!-- Attack Paths panel -->
<div id="attack-panel" class="panel-collapsible">
  <div class="panel-header" onclick="togglePanel('attack-body')">
    <span class="panel-title">Attack Paths</span>
    <span class="chevron" id="attack-chevron">&#9660;</span>
  </div>
  <div class="panel-body collapsed" id="attack-body">{attack_paths_html}</div>
</div>

<!-- View Toggle -->
<div id="view-toggle">
  <button class="view-btn active" onclick="switchView('mindmap')">Mindmap</button>
  <button class="view-btn" onclick="switchView('dashboard')">Dashboard</button>
</div>

<!-- Mindmap View -->
<div id="mindmap-view">
  <svg id="tree-svg"></svg>
</div>

<!-- Dashboard View -->
<div id="dashboard-view" style="display:none">
  <div class="dash-grid">
    <div class="dash-card">
      <div class="dash-card-title">Total Assets</div>
      <div class="dash-card-value">{total}</div>
    </div>
    <div class="dash-card">
      <div class="dash-card-title">Live Hosts</div>
      <div class="dash-card-value" style="color:#22c55e">{live}</div>
    </div>
    <div class="dash-card">
      <div class="dash-card-title">Risk Score</div>
      <div class="dash-card-value" style="color:{risk_color}">{risk_display}</div>
    </div>
    <div class="dash-card">
      <div class="dash-card-title">Severity</div>
      <div class="dash-card-breakdown">{severity_breakdown_html}</div>
    </div>
  </div>

  <div class="dash-table-section">
    <div class="dash-table-header">
      <input type="text" id="asset-search" placeholder="Search assets..." onkeyup="filterAssets()">
      <select id="type-filter" onchange="filterAssets()">
        <option value="">All Types</option>
        {type_options_html}
      </select>
      <select id="severity-filter" onchange="filterAssets()">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
      <select id="status-filter" onchange="filterAssets()">
        <option value="">All Statuses</option>
        <option value="live">Live</option>
        <option value="down">Down</option>
        <option value="redirect">Redirect</option>
        <option value="unknown">Unknown</option>
        <option value="takeover_possible">Takeover</option>
      </select>
      <div style="display:flex;gap:4px;margin-left:auto">
        <button class="export-btn" onclick="exportVisible('txt')">TXT</button>
        <button class="export-btn" onclick="exportVisible('csv')">CSV</button>
        <button class="export-btn" onclick="exportVisible('json')">JSON</button>
      </div>
    </div>
    <div class="dash-table-wrap">
      <table id="asset-table">
        <thead>
          <tr>
            <th onclick="sortTable(0)">Value</th>
            <th onclick="sortTable(1)">Type</th>
            <th onclick="sortTable(2)">Status</th>
            <th onclick="sortTable(3)">Severity</th>
            <th onclick="sortTable(4)">Source</th>
          </tr>
        </thead>
        <tbody id="asset-tbody">
          {asset_rows_html}
        </tbody>
      </table>
    </div>
    <div class="dash-table-footer" id="table-footer">Showing all assets</div>
  </div>
</div>

<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
// ---- Data ----
const data = {tree_json};
const severityColor = {severity_json};
const statusColor = {status_json};

// ---- Panel toggle ----
function togglePanel(bodyId) {{
  const body = document.getElementById(bodyId);
  const chevron = document.getElementById(bodyId.replace('-body', '-chevron'));
  body.classList.toggle('collapsed');
  if (chevron) chevron.style.transform = body.classList.contains('collapsed') ? '' : 'rotate(180deg)';
}}

// ---- D3 tree ----
const width = window.innerWidth;
const height = window.innerHeight;
const svg = d3.select("#tree-svg").attr("width", width).attr("height", height);
const g = svg.append("g").attr("transform", "translate(240, 0)");

svg.call(d3.zoom().scaleExtent([0.15, 5]).on("zoom", e => g.attr("transform", e.transform)));

const root = d3.hierarchy(data);
root.x0 = height / 2;
root.y0 = 0;

// Collapse ALL children by default for performance
// User clicks to expand what they want to see
function collapseAll(node) {{
  if (node.children) {{
    node.children.forEach(collapseAll);
    node._children = node.children;
    node.children = null;
  }}
}}
// Only keep root's immediate children (categories) visible
if (root.children) {{
  root.children.forEach(child => collapseAll(child));
}}

const treelayout = d3.tree().nodeSize([20, 280]);
const tooltip = d3.select("#tooltip");
const tipName = tooltip.select(".tip-name");
const tipDetails = tooltip.select(".tip-details");

let nodeId = 0;
update(root);

function update(source) {{
  const treeData = treelayout(root);
  const nodes = treeData.descendants();
  const links = treeData.links();

  nodes.forEach(d => {{ d.y = d.depth * 300; }});

  // ---- Nodes ----
  const node = g.selectAll("g.node").data(nodes, d => d.id || (d.id = ++nodeId));

  const nodeEnter = node.enter().append("g")
    .attr("class", "node")
    .attr("transform", () => `translate(${{source.y0}},${{source.x0}})`)
    .on("click", (e, d) => {{
      if (d.children) {{ d._children = d.children; d.children = null; }}
      else if (d._children) {{ d.children = d._children; d._children = null; }}
      update(d);
    }})
    .on("mouseover", (e, d) => {{
      const dd = d.data;
      tipName.text(dd.name);
      let html = '';
      if (dd.severity && dd.severity !== 'info') {{
        const col = severityColor[dd.severity] || '#95a5a6';
        html += '<div class="tip-row"><span class="label">Severity</span> <span class="tip-severity" style="background:' + col + '">' + dd.severity + '</span></div>';
      }}
      if (dd.status) {{
        const scol = statusColor[dd.status] || '#6e7681';
        html += '<div class="tip-row"><span class="label">Status</span> <span class="tip-status" style="background:' + scol + '">' + dd.status + '</span></div>';
      }}
      if (dd.source) html += '<div class="tip-row"><span class="label">Source</span> ' + dd.source + '</div>';
      if (dd.notes) html += '<div class="tip-row"><span class="label">Notes</span> ' + dd.notes + '</div>';
      if (dd.metadata && typeof dd.metadata === 'object') {{
        Object.entries(dd.metadata).forEach(([k,v]) => {{
          if (v) html += '<div class="tip-row"><span class="label">' + k + '</span> ' + v + '</div>';
        }});
      }}
      if (dd.category) html += '<div class="tip-row"><span class="label">Group</span> ' + dd.category + '</div>';
      tipDetails.html(html);
      tooltip.style("display", "block");
    }})
    .on("mousemove", (e) => {{
      tooltip.style("left", (e.pageX + 16) + "px").style("top", (e.pageY - 14) + "px");
    }})
    .on("mouseout", () => tooltip.style("display", "none"));

  // Node circles
  nodeEnter.append("circle")
    .attr("r", d => {{
      if (d.depth === 0) return 10;
      if (d.depth === 1) return 7;
      if (d.children || d._children) return 5;
      return 3.5;
    }})
    .style("fill", d => {{
      if (d.depth === 0) return "{root_color}";
      if (d.data.status === 'vulnerable') return '#ff1744';
      if (d.data.status === 'misconfigured') return '#ff9800';
      if (d.data.status === 'takeover_possible') return '#e74c3c';
      if (d.data.severity && d.data.severity !== 'info') return severityColor[d.data.severity] || '#95a5a6';
      if (d.depth === 1) return '#30363d';
      return '#30363d';
    }})
    .style("stroke", d => {{
      if (d._children) return "#f0f6fc";
      if (d.depth === 0) return "{root_stroke}";
      if (d.depth === 1) return '#21262d';
      return '#21262d';
    }});

  // Node label
  nodeEnter.append("text")
    .attr("dy", "0.35em")
    .attr("x", d => d.children || d._children ? -14 : 8)
    .attr("text-anchor", d => d.children || d._children ? "end" : "start")
    .text(d => {{
      const name = d.data.name;
      return name.length > 60 ? name.slice(0, 57) + "..." : name;
    }})
    .style("font-weight", d => d.depth <= 1 ? "600" : "normal")
    .style("font-size", d => d.depth === 0 ? "13px" : d.depth === 1 ? "12px" : "11px")
    .style("fill", d => {{
      if (d.depth === 0) return "#f0f6fc";
      if (d.depth === 1) return "#58a6ff";
      return "#c9d1d9";
    }});

  // Severity badge inline (for non-info leaf nodes)
  nodeEnter.filter(d => d.data.severity && d.data.severity !== 'info' && !d.children && !d._children)
    .append("text")
    .attr("class", "sev-badge")
    .attr("dy", "0.35em")
    .attr("x", d => {{
      const name = d.data.name;
      const truncated = name.length > 60 ? name.slice(0, 57) + "..." : name;
      return 8 + truncated.length * 5.8 + 8;
    }})
    .text(d => d.data.severity.toUpperCase())
    .style("fill", d => severityColor[d.data.severity] || '#95a5a6');

  // Collapsed children count badge
  nodeEnter.filter(d => d._children && d._children.length > 0)
    .append("text")
    .attr("dy", "-0.8em")
    .attr("x", 0)
    .attr("text-anchor", "middle")
    .style("font-size", "9px")
    .style("fill", "#6e7681")
    .text(d => "+" + (d._children ? d._children.length : ""));

  // ---- Transitions ----
  const nodeUpdate = nodeEnter.merge(node);
  nodeUpdate.transition().duration(350)
    .attr("transform", d => `translate(${{d.y}},${{d.x}})`);

  const nodeExit = node.exit().transition().duration(350)
    .attr("transform", () => `translate(${{source.y}},${{source.x}})`)
    .remove();
  nodeExit.select("circle").attr("r", 1e-6);
  nodeExit.select("text").style("fill-opacity", 1e-6);

  // ---- Links ----
  const link = g.selectAll("path.link").data(links, d => d.target.id);

  const linkEnter = link.enter().insert("path", "g")
    .attr("class", "link")
    .attr("d", () => {{
      const o = {{ x: source.x0, y: source.y0 }};
      return diagonal(o, o);
    }})
    .style("stroke", d => {{
      const sev = d.target.data.severity;
      if (sev && sev !== 'info') return severityColor[sev] ? severityColor[sev] + '40' : '#21262d';
      return '#21262d';
    }});

  linkEnter.merge(link).transition().duration(350)
    .attr("d", d => diagonal(d.source, d.target));

  link.exit().transition().duration(350)
    .attr("d", () => {{
      const o = {{ x: source.x, y: source.y }};
      return diagonal(o, o);
    }}).remove();

  nodes.forEach(d => {{ d.x0 = d.x; d.y0 = d.y; }});
}}

function diagonal(s, d) {{
  return `M ${{s.y}} ${{s.x}}
          C ${{(s.y + d.y) / 2}} ${{s.x}},
            ${{(s.y + d.y) / 2}} ${{d.x}},
            ${{d.y}} ${{d.x}}`;
}}

// Center on root initially
(function() {{
  const initialTransform = d3.zoomIdentity.translate(240, height / 2).scale(0.85);
  svg.call(d3.zoom().scaleExtent([0.15, 5]).on("zoom", e => g.attr("transform", e.transform))
    .transform, initialTransform);
  g.attr("transform", initialTransform);
}})();

// ---- View Switching ----
function switchView(view) {{
  document.getElementById('mindmap-view').style.display = view === 'mindmap' ? 'block' : 'none';
  document.getElementById('dashboard-view').style.display = view === 'dashboard' ? 'block' : 'none';
  // Toggle panels visibility
  const panels = ['legend','tech-panel','exec-panel','attack-panel','live-panel'];
  panels.forEach(id => {{
    const el = document.getElementById(id);
    if (el) el.style.display = view === 'mindmap' ? (el.dataset.origDisplay || 'block') : 'none';
  }});
  // Update buttons
  document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
}}
// Store original display values
document.addEventListener('DOMContentLoaded', () => {{
  ['legend','tech-panel','exec-panel','attack-panel','live-panel'].forEach(id => {{
    const el = document.getElementById(id);
    if (el) el.dataset.origDisplay = el.style.display || getComputedStyle(el).display;
  }});
}});

// ---- Dashboard filtering ----
function filterAssets() {{
  const search = (document.getElementById('asset-search').value || '').toLowerCase();
  const typeF = document.getElementById('type-filter').value;
  const sevF = document.getElementById('severity-filter').value;
  const statusF = document.getElementById('status-filter').value;
  const rows = document.querySelectorAll('#asset-tbody tr');
  let shown = 0;
  rows.forEach(row => {{
    const val = (row.cells[0].textContent || '').toLowerCase();
    const type = row.dataset.type || '';
    const sev = row.dataset.severity || '';
    const status = row.dataset.status || '';
    const match = (!search || val.includes(search))
      && (!typeF || type === typeF)
      && (!sevF || sev === sevF)
      && (!statusF || status === statusF);
    row.style.display = match ? '' : 'none';
    if (match) shown++;
  }});
  document.getElementById('table-footer').textContent = `Showing ${{shown}} of ${{rows.length}} assets`;
}}

// ---- Export visible rows ----
function exportVisible(format) {{
  const rows = document.querySelectorAll('#asset-tbody tr');
  const visible = [];
  rows.forEach(row => {{
    if (row.style.display !== 'none') {{
      visible.push({{
        value: row.cells[0].textContent,
        type: row.dataset.type,
        status: row.dataset.status,
        severity: row.dataset.severity,
        source: row.cells[4].textContent,
      }});
    }}
  }});

  let content, filename, mime;
  if (format === 'txt') {{
    content = visible.map(r => r.value).join('\\n');
    filename = '{target}_assets.txt';
    mime = 'text/plain';
  }} else if (format === 'csv') {{
    const header = 'value,type,status,severity,source';
    const lines = visible.map(r => `"${{r.value}}","${{r.type}}","${{r.status}}","${{r.severity}}","${{r.source}}"`);
    content = header + '\\n' + lines.join('\\n');
    filename = '{target}_assets.csv';
    mime = 'text/csv';
  }} else {{
    content = JSON.stringify(visible, null, 2);
    filename = '{target}_assets.json';
    mime = 'application/json';
  }}

  const blob = new Blob([content], {{ type: mime }});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}}

// ---- Dashboard sorting ----
let sortDir = [true, true, true, true, true];
function sortTable(col) {{
  const tbody = document.getElementById('asset-tbody');
  const rows = Array.from(tbody.rows);
  sortDir[col] = !sortDir[col];
  rows.sort((a, b) => {{
    const aVal = a.cells[col].textContent;
    const bVal = b.cells[col].textContent;
    return sortDir[col] ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}
</script>
</body>
</html>
"""


def generate_html_mindmap(result: ScanResult, output_path: Path) -> Path:
    """Generate an interactive HTML mindmap and write it to *output_path*."""
    tree = _build_tree(result)
    stats = result.compute_stats()

    # ---- Risk HTML for header ----
    grade = result.risk_grade or None
    risk_score = result.risk_score
    grade_color = _GRADE_COLORS.get(grade, "#6e7681") if grade else "#6e7681"
    if grade and risk_score is not None:
        risk_html = (
            f'<span class="risk-label">Risk</span>'
            f'<span class="grade-badge" style="background:{grade_color}">{html.escape(grade)}</span>'
            f'<span class="stat-pill">Score: <strong style="color:{grade_color}">{risk_score}/100</strong></span>'
        )
    elif grade:
        risk_html = (
            f'<span class="risk-label">Risk</span>'
            f'<span class="grade-badge" style="background:{grade_color}">{html.escape(grade)}</span>'
        )
    else:
        risk_html = ""

    # ---- Root node color from grade ----
    root_color = grade_color if grade else "#58a6ff"
    root_stroke = _GRADE_COLORS.get(grade, "#1f6feb") if grade else "#1f6feb"

    # ---- Technologies badges ----
    techs = stats.get("unique_technologies", [])
    if techs:
        tech_badges = " ".join(
            f'<span class="tech-badge">{html.escape(t)}</span>' for t in techs
        )
        tech_display = "block"
    else:
        tech_badges = ""
        tech_display = "none"

    # ---- Executive summary (convert markdown to HTML) ----
    if result.executive_summary:
        exec_summary_html = _markdown_to_html(result.executive_summary)
        exec_display = "block"
    else:
        exec_summary_html = ""
        exec_display = "none"

    # ---- Attack paths with steps ----
    if result.attack_paths:
        parts: list[str] = []
        for path in result.attack_paths:
            name = html.escape(str(path.get("name", path.get("title", "Attack Path"))))
            sev = str(path.get("severity", path.get("risk", "medium"))).lower()
            sev_color = _SEVERITY_COLORS.get(sev, "#e67e22")
            steps = path.get("steps", [])
            assets = path.get("assets_involved", [])

            steps_html = ""
            if steps:
                step_items = "".join(
                    f'<li>{html.escape(str(s))}</li>' for s in steps
                )
                steps_html = f'<ol class="path-steps">{step_items}</ol>'

            assets_html = ""
            if assets:
                asset_tags = "".join(
                    f'<span class="path-asset">{html.escape(str(a))}</span>' for a in assets[:5]
                )
                assets_html = f'<div class="path-assets">{asset_tags}</div>'

            parts.append(
                f'<div class="path-item">'
                f'<div class="path-header">'
                f'<span class="path-name">{name}</span>'
                f'<span class="path-sev" style="background:{sev_color}">{html.escape(sev)}</span>'
                f'</div>'
                f'{steps_html}'
                f'{assets_html}'
                f'</div>'
            )
        attack_paths_html = "".join(parts)
        attack_display = "block"
    else:
        attack_paths_html = ""
        attack_display = "none"

    # Offset attack panel below tech panel when both exist
    attack_top_offset = "0"
    if techs and result.attack_paths:
        # Rough estimate; CSS will handle overflow
        attack_top_offset = "calc(40vh + 16px)"
    elif result.attack_paths:
        attack_top_offset = "0"

    # ---- Live domains table ----
    live_hosts = result.get_live_hosts()
    live_rows: list[str] = []
    for host in live_hosts[:200]:  # cap for performance
        # Find technologies for this host
        host_techs: list[str] = []
        for a in result.assets:
            if a.value == host and a.technologies:
                host_techs.extend(a.technologies)
            elif a.parent == host and a.type == AssetType.TECHNOLOGY:
                host_techs.append(a.value)
        tech_tags = "".join(
            f'<span class="tech-tag">{html.escape(t)}</span>' for t in dict.fromkeys(host_techs)
        ) if host_techs else '<span style="color:#6e7681">-</span>'

        live_rows.append(
            f'<tr><td>{html.escape(host)}</td>'
            f'<td><span class="status-live">LIVE</span></td>'
            f'<td>{tech_tags}</td></tr>'
        )

    live_rows_html = "".join(live_rows) if live_rows else '<tr><td colspan="3" style="color:#6e7681">No live hosts found</td></tr>'
    live_count = len(live_hosts)
    live_panel_display = "block" if live_hosts else "none"

    # ---- Dashboard data ----
    # Risk display
    risk_display = f"{result.risk_score} ({result.risk_grade})" if result.risk_score is not None else "N/A"
    risk_color = grade_color

    # Severity breakdown chips
    sev_colors_map = {
        "critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
        "low": "#3b82f6", "info": "#71717a",
    }
    sev_breakdown_parts: list[str] = []
    for sev_name in ("critical", "high", "medium", "low", "info"):
        count = stats["by_severity"].get(sev_name, 0)
        if count > 0:
            c = sev_colors_map.get(sev_name, "#71717a")
            sev_breakdown_parts.append(
                f'<span class="sev-chip">'
                f'<span class="sev-dot" style="background:{c}"></span>'
                f'{count} {sev_name}</span>'
            )
    severity_breakdown_html = "".join(sev_breakdown_parts)

    # Type filter options
    type_options = "".join(
        f'<option value="{html.escape(t)}">{html.escape(t)} ({c})</option>'
        for t, c in sorted(stats["by_type"].items(), key=lambda x: -x[1])
    )

    # Asset table rows (cap at 2000 for browser performance)
    sev_tag_class = {
        "critical": "sev-tag-critical", "high": "sev-tag-high",
        "medium": "sev-tag-medium", "low": "sev-tag-low", "info": "sev-tag-info",
    }
    asset_table_rows: list[str] = []
    for a in result.assets[:2000]:
        sev_cls = sev_tag_class.get(a.severity.value, "sev-tag-info")
        status_cls = f"status-tag-{a.status.value}"
        asset_table_rows.append(
            f'<tr data-type="{html.escape(a.type.value)}" '
            f'data-severity="{html.escape(a.severity.value)}" '
            f'data-status="{html.escape(a.status.value)}">'
            f'<td title="{html.escape(a.value)}">{html.escape(a.value[:80])}</td>'
            f'<td>{html.escape(a.type.value)}</td>'
            f'<td><span class="status-tag {status_cls}">{html.escape(a.status.value)}</span></td>'
            f'<td><span class="sev-tag {sev_cls}">{html.escape(a.severity.value)}</span></td>'
            f'<td>{html.escape(a.source)}</td>'
            f'</tr>'
        )
    asset_rows_html = "".join(asset_table_rows)

    content = HTML_TEMPLATE.format(
        target=html.escape(result.target),
        total=stats["total_assets"],
        live=stats["live_assets"],
        risk_html=risk_html,
        root_color=root_color,
        root_stroke=root_stroke,
        tree_json=json.dumps(tree),
        severity_json=json.dumps(_SEVERITY_COLORS),
        status_json=json.dumps(_STATUS_COLORS),
        tech_badges=tech_badges,
        tech_display=tech_display,
        exec_summary_html=exec_summary_html,
        exec_display=exec_display,
        attack_paths_html=attack_paths_html,
        attack_display=attack_display,
        attack_top_offset=attack_top_offset,
        live_rows_html=live_rows_html,
        live_count=live_count,
        live_panel_display=live_panel_display,
        risk_display=risk_display,
        risk_color=risk_color,
        severity_breakdown_html=severity_breakdown_html,
        type_options_html=type_options,
        asset_rows_html=asset_rows_html,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content)
    return output_path
