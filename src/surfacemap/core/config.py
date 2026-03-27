"""Configuration management for SurfaceMap.

All settings are loaded from environment variables with sensible defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv() -> None:
    """Load .env file from current directory or project root if it exists."""
    for candidate in (Path(".env"), Path(__file__).resolve().parents[3] / ".env"):
        if candidate.is_file():
            with open(candidate) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip("'\"")
                    if key and key not in os.environ:
                        os.environ[key] = value
            break


# Default sensitive paths to probe on live hosts
_DEFAULT_SENSITIVE_PATHS = (
    ".git/HEAD,.git/config,.env,.env.local,.env.production,"
    "robots.txt,sitemap.xml,.well-known/security.txt,"
    "swagger.json,swagger/index.html,openapi.json,api-docs,"
    "graphql,graphiql,.graphql,"
    "admin,wp-admin,wp-login.php,administrator,_admin,login,"
    "phpmyadmin,adminer,phpinfo.php,"
    "actuator,actuator/health,actuator/env,actuator/configprops,"
    "server-status,server-info,debug,trace,console,elmah.axd,"
    ".DS_Store,.htaccess,.htpasswd,web.config,.svn/entries,"
    "backup.sql,dump.sql,database.sql,db.sql,"
    "backup.zip,backup.tar.gz,site.tar.gz,"
    "package.json,composer.json,Gemfile,requirements.txt,"
    "crossdomain.xml,clientaccesspolicy.xml,"
    "wp-config.php.bak,config.php.bak,config.yml,"
    ".dockerenv,docker-compose.yml,Dockerfile,"
    "debug/default/view,_debug_toolbar,__debug__,"
    "info.php,test.php,status,health,healthcheck,metrics,"
    ".aws/credentials,config/database.yml"
)


@dataclass
class SurfaceMapConfig:
    """Central configuration loaded from environment variables."""

    # LLM settings
    gemini_api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    anthropic_api_key: str = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    llm_provider: str = field(default_factory=lambda: os.getenv("SURFACEMAP_LLM_PROVIDER", "gemini"))
    llm_model: str = field(default_factory=lambda: os.getenv("SURFACEMAP_LLM_MODEL", "gemini-2.5-flash"))
    gemini_fallback_model: str = field(default_factory=lambda: os.getenv("SURFACEMAP_GEMINI_FALLBACK_MODEL", "gemini-2.0-flash"))
    anthropic_model: str = field(default_factory=lambda: os.getenv("SURFACEMAP_ANTHROPIC_MODEL", "claude-sonnet-4-20250514"))
    openai_model: str = field(default_factory=lambda: os.getenv("SURFACEMAP_OPENAI_MODEL", "gpt-4o"))
    llm_temperature: float = field(default_factory=lambda: float(os.getenv("SURFACEMAP_LLM_TEMPERATURE", "0.3")))
    llm_max_tokens: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_LLM_MAX_TOKENS", "16384")))
    llm_max_retries: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_LLM_MAX_RETRIES", "3")))
    llm_retry_delay: float = field(default_factory=lambda: float(os.getenv("SURFACEMAP_LLM_RETRY_DELAY", "10")))

    # Enrichment API keys (all optional)
    virustotal_api_key: str = field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY", ""))
    shodan_api_key: str = field(default_factory=lambda: os.getenv("SHODAN_API_KEY", ""))
    github_token: str = field(default_factory=lambda: os.getenv("GITHUB_TOKEN", ""))
    hunter_api_key: str = field(default_factory=lambda: os.getenv("HUNTER_API_KEY", ""))
    censys_api_id: str = field(default_factory=lambda: os.getenv("CENSYS_API_ID", ""))
    censys_api_secret: str = field(default_factory=lambda: os.getenv("CENSYS_API_SECRET", ""))
    binaryedge_api_key: str = field(default_factory=lambda: os.getenv("BINARYEDGE_API_KEY", ""))
    fullhunt_api_key: str = field(default_factory=lambda: os.getenv("FULLHUNT_API_KEY", ""))
    passivetotal_username: str = field(default_factory=lambda: os.getenv("PASSIVETOTAL_USERNAME", ""))
    passivetotal_api_key: str = field(default_factory=lambda: os.getenv("PASSIVETOTAL_API_KEY", ""))

    # Timeouts (seconds)
    http_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_HTTP_TIMEOUT", "15")))
    osint_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_OSINT_TIMEOUT", "60")))
    osint_connect_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_OSINT_CONNECT_TIMEOUT", "15")))
    dns_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_DNS_TIMEOUT", "10")))
    llm_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_LLM_TIMEOUT", "120")))
    subfinder_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_SUBFINDER_TIMEOUT", "60")))
    slack_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_SLACK_TIMEOUT", "10")))
    ssl_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_SSL_TIMEOUT", "10")))
    axfr_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_AXFR_TIMEOUT", "15")))
    whois_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_WHOIS_TIMEOUT", "15")))
    active_probe_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_ACTIVE_PROBE_TIMEOUT", "20")))
    js_analysis_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_JS_ANALYSIS_TIMEOUT", "30")))

    # Retry settings for external APIs
    osint_max_retries: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_OSINT_MAX_RETRIES", "2")))
    osint_retry_delay: float = field(default_factory=lambda: float(os.getenv("SURFACEMAP_OSINT_RETRY_DELAY", "3")))

    # Output settings
    output_dir: Path = field(default_factory=lambda: Path(os.getenv("SURFACEMAP_OUTPUT_DIR", "./output")))
    db_path: Path = field(default_factory=lambda: Path(os.getenv("SURFACEMAP_DB_PATH", "./surfacemap.db")))

    # Notifications
    slack_webhook_url: str = field(default_factory=lambda: os.getenv("SURFACEMAP_SLACK_WEBHOOK", ""))
    slack_bot_token: str = field(default_factory=lambda: os.getenv("SURFACEMAP_SLACK_TOKEN", ""))
    slack_channel: str = field(default_factory=lambda: os.getenv("SURFACEMAP_SLACK_CHANNEL", "#security"))

    # Port scanning
    nmap_args: str = field(default_factory=lambda: os.getenv("SURFACEMAP_NMAP_ARGS", "-sV -T4 --top-ports 100"))
    scan_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_SCAN_TIMEOUT", "300")))
    max_ips_to_scan: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_IPS_TO_SCAN", "10")))

    # Discovery settings
    max_subdomains: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_SUBDOMAINS", "500")))
    max_extra_domains: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_EXTRA_DOMAINS", "20")))
    max_llm_known_subs: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_LLM_KNOWN_SUBS", "30")))
    max_wayback_results: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_WAYBACK_RESULTS", "500")))
    max_permutations: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_PERMUTATIONS", "500")))
    dns_wordlist: str = field(default_factory=lambda: os.getenv("SURFACEMAP_DNS_WORDLIST", ""))
    user_agent: str = field(
        default_factory=lambda: os.getenv(
            "SURFACEMAP_USER_AGENT",
            "SurfaceMap/2.0.0 (Attack Surface Discovery)",
        )
    )
    cli_asset_display_limit: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_DISPLAY_LIMIT", "50")))

    # Sensitive paths for active probing (comma-separated)
    sensitive_paths: list[str] = field(
        default_factory=lambda: os.getenv(
            "SURFACEMAP_SENSITIVE_PATHS", _DEFAULT_SENSITIVE_PATHS
        ).split(",")
    )

    # DKIM selectors to check
    dkim_selectors: list[str] = field(
        default_factory=lambda: os.getenv(
            "SURFACEMAP_DKIM_SELECTORS",
            "default,google,selector1,selector2,k1,k2,s1,s2,mail,dkim,mandrill,mailgun,smtp"
        ).split(",")
    )

    # Concurrency
    max_concurrent_probes: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_PROBES", "50")))
    max_concurrent_dns: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_DNS", "200")))
    max_concurrent_ssl: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_SSL", "15")))
    max_concurrent_paths: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_PATHS", "10")))
    max_concurrent_js: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_JS", "5")))
    webtech_batch_size: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_WEBTECH_BATCH_SIZE", "10")))
    webtech_batch_delay: float = field(default_factory=lambda: float(os.getenv("SURFACEMAP_WEBTECH_BATCH_DELAY", "0.2")))

    # VirusTotal rate limiting (free tier: 4 req/min)
    vt_rate_delay: float = field(default_factory=lambda: float(os.getenv("SURFACEMAP_VT_RATE_DELAY", "15")))

    # Web crawler settings
    crawl_max_depth: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_CRAWL_MAX_DEPTH", "3")))
    crawl_max_pages: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_CRAWL_MAX_PAGES", "100")))
    crawl_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_CRAWL_TIMEOUT", "300")))

    # Nuclei settings
    nuclei_severity: str = field(default_factory=lambda: os.getenv("SURFACEMAP_NUCLEI_SEVERITY", "critical,high,medium"))
    nuclei_rate_limit: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_NUCLEI_RATE_LIMIT", "150")))
    nuclei_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_NUCLEI_TIMEOUT", "600")))
    nuclei_concurrency: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_NUCLEI_CONCURRENCY", "25")))
    nuclei_templates: str = field(default_factory=lambda: os.getenv("SURFACEMAP_NUCLEI_TEMPLATES", ""))

    # Screenshot settings
    screenshot_enabled: bool = field(default_factory=lambda: os.getenv("SURFACEMAP_SCREENSHOTS", "false").lower() == "true")
    screenshot_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_SCREENSHOT_TIMEOUT", "30")))
    screenshot_width: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_SCREENSHOT_WIDTH", "1280")))
    screenshot_height: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_SCREENSHOT_HEIGHT", "720")))

    # Plugin system
    plugin_dirs: str = field(default_factory=lambda: os.getenv("SURFACEMAP_PLUGIN_DIRS", ""))
    enable_plugins: bool = field(default_factory=lambda: os.getenv("SURFACEMAP_ENABLE_PLUGINS", "true").lower() == "true")

    def ensure_output_dir(self) -> Path:
        """Create and return the output directory."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        return self.output_dir

    @property
    def has_llm(self) -> bool:
        """Check if any LLM API key is configured."""
        return bool(self.gemini_api_key or self.anthropic_api_key or self.openai_api_key)

    @property
    def has_slack(self) -> bool:
        """Check if Slack notifications are configured."""
        return bool(self.slack_webhook_url or self.slack_bot_token)

    @property
    def has_virustotal(self) -> bool:
        return bool(self.virustotal_api_key)

    @property
    def has_shodan(self) -> bool:
        return bool(self.shodan_api_key)

    @property
    def has_github(self) -> bool:
        return bool(self.github_token)

    @property
    def has_hunter(self) -> bool:
        return bool(self.hunter_api_key)

    @property
    def has_censys(self) -> bool:
        return bool(self.censys_api_id and self.censys_api_secret)

    @property
    def has_binaryedge(self) -> bool:
        return bool(self.binaryedge_api_key)

    @property
    def has_fullhunt(self) -> bool:
        return bool(self.fullhunt_api_key)

    @property
    def has_passivetotal(self) -> bool:
        return bool(self.passivetotal_username and self.passivetotal_api_key)


# Singleton config instance
_config: SurfaceMapConfig | None = None


def get_config() -> SurfaceMapConfig:
    """Get or create the global config instance."""
    global _config
    if _config is None:
        _load_dotenv()
        _config = SurfaceMapConfig()
    return _config


def reset_config() -> None:
    """Reset config (useful for testing)."""
    global _config
    _config = None
