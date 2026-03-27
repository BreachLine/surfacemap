"""Configuration management for SurfaceMap.

All settings are loaded from environment variables with sensible defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SurfaceMapConfig:
    """Central configuration loaded from environment variables."""

    # LLM settings
    gemini_api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    anthropic_api_key: str = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    llm_provider: str = field(default_factory=lambda: os.getenv("SURFACEMAP_LLM_PROVIDER", "gemini"))
    llm_model: str = field(default_factory=lambda: os.getenv("SURFACEMAP_LLM_MODEL", "gemini-2.5-flash"))
    llm_temperature: float = field(default_factory=lambda: float(os.getenv("SURFACEMAP_LLM_TEMPERATURE", "0.3")))

    # Timeouts (seconds)
    http_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_HTTP_TIMEOUT", "15")))
    dns_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_DNS_TIMEOUT", "10")))
    scan_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_SCAN_TIMEOUT", "300")))
    llm_timeout: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_LLM_TIMEOUT", "30")))

    # Output settings
    output_dir: Path = field(default_factory=lambda: Path(os.getenv("SURFACEMAP_OUTPUT_DIR", "./output")))
    db_path: Path = field(default_factory=lambda: Path(os.getenv("SURFACEMAP_DB_PATH", "./surfacemap.db")))

    # Notifications
    slack_webhook_url: str = field(default_factory=lambda: os.getenv("SURFACEMAP_SLACK_WEBHOOK", ""))
    slack_bot_token: str = field(default_factory=lambda: os.getenv("SURFACEMAP_SLACK_TOKEN", ""))
    slack_channel: str = field(default_factory=lambda: os.getenv("SURFACEMAP_SLACK_CHANNEL", "#security"))

    # Discovery settings
    max_subdomains: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_SUBDOMAINS", "500")))
    max_ports: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_PORTS", "1000")))
    dns_wordlist: str = field(default_factory=lambda: os.getenv("SURFACEMAP_DNS_WORDLIST", ""))
    nmap_args: str = field(default_factory=lambda: os.getenv("SURFACEMAP_NMAP_ARGS", "-sV -T4 --top-ports 100"))
    user_agent: str = field(
        default_factory=lambda: os.getenv(
            "SURFACEMAP_USER_AGENT",
            "SurfaceMap/1.0.0 (Attack Surface Discovery)",
        )
    )

    # Concurrency
    max_concurrent_probes: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_PROBES", "20")))
    max_concurrent_dns: int = field(default_factory=lambda: int(os.getenv("SURFACEMAP_MAX_DNS", "50")))

    def ensure_output_dir(self) -> Path:
        """Create and return the output directory."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        return self.output_dir

    @property
    def has_llm(self) -> bool:
        """Check if an LLM API key is configured."""
        if self.llm_provider == "gemini":
            return bool(self.gemini_api_key)
        if self.llm_provider == "anthropic":
            return bool(self.anthropic_api_key)
        return False

    @property
    def has_slack(self) -> bool:
        """Check if Slack notifications are configured."""
        return bool(self.slack_webhook_url or self.slack_bot_token)


# Singleton config instance
_config: SurfaceMapConfig | None = None


def get_config() -> SurfaceMapConfig:
    """Get or create the global config instance."""
    global _config
    if _config is None:
        _config = SurfaceMapConfig()
    return _config


def reset_config() -> None:
    """Reset config (useful for testing)."""
    global _config
    _config = None
