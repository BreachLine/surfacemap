"""LLM integration for intelligent discovery.

Uses Gemini (default) or Anthropic to augment traditional OSINT with
AI-driven reasoning about company infrastructure, subsidiaries, and
potential attack vectors.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from surfacemap.core.config import get_config

logger = logging.getLogger(__name__)


class LLMBrain:
    """LLM-powered intelligence for attack surface discovery."""

    def __init__(self) -> None:
        self.config = get_config()
        self._client: Any = None

    def _get_client(self) -> Any:
        """Lazily initialize the LLM client."""
        if self._client is not None:
            return self._client

        if self.config.llm_provider == "gemini":
            try:
                from google import genai

                self._client = genai.Client(api_key=self.config.gemini_api_key)
            except ImportError:
                raise RuntimeError(
                    "google-genai is required for Gemini. "
                    "Install with: pip install 'surfacemap[llm]'"
                )
        elif self.config.llm_provider == "anthropic":
            try:
                import anthropic

                self._client = anthropic.Anthropic(api_key=self.config.anthropic_api_key)
            except ImportError:
                raise RuntimeError(
                    "anthropic is required for Claude. "
                    "Install with: pip install 'surfacemap[llm]'"
                )
        else:
            raise ValueError(f"Unknown LLM provider: {self.config.llm_provider}")

        return self._client

    def ask(self, prompt: str) -> str:
        """Send a prompt to the LLM and return the text response."""
        client = self._get_client()

        try:
            if self.config.llm_provider == "gemini":
                response = client.models.generate_content(
                    model=self.config.llm_model,
                    contents=prompt,
                    config={
                        "temperature": self.config.llm_temperature,
                        "max_output_tokens": 4096,
                    },
                )
                return response.text or ""

            elif self.config.llm_provider == "anthropic":
                response = client.messages.create(
                    model=self.config.llm_model,
                    max_tokens=4096,
                    temperature=self.config.llm_temperature,
                    messages=[{"role": "user", "content": prompt}],
                )
                return response.content[0].text

        except Exception as e:
            logger.error("LLM request failed: %s", e)
            return ""

    def ask_json(self, prompt: str) -> dict[str, Any] | list[Any]:
        """Send a prompt and parse the response as JSON."""
        full_prompt = (
            f"{prompt}\n\n"
            "IMPORTANT: Respond with ONLY valid JSON. No markdown, no explanation, "
            "no code fences. Just the raw JSON object or array."
        )

        raw = self.ask(full_prompt)
        if not raw:
            return {}

        # Strip markdown code fences if present
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            cleaned = "\n".join(lines)

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM JSON response: %s...", raw[:200])
            return {}

    def discover_company_domains(self, company: str) -> list[dict[str, str]]:
        """Use LLM to discover domains associated with a company.

        Returns a list of dicts with 'domain' and 'confidence' keys.
        """
        prompt = f"""You are an expert OSINT analyst. Given the company name "{company}",
identify all domains that this company likely owns or operates.

Consider:
- Primary corporate domain
- Product-specific domains
- Regional/country-specific domains
- Marketing and campaign domains
- Developer/API domains
- Acquired company domains
- CDN or asset-serving domains

Return a JSON array of objects with these fields:
- "domain": the domain name (e.g., "example.com")
- "confidence": "high", "medium", or "low"
- "purpose": brief description of the domain's purpose

Only include domains you are reasonably confident about. Do not fabricate domains."""

        result = self.ask_json(prompt)
        if isinstance(result, list):
            return result
        return result.get("domains", []) if isinstance(result, dict) else []

    def discover_subsidiaries(self, company: str) -> list[dict[str, str]]:
        """Use LLM to discover subsidiaries and acquisitions.

        Returns a list of dicts with 'name', 'domain', and 'relationship' keys.
        """
        prompt = f"""You are an expert corporate intelligence analyst. For the company "{company}",
identify subsidiaries, acquisitions, and related companies.

Consider:
- Wholly owned subsidiaries
- Recent acquisitions (last 5 years)
- Joint ventures
- Brand names that operate independently
- Regional operating companies

Return a JSON array of objects with:
- "name": subsidiary/company name
- "domain": their primary domain if known (or empty string)
- "relationship": "subsidiary", "acquisition", "brand", "joint_venture"
- "confidence": "high", "medium", or "low"

Only include entities you are reasonably confident about."""

        result = self.ask_json(prompt)
        if isinstance(result, list):
            return result
        return result.get("subsidiaries", []) if isinstance(result, dict) else []

    def suggest_subdomains(self, domain: str, known: list[str] | None = None) -> list[str]:
        """Use LLM to suggest likely subdomains for a given domain.

        Returns a list of subdomain prefixes to try.
        """
        known_list = ", ".join(known[:20]) if known else "none discovered yet"

        prompt = f"""You are a penetration tester enumerating subdomains for {domain}.
Already discovered subdomains: {known_list}

Based on common naming patterns, the industry this domain operates in,
and typical infrastructure layouts, suggest additional subdomain prefixes
that are likely to exist but haven't been found yet.

Think about:
- Internal tools (jira, confluence, gitlab, jenkins, grafana, kibana)
- Staging/dev environments (staging, dev, qa, uat, sandbox, beta)
- API endpoints (api, api-v2, graphql, ws, grpc)
- Mail and auth (mail, smtp, imap, sso, auth, login, oauth)
- Infrastructure (vpn, proxy, bastion, jump, gateway, lb)
- Cloud services (s3, cdn, assets, static, media, files)
- Monitoring (monitor, status, health, metrics, logs)
- Regional (us, eu, ap, us-east, eu-west)

Return a JSON array of subdomain prefixes (strings only, no dots).
Return at most 50 suggestions, ordered by likelihood."""

        result = self.ask_json(prompt)
        if isinstance(result, list):
            return [str(s) for s in result if isinstance(s, str)]
        return []

    def analyze_asset(self, data: dict[str, Any]) -> dict[str, Any]:
        """Use LLM to analyze a discovered asset for security implications.

        Returns analysis with risk_level, findings, and recommendations.
        """
        prompt = f"""You are a security analyst reviewing a discovered asset:

{json.dumps(data, indent=2)}

Analyze this asset for security implications:
1. What is the risk level? (critical, high, medium, low, info)
2. What potential vulnerabilities or misconfigurations might exist?
3. What recommendations would you make?

Return a JSON object with:
- "risk_level": severity string
- "findings": array of finding strings
- "recommendations": array of recommendation strings
- "tags": array of relevant tags (e.g., "exposed-admin", "default-creds-possible")"""

        result = self.ask_json(prompt)
        return result if isinstance(result, dict) else {}

    def generate_google_dorks(self, company: str, domain: str) -> list[dict[str, str]]:
        """Generate targeted Google dork queries for the company.

        Returns a list of dicts with 'query', 'purpose', and 'category' keys.
        """
        prompt = f"""You are an OSINT specialist creating Google dork queries for
reconnaissance on "{company}" (domain: {domain}).

Generate targeted search queries that could reveal:
- Exposed documents and files (PDF, XLSX, DOCX, SQL, LOG)
- Login pages and admin panels
- Configuration files and backups
- API documentation and endpoints
- Error messages revealing stack info
- Exposed directories and file listings
- Cloud storage buckets
- Code repositories and paste sites
- Employee information on LinkedIn/social
- Subdomains and related infrastructure

Return a JSON array of objects with:
- "query": the full Google dork query
- "purpose": what this query is looking for
- "category": "files", "admin", "config", "api", "errors", "directories",
  "cloud", "code", "people", or "infrastructure"

Generate 15-20 high-value dork queries."""

        result = self.ask_json(prompt)
        if isinstance(result, list):
            return result
        return result.get("dorks", []) if isinstance(result, dict) else []
