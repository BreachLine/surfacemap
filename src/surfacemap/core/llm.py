"""LLM integration for intelligent discovery.

Uses Gemini (default), Anthropic, or OpenAI to augment traditional OSINT with
AI-driven reasoning about company infrastructure, subsidiaries, and
potential attack vectors.  Providers are tried in order: Gemini -> Anthropic -> OpenAI.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import httpx

from surfacemap.core.config import get_config

logger = logging.getLogger(__name__)


class LLMBrain:
    """LLM-powered intelligence for attack surface discovery."""

    def __init__(self) -> None:
        self.config = get_config()

    # ------------------------------------------------------------------
    # Web search via DuckDuckGo (no API key needed)
    # ------------------------------------------------------------------

    def web_search(self, query: str, max_results: int = 10) -> list[dict[str, str]]:
        """Search the web via DuckDuckGo HTML and extract results.

        Returns list of dicts with 'title', 'url', 'snippet'.
        """
        try:
            with httpx.Client(
                timeout=self.config.http_timeout,
                follow_redirects=True,
                headers={"User-Agent": self.config.user_agent},
            ) as client:
                resp = client.get(
                    "https://html.duckduckgo.com/html/",
                    params={"q": query},
                )
                if resp.status_code != 200:
                    return []

                import re
                results: list[dict[str, str]] = []
                # Parse DDG HTML results
                for match in re.finditer(
                    r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.+?)</a>.*?'
                    r'<a[^>]+class="result__snippet"[^>]*>(.+?)</a>',
                    resp.text, re.DOTALL,
                ):
                    url, title, snippet = match.groups()
                    # Clean HTML tags from title/snippet
                    title = re.sub(r'<[^>]+>', '', title).strip()
                    snippet = re.sub(r'<[^>]+>', '', snippet).strip()
                    if url and title:
                        results.append({"title": title, "url": url, "snippet": snippet})
                    if len(results) >= max_results:
                        break
                return results
        except Exception as exc:
            logger.debug("[WebSearch] DuckDuckGo search failed: %s", exc)
            return []

    def search_and_ask(self, question: str) -> str:
        """Search the web for context, then ask LLM with that context."""
        results = self.web_search(question)
        if not results:
            return self.ask(question)

        context = "\n".join(
            f"- {r['title']}: {r['snippet']}" for r in results[:5]
        )
        enriched_prompt = (
            f"Use the following recent web search results as context:\n\n"
            f"{context}\n\n"
            f"Based on this information, answer: {question}"
        )
        return self.ask(enriched_prompt)

    # ------------------------------------------------------------------
    # Provider-specific call methods
    # ------------------------------------------------------------------

    def _call_gemini_model(self, prompt: str, model: str) -> str:
        """Call a specific Gemini model via REST.

        Returns the response text, or "" on failure.
        Retries with exponential backoff on transient errors.
        """
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent"
        )
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self.config.llm_temperature,
                "maxOutputTokens": self.config.llm_max_tokens,
            },
        }
        # Pass API key as query param (required by Gemini API) but keep it
        # out of the URL string to prevent accidental logging
        query_params = {"key": self.config.gemini_api_key}

        max_retries = self.config.llm_max_retries
        last_error = ""

        for attempt in range(max_retries):
            try:
                with httpx.Client(timeout=self.config.llm_timeout) as client:
                    resp = client.post(url, params=query_params, json=payload)

                # Transient HTTP status → retry
                if resp.status_code in (429, 500, 502, 503):
                    last_error = f"HTTP {resp.status_code}"
                    wait = self.config.llm_retry_delay * (2 ** attempt)
                    logger.warning(
                        "[LLM] %s returned %d (attempt %d/%d), retrying in %.0fs…",
                        model, resp.status_code, attempt + 1, max_retries, wait,
                    )
                    time.sleep(wait)
                    continue

                data = resp.json()

                # Success — extract text from candidates
                if "candidates" in data and data["candidates"]:
                    candidate = data["candidates"][0]
                    # Handle safety-blocked responses
                    finish = candidate.get("finishReason", "")
                    if finish == "SAFETY":
                        logger.warning("[LLM] %s blocked by safety filter", model)
                        return ""
                    parts = candidate.get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", "")

                # No candidates — check why
                error_obj = data.get("error", {})
                error_msg = error_obj.get("message", "")

                # Handle empty candidates with promptFeedback (content filtered)
                if "promptFeedback" in data:
                    block_reason = data["promptFeedback"].get("blockReason", "unknown")
                    logger.warning("[LLM] %s prompt blocked: %s", model, block_reason)
                    return ""

                # Transient error messages → retry
                if not error_msg:
                    error_msg = str(data)[:300]
                last_error = error_msg

                retryable_keywords = ("high demand", "overloaded", "rate", "quota", "resource", "temporarily")
                if any(k in error_msg.lower() for k in retryable_keywords):
                    wait = self.config.llm_retry_delay * (2 ** attempt)
                    logger.warning(
                        "[LLM] %s: %s (attempt %d/%d), retrying in %.0fs…",
                        model, error_msg[:100], attempt + 1, max_retries, wait,
                    )
                    time.sleep(wait)
                    continue

                # Non-retryable API error
                logger.warning("[LLM] %s API error: %s", model, error_msg[:200])
                return ""

            except httpx.TimeoutException:
                last_error = f"timeout after {self.config.llm_timeout}s"
                if attempt < max_retries - 1:
                    wait = self.config.llm_retry_delay * (2 ** attempt)
                    logger.warning(
                        "[LLM] %s timed out (attempt %d/%d), retrying in %.0fs…",
                        model, attempt + 1, max_retries, wait,
                    )
                    time.sleep(wait)
                    continue
            except Exception as exc:
                last_error = str(exc)
                if attempt < max_retries - 1:
                    wait = self.config.llm_retry_delay * (2 ** attempt)
                    logger.warning(
                        "[LLM] %s error: %s (attempt %d/%d), retrying in %.0fs…",
                        model, exc, attempt + 1, max_retries, wait,
                    )
                    time.sleep(wait)
                    continue

        logger.warning(
            "[LLM] %s exhausted %d retries (last error: %s)",
            model, max_retries, last_error[:200],
        )
        return ""

    def _call_gemini(self, prompt: str) -> str:
        """Call Gemini API with automatic model fallback.

        Tries the primary model first, then falls back to the fallback model
        if the primary fails all retries.
        """
        if not self.config.gemini_api_key:
            return ""

        primary = self.config.llm_model or "gemini-2.5-flash"
        result = self._call_gemini_model(prompt, primary)
        if result:
            return result

        # Fallback to a cheaper/faster model if configured and different
        fallback = self.config.gemini_fallback_model
        if fallback and fallback != primary:
            logger.info("[LLM] Primary model %s failed, trying fallback %s…", primary, fallback)
            return self._call_gemini_model(prompt, fallback)

        return ""

    def _call_anthropic(self, prompt: str, system: str = "") -> str:
        """Call Anthropic Claude API via httpx (no SDK required)."""
        api_key = self.config.anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            return ""
        try:
            with httpx.Client(timeout=self.config.llm_timeout) as client:
                body: dict[str, Any] = {
                    "model": self.config.anthropic_model,
                    "max_tokens": self.config.llm_max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                }
                if system:
                    body["system"] = system
                resp = client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json=body,
                )
                data = resp.json()
                if "content" in data:
                    return data["content"][0].get("text", "")
        except Exception as exc:
            logger.warning("[LLM] Anthropic failed: %s", exc)
        return ""

    def _call_openai(self, prompt: str, system: str = "") -> str:
        """Call OpenAI API via httpx (no SDK required)."""
        api_key = self.config.openai_api_key or os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            return ""
        try:
            messages: list[dict[str, str]] = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            with httpx.Client(timeout=self.config.llm_timeout) as client:
                resp = client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.config.openai_model,
                        "messages": messages,
                        "max_tokens": self.config.llm_max_tokens,
                    },
                )
                data = resp.json()
                if "choices" in data:
                    return data["choices"][0].get("message", {}).get("content", "")
        except Exception as exc:
            logger.warning("[LLM] OpenAI failed: %s", exc)
        return ""

    # ------------------------------------------------------------------
    # Unified ask() with provider fallback
    # ------------------------------------------------------------------

    def ask(self, prompt: str) -> str:
        """Send a prompt to LLM providers in order: Gemini -> Anthropic -> OpenAI.

        Returns the first successful non-empty response.
        """
        # Try providers in priority order
        for provider_fn in (self._call_gemini, self._call_anthropic, self._call_openai):
            try:
                result = provider_fn(prompt)
                if result:
                    return result
            except Exception as exc:
                logger.debug("Provider %s failed: %s", provider_fn.__name__, exc)
                continue

        logger.warning("All LLM providers failed or returned empty responses")
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
            # Remove opening fence line (e.g. ```json, ```JSON, ```)
            first_newline = cleaned.index("\n") if "\n" in cleaned else len(cleaned)
            cleaned = cleaned[first_newline + 1:]
            # Remove closing fence if present
            if cleaned.rstrip().endswith("```"):
                cleaned = cleaned.rstrip()
                cleaned = cleaned[: cleaned.rfind("```")]
            cleaned = cleaned.strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # Attempt to salvage truncated JSON (e.g. array cut mid-object)
            repaired = self._repair_truncated_json(cleaned)
            if repaired is not None:
                keys_info = list(repaired.keys()) if isinstance(repaired, dict) else f"{len(repaired)} items"
                logger.info("[LLM] Recovered truncated response → %s", keys_info)
                return repaired
            # Only warn if both direct parse and repair failed
            logger.warning("[LLM] Could not parse response (%d chars). First 100: %s", len(raw), raw[:100])
            return {}

    @staticmethod
    def _repair_truncated_json(text: str) -> dict[str, Any] | list[Any] | None:
        """Try to recover truncated JSON by finding the last valid closing point."""
        text = text.strip()
        if not text:
            return None

        # Strategy: progressively truncate from the end until json.loads succeeds,
        # closing any open brackets/braces along the way.
        # Find the last complete value boundary (}, ], or quoted string)
        for end_char in ("}", "]"):
            pos = text.rfind(end_char)
            while pos > 0:
                candidate = text[: pos + 1]
                # Count open/close brackets to know what to append
                open_braces = candidate.count("{") - candidate.count("}")
                open_brackets = candidate.count("[") - candidate.count("]")
                suffix = "}" * max(open_braces, 0) + "]" * max(open_brackets, 0)
                try:
                    return json.loads(candidate + suffix)
                except json.JSONDecodeError:
                    # Try removing trailing comma before the suffix
                    trimmed = candidate.rstrip().rstrip(",")
                    try:
                        return json.loads(trimmed + suffix)
                    except json.JSONDecodeError:
                        pass
                pos = text.rfind(end_char, 0, pos)

        return None

    def brainstorm_attack_surface(self, company: str, domain: str) -> dict[str, Any]:
        """Deep LLM brainstorming — comprehensive intelligence gathering.

        Splits the work into two focused LLM calls to avoid output truncation:
        1. Domains, subsidiaries, acquisitions, and geographic presence.
        2. Cloud infrastructure, tech stack, IP ranges, services, email, and social.

        Returns a single merged dict with all sections that seeds the discovery
        pipeline.
        """
        intel: dict[str, Any] = {}

        part1 = self.brainstorm_domains_and_subsidiaries(company, domain)
        intel.update(part1)

        part2 = self.brainstorm_infrastructure(company, domain)
        intel.update(part2)

        return intel

    def brainstorm_domains_and_subsidiaries(self, company: str, domain: str) -> dict[str, Any]:
        """LLM brainstorm focused on domains, subsidiaries, and corporate structure.

        Uses web search to gather current intel before asking the LLM.
        Returns a JSON dict with: domains, subsidiaries, acquisition_history,
        geographic_presence.
        """
        # Gather current web intel to enrich LLM context
        web_context = ""
        search_queries = [
            f"{company} subsidiaries acquisitions",
            f"{company} domains products services",
        ]
        for q in search_queries:
            results = self.web_search(q, max_results=5)
            if results:
                web_context += "\n".join(f"- {r['title']}: {r['snippet']}" for r in results) + "\n"

        web_section = ""
        if web_context:
            web_section = f"\nRecent web search results for additional context:\n{web_context}\n"

        prompt = f"""You are an elite OSINT and attack surface analyst. You have been given a target:
Company/Target: "{company}"
Primary Domain: {domain}
{web_section}
Perform a COMPREHENSIVE brainstorm of this target's corporate structure and domain
footprint. Think deeply and exhaustively about every domain, subsidiary, acquisition,
and regional presence you know of.

Return a JSON object with ALL of these sections (include as many items as you can):

{{
  "domains": [
    {{"domain": "example.com", "confidence": "high|medium|low", "purpose": "description"}}
  ],
  "subsidiaries": [
    {{"name": "Company Name", "domain": "sub.com", "relationship": "subsidiary|acquisition|brand|joint_venture|partner", "confidence": "high|medium|low"}}
  ],
  "acquisition_history": [
    {{"company": "Acquired Co", "year": 2023, "domain": "acquired.com", "status": "integrated|independent|deprecated"}}
  ],
  "geographic_presence": [
    {{"region": "US|EU|APAC|etc", "likely_domains": ["us.example.com", "eu.example.com"]}}
  ]
}}

Guidelines:
- Include EVERY domain you know of: primary, product-specific, regional, marketing,
  developer/API, CDN/asset-serving, and acquired-company domains.
- For subsidiaries, include wholly owned subsidiaries, recent acquisitions (last 10
  years), joint ventures, brands that operate independently, and regional operating
  companies. Include their domains where known.
- For acquisition history, list every acquisition you know about with domain and
  current status (integrated, independent, or deprecated).
- For geographic presence, list regions and any region-specific domains or subdomains.
- For major companies, think about ALL their products, services, APIs, developer
  platforms, etc.
- Limit to the top 30 most important domains and 20 most important subsidiaries.
- Do NOT fabricate — only include things you are reasonably confident about.
- Keep descriptions SHORT (under 10 words each) to save space."""

        result = self.ask_json(prompt)
        if isinstance(result, dict):
            return result
        return {}

    def brainstorm_infrastructure(self, company: str, domain: str) -> dict[str, Any]:
        """LLM brainstorm focused on infrastructure, tech stack, and services.

        Returns a JSON dict with: cloud_infrastructure, technology_stack,
        known_ip_ranges, known_services, email_patterns, social_profiles.
        This is supplementary intelligence that enriches the attack surface.
        """
        prompt = f"""You are an elite OSINT and attack surface analyst. You have been given a target:
Company/Target: "{company}"
Primary Domain: {domain}

Perform a COMPREHENSIVE brainstorm of this target's technical infrastructure,
cloud presence, services, and digital profiles. Think deeply about every cloud
asset, technology choice, service endpoint, and public profile.

Return a JSON object with ALL of these sections (include as many items as you can):

{{
  "cloud_infrastructure": [
    {{"provider": "aws|gcp|azure|cloudflare|fastly|akamai", "service": "S3|CloudFront|GCS|etc", "likely_names": ["bucket-name-1", "bucket-name-2"]}}
  ],
  "technology_stack": [
    {{"category": "frontend|backend|database|cdn|ci_cd|monitoring|auth", "technology": "React|Python|PostgreSQL|etc", "confidence": "high|medium|low"}}
  ],
  "known_ip_ranges": [
    {{"range": "x.x.x.0/24", "purpose": "description", "source": "where you know this from"}}
  ],
  "known_services": [
    {{"service": "API Gateway|CDN|Mail|VPN|SSO|etc", "likely_subdomains": ["api", "cdn", "mail", "vpn", "sso"]}}
  ],
  "email_patterns": [
    {{"pattern": "first.last@domain.com", "domain": "domain.com", "confidence": "high|medium|low"}}
  ],
  "social_profiles": [
    {{"platform": "github|linkedin|twitter|facebook|youtube", "url": "https://...", "handle": "@handle"}}
  ]
}}

Guidelines:
- For cloud infrastructure, consider AWS (S3, CloudFront, EC2), GCP (GCS, Cloud CDN),
  Azure (Blob Storage, CDN), and other CDN/edge providers. Predict likely bucket and
  resource names based on the company name and domain.
- For technology stack, consider frontend frameworks, backend languages, databases,
  CDNs, CI/CD tools, monitoring, auth providers, and any technologies visible from
  public job postings, tech blogs, or conference talks.
- For known IP ranges, include any ASNs or IP blocks you know are associated with
  this company.
- For known services, list services (API, CDN, mail, VPN, SSO, etc.) and predict
  the likely subdomains where they are hosted.
- For email patterns, identify the format used (first.last, f.last, firstlast, etc.)
  and which domains are used for corporate email.
- For social profiles, include official accounts on GitHub, LinkedIn, Twitter/X,
  Facebook, YouTube, and other platforms.
- Do NOT fabricate — only include things you are reasonably confident about."""

        result = self.ask_json(prompt)
        if isinstance(result, dict):
            return result
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
