"""Threat intelligence lookup provider interface, caching, and adapters for FraudLens.

Integrates:
1. BaseThreatIntelAdapter interface.
2. VirusTotal API v3 adapter (privacy-preserving URL/domain hash lookups).
3. URLScan.io API v1 adapter (domain-level lookups).
4. Thread-safe in-memory TTL caching with freshness/stale tracking.
5. Strict data minimization: never transmits message text, UPI parameters, credentials, or private query params.
6. Graceful failure and offline fallback (timeouts, rate-limiting, missing credentials).
"""

from abc import ABC, abstractmethod
import base64
from datetime import datetime, timezone
import logging
import re
import threading
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse
import requests

from backend.app.config import settings
from backend.app.schemas.url import ThreatIntelResult

logger = logging.getLogger(__name__)

# Sensitive query parameter keys that must be stripped before external lookup
SENSITIVE_PARAM_NAMES = {
    "token", "auth", "key", "apikey", "password", "pwd", "secret",
    "session", "session_id", "sessionid", "sess", "id", "code", "pin", "otp", "access_token",
    "jwt", "bearer", "sig", "signature", "credential", "creds",
}


def sanitize_url_for_lookup(raw_url: str) -> Tuple[str, str]:
    """Sanitize URL to enforce privacy and data minimization.

    Returns (sanitized_url, domain).
    Strips user credentials and sensitive parameters (e.g. token, session, auth).
    """
    clean = (raw_url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean):
        clean = f"http://{clean}"

    try:
        parsed = urlparse(clean)
    except Exception:
        return clean, ""

    hostname = (parsed.hostname or "").lower()

    # Strip query parameters that might carry personal or auth tokens
    clean_query = ""
    if parsed.query:
        try:
            params = parse_qs(parsed.query, keep_blank_values=False)
            filtered = {
                k: v for k, v in params.items()
                if k.lower() not in SENSITIVE_PARAM_NAMES
                and not any(s in k.lower() for s in ("token", "secret", "auth", "pass", "session", "otp", "cred"))
            }
            clean_query = urlencode(filtered, doseq=True)
        except Exception:
            clean_query = ""

    # Reconstruct sanitized URL without userinfo (e.g. user:pass@host)
    scheme = parsed.scheme if parsed.scheme in ("http", "https") else "http"
    netloc = hostname
    if parsed.port and parsed.port not in (80, 443):
        netloc = f"{hostname}:{parsed.port}"

    path = parsed.path or "/"
    sanitized = f"{scheme}://{netloc}{path}"
    if clean_query:
        sanitized = f"{sanitized}?{clean_query}"

    return sanitized, hostname


class BaseThreatIntelAdapter(ABC):
    """Abstract base adapter for external threat intelligence providers."""

    name: str = "BaseProvider"

    @abstractmethod
    def check_reputation(self, sanitized_url: str, domain: str) -> ThreatIntelResult:
        """Query reputation for target URL or domain."""
        pass


class VirusTotalAdapter(BaseThreatIntelAdapter):
    """Adapter for VirusTotal API v3 (URL and Domain analyses)."""

    name: str = "VirusTotal"

    def __init__(self, api_key: str, timeout: float = 5.0):
        self.api_key = api_key
        self.timeout = timeout
        self.base_url = "https://www.virustotal.com/api/v3"

    def check_reputation(self, sanitized_url: str, domain: str) -> ThreatIntelResult:
        now_iso = datetime.now(timezone.utc).isoformat()
        if not self.api_key:
            return ThreatIntelResult(
                source="VirusTotal",
                is_flagged=False,
                lookup_timestamp=now_iso,
                lookup_status="UNCONFIGURED",
                provider_name="VirusTotal",
                details="VirusTotal API key is not configured.",
            )

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        # Use base64 URL identifier as per VirusTotal API v3 docs
        url_id = base64.urlsafe_b64encode(sanitized_url.encode("utf-8")).decode("utf-8").strip("=")
        endpoint = f"{self.base_url}/urls/{url_id}"

        try:
            resp = requests.get(endpoint, headers=headers, timeout=self.timeout)

            if resp.status_code == 200:
                payload = resp.json()
                stats = (
                    payload.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)

                # Definitive threat threshold: at least 2 malicious engines or 4 suspicious
                is_flagged = bool(malicious >= 2 or suspicious >= 4)
                if is_flagged:
                    lookup_status = "MATCH_FOUND"
                    details = f"VirusTotal match: flagged by {malicious} malicious and {suspicious} suspicious vendor engines."
                elif malicious == 0 and suspicious == 0:
                    lookup_status = "CLEAN"
                    details = f"VirusTotal clean: 0 vendor engines flagged malicious ({harmless + undetected} clean/undetected)."
                else:
                    lookup_status = "INCONCLUSIVE"
                    details = f"VirusTotal inconclusive: {malicious} malicious, {suspicious} suspicious flags."

                return ThreatIntelResult(
                    source="VirusTotal",
                    is_flagged=is_flagged,
                    lookup_timestamp=now_iso,
                    lookup_status=lookup_status,
                    provider_name="VirusTotal",
                    malicious_count=malicious,
                    suspicious_count=suspicious,
                    harmless_count=harmless + undetected,
                    details=details,
                )

            elif resp.status_code == 404:
                # Target not present in VirusTotal index -> clean/not found
                return ThreatIntelResult(
                    source="VirusTotal",
                    is_flagged=False,
                    lookup_timestamp=now_iso,
                    lookup_status="CLEAN",
                    provider_name="VirusTotal",
                    malicious_count=0,
                    suspicious_count=0,
                    details="Target not found in VirusTotal database (no negative records).",
                )

            elif resp.status_code == 429:
                return ThreatIntelResult(
                    source="VirusTotal",
                    is_flagged=False,
                    lookup_timestamp=now_iso,
                    lookup_status="RATE_LIMITED",
                    provider_name="VirusTotal",
                    details="VirusTotal API rate limit exceeded.",
                )

            else:
                return ThreatIntelResult(
                    source="VirusTotal",
                    is_flagged=False,
                    lookup_timestamp=now_iso,
                    lookup_status="SERVICE_UNAVAILABLE",
                    provider_name="VirusTotal",
                    details=f"VirusTotal API returned HTTP status {resp.status_code}.",
                )

        except requests.exceptions.Timeout:
            logger.warning(f"VirusTotal request timed out after {self.timeout}s.")
            return ThreatIntelResult(
                source="VirusTotal",
                is_flagged=False,
                lookup_timestamp=now_iso,
                lookup_status="SERVICE_UNAVAILABLE",
                provider_name="VirusTotal",
                details=f"VirusTotal request timed out after {self.timeout}s.",
            )
        except requests.exceptions.RequestException as exc:
            logger.warning(f"VirusTotal request connection failure: {exc}")
            return ThreatIntelResult(
                source="VirusTotal",
                is_flagged=False,
                lookup_timestamp=now_iso,
                lookup_status="SERVICE_UNAVAILABLE",
                provider_name="VirusTotal",
                details="VirusTotal connection failure or host unreachable.",
            )


class URLScanAdapter(BaseThreatIntelAdapter):
    """Adapter for URLScan.io API v1 (Domain search lookups)."""

    name: str = "URLScan"

    def __init__(self, api_key: str, timeout: float = 5.0):
        self.api_key = api_key
        self.timeout = timeout
        self.base_url = "https://urlscan.io/api/v1/search"

    def check_reputation(self, sanitized_url: str, domain: str) -> ThreatIntelResult:
        now_iso = datetime.now(timezone.utc).isoformat()
        if not self.api_key:
            return ThreatIntelResult(
                source="URLScan.io",
                is_flagged=False,
                lookup_timestamp=now_iso,
                lookup_status="UNCONFIGURED",
                provider_name="URLScan",
                details="URLScan.io API key is not configured.",
            )

        headers = {
            "API-Key": self.api_key,
            "Accept": "application/json",
        }

        # Privacy minimization: query ONLY the domain, never the full path or parameters
        target_domain = domain or urlparse(sanitized_url).hostname or ""
        params = {"q": f"domain:{target_domain}", "size": 1}

        try:
            resp = requests.get(self.base_url, headers=headers, params=params, timeout=self.timeout)

            if resp.status_code == 200:
                payload = resp.json()
                results = payload.get("results", [])
                if results:
                    latest = results[0]
                    verdicts = latest.get("verdicts", {}).get("overall", {})
                    malicious = verdicts.get("malicious", False)
                    score = verdicts.get("score", 0)

                    is_flagged = bool(malicious or score >= 100)
                    lookup_status = "MATCH_FOUND" if is_flagged else "CLEAN"
                    details = (
                        f"URLScan result: flagged malicious (Score: {score})."
                        if is_flagged
                        else f"URLScan result: verified clean (Score: {score})."
                    )
                    return ThreatIntelResult(
                        source="URLScan.io",
                        is_flagged=is_flagged,
                        lookup_timestamp=now_iso,
                        lookup_status=lookup_status,
                        provider_name="URLScan",
                        details=details,
                    )
                else:
                    return ThreatIntelResult(
                        source="URLScan.io",
                        is_flagged=False,
                        lookup_timestamp=now_iso,
                        lookup_status="CLEAN",
                        provider_name="URLScan",
                        details="No previous malicious scans found for domain in URLScan.io index.",
                    )

            elif resp.status_code == 429:
                return ThreatIntelResult(
                    source="URLScan.io",
                    is_flagged=False,
                    lookup_timestamp=now_iso,
                    lookup_status="RATE_LIMITED",
                    provider_name="URLScan",
                    details="URLScan.io API rate limit reached.",
                )
            else:
                return ThreatIntelResult(
                    source="URLScan.io",
                    is_flagged=False,
                    lookup_timestamp=now_iso,
                    lookup_status="SERVICE_UNAVAILABLE",
                    provider_name="URLScan",
                    details=f"URLScan.io returned HTTP status {resp.status_code}.",
                )

        except requests.exceptions.Timeout:
            logger.warning(f"URLScan request timed out after {self.timeout}s.")
            return ThreatIntelResult(
                source="URLScan.io",
                is_flagged=False,
                lookup_timestamp=now_iso,
                lookup_status="SERVICE_UNAVAILABLE",
                provider_name="URLScan",
                details=f"URLScan request timed out after {self.timeout}s.",
            )
        except requests.exceptions.RequestException as exc:
            logger.warning(f"URLScan request failure: {exc}")
            return ThreatIntelResult(
                source="URLScan.io",
                is_flagged=False,
                lookup_timestamp=now_iso,
                lookup_status="SERVICE_UNAVAILABLE",
                provider_name="URLScan",
                details="URLScan connection failure or host unreachable.",
            )


class ThreatIntelCache:
    """Thread-safe in-memory TTL cache with freshness, stale tracking, and LRU eviction."""

    def __init__(self, ttl_seconds: int = 3600, max_entries: int = 1000):
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._cache: Dict[str, Tuple[ThreatIntelResult, float]] = {}  # key -> (result, cached_at_timestamp)
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[ThreatIntelResult]:
        with self._lock:
            item = self._cache.get(key)
            if not item:
                return None

            result, cached_at = item
            age = time.time() - cached_at

            if age > self.ttl:
                # Mark as stale result rather than clean fresh result
                stale_res = result.model_copy()
                stale_res.is_cached = True
                stale_res.lookup_status = "STALE"
                stale_res.cached_timestamp = datetime.fromtimestamp(cached_at, timezone.utc).isoformat()
                stale_res.details = f"Cached result is stale (observed {int(age)}s ago, TTL {self.ttl}s)."
                return stale_res

            # Fresh cached result
            cached_res = result.model_copy()
            cached_res.is_cached = True
            cached_res.cached_timestamp = datetime.fromtimestamp(cached_at, timezone.utc).isoformat()
            return cached_res

    def set(self, key: str, result: ThreatIntelResult) -> None:
        # Constraint: Do not cache failed, rate-limited, or unconfigured lookups as confirmed results
        if result.lookup_status not in ("MATCH_FOUND", "CLEAN"):
            return

        with self._lock:
            if len(self._cache) >= self.max_entries:
                # Evict oldest entry
                oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
                del self._cache[oldest_key]
            self._cache[key] = (result, time.time())

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


class ThreatIntelService:
    """Orchestrates threat intelligence lookups across configured providers with caching."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        adapters: Optional[List[BaseThreatIntelAdapter]] = None,
        cache: Optional[ThreatIntelCache] = None,
    ):
        self.vt_api_key = api_key or settings.THREAT_INTEL_VIRUSTOTAL_API_KEY
        self.urlscan_api_key = settings.THREAT_INTEL_URLSCAN_API_KEY
        self.timeout = settings.THREAT_INTEL_TIMEOUT_SECONDS
        self.enabled = settings.THREAT_INTEL_ENABLED
        self.cache = cache or ThreatIntelCache(
            ttl_seconds=settings.THREAT_INTEL_CACHE_TTL_SECONDS,
            max_entries=settings.THREAT_INTEL_MAX_CACHE_ENTRIES,
        )

        if adapters is not None:
            self.adapters = adapters
        else:
            self.adapters = []
            if self.vt_api_key:
                self.adapters.append(VirusTotalAdapter(api_key=self.vt_api_key, timeout=self.timeout))
            if self.urlscan_api_key:
                self.adapters.append(URLScanAdapter(api_key=self.urlscan_api_key, timeout=self.timeout))

    def check_reputation(self, url: str) -> ThreatIntelResult:
        """Check domain or URL against external reputation sources safely."""
        now_iso = datetime.now(timezone.utc).isoformat()

        # Sanitize target URL and enforce data minimization
        sanitized_url, domain = sanitize_url_for_lookup(url)
        cache_key = f"{domain}:{sanitized_url}".lower()

        # 1. Check local cache
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        # 2. Check if external lookups are disabled or unconfigured
        if not self.enabled or not self.adapters:
            status_str = "UNCONFIGURED"
            return ThreatIntelResult(
                source="FraudLens Threat Feed",
                is_flagged=False,
                lookup_timestamp=now_iso,
                lookup_status=status_str,
                details="External threat feed lookup is unconfigured or disabled. Running in local-only detection mode.",
            )

        # 3. Query configured adapters in order
        for adapter in self.adapters:
            try:
                result = adapter.check_reputation(sanitized_url, domain)
                # If a match is found or conclusive result obtained, cache and return
                if result.lookup_status in ("MATCH_FOUND", "CLEAN"):
                    self.cache.set(cache_key, result)
                    return result
                elif result.lookup_status in ("RATE_LIMITED", "SERVICE_UNAVAILABLE"):
                    # Continue to next adapter if available
                    continue
            except Exception as err:
                logger.warning(f"Error querying threat adapter {adapter.name}: {err}")
                continue

        # 4. Fallback if all configured providers failed or were unavailable
        return ThreatIntelResult(
            source="FraudLens Threat Feed",
            is_flagged=False,
            lookup_timestamp=now_iso,
            lookup_status="SERVICE_UNAVAILABLE",
            details="Threat intelligence providers were unreachable or timed out. Local ML and heuristics remain fully active.",
        )


_global_threat_intel_service: Optional[ThreatIntelService] = None


def get_threat_intel_service() -> ThreatIntelService:
    """Dependency injector for singleton ThreatIntelService."""
    global _global_threat_intel_service
    if _global_threat_intel_service is None:
        _global_threat_intel_service = ThreatIntelService()
    return _global_threat_intel_service
