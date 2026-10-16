"""Unit and integration tests for FraudLens Threat Intelligence Integration.

Verifies:
1. Provider adapter abstractions (VirusTotal v3, URLScan v1) with mocked API responses.
2. Threat intel caching with TTL expiration, stale handling, and capacity management.
3. Strict data minimization and URL indicator sanitization (stripping userinfo, sensitive tokens).
4. Error resilience: graceful degradation on timeouts, 429 rate limits, and provider network failures.
5. Invariant: Offline by default; no required paid subscriptions or unexpected egress.
"""

from datetime import datetime, timezone, timedelta
import unittest
from unittest.mock import MagicMock, patch
import requests

from backend.app.schemas.url import ThreatIntelResult
from backend.app.services.threat_intel import (
    ThreatIntelCache,
    ThreatIntelService,
    URLScanAdapter,
    VirusTotalAdapter,
    sanitize_url_for_lookup,
)


class TestThreatIntelSanitization(unittest.TestCase):
    """Test data minimization and privacy sanitization of target URLs."""

    def test_strip_credentials_and_sensitive_tokens(self):
        """Verify username, password, and sensitive query tokens are stripped."""
        raw_url = "https://alice:secret123@auth-bank.com/login?token=abc-token-xyz&user=test&otp=998877&session_id=sess456"
        sanitized, domain = sanitize_url_for_lookup(raw_url)

        self.assertEqual(domain, "auth-bank.com")
        self.assertTrue(sanitized.startswith("https://auth-bank.com/login"))
        # Credentials stripped
        self.assertNotIn("alice", sanitized)
        self.assertNotIn("secret123", sanitized)
        # Sensitive query parameters stripped
        self.assertNotIn("abc-token-xyz", sanitized)
        self.assertNotIn("998877", sanitized)
        self.assertNotIn("sess456", sanitized)
        # Non-sensitive query parameters retained
        self.assertIn("user=test", sanitized)

    def test_clean_ordinary_url_preserved(self):
        """Verify normal URLs without sensitive keys remain intact."""
        raw_url = "https://example.com/about/team?page=2&sort=asc"
        sanitized, domain = sanitize_url_for_lookup(raw_url)
        self.assertEqual(domain, "example.com")
        self.assertEqual(sanitized, "https://example.com/about/team?page=2&sort=asc")

    def test_bare_domain_canonicalized(self):
        """Verify bare domains receive valid structure."""
        sanitized, domain = sanitize_url_for_lookup("example.org")
        self.assertEqual(domain, "example.org")
        self.assertEqual(sanitized, "http://example.org/")


class TestThreatIntelCache(unittest.TestCase):
    """Test in-memory TTL caching and stale tracking."""

    def test_cache_put_and_hit(self):
        """Verify setting and getting a valid cached item."""
        cache = ThreatIntelCache(ttl_seconds=300, max_entries=10)
        result = ThreatIntelResult(
            source="MockProvider",
            is_flagged=False,
            lookup_timestamp=datetime.now(timezone.utc).isoformat(),
            lookup_status="CLEAN",
            details="Mock clean report",
        )
        cache.set("https://example.com/", result)

        cached_item = cache.get("https://example.com/")
        self.assertIsNotNone(cached_item)
        self.assertTrue(cached_item.is_cached)
        self.assertEqual(cached_item.lookup_status, "CLEAN")

    def test_cache_miss(self):
        """Verify unknown URLs return None."""
        cache = ThreatIntelCache(ttl_seconds=300, max_entries=10)
        self.assertIsNone(cache.get("https://notfound.com/"))

    def test_cache_stale_handling(self):
        """Verify entries exceeding TTL return stale cached result with status STALE."""
        cache = ThreatIntelCache(ttl_seconds=10, max_entries=10)
        past_iso = (datetime.now(timezone.utc) - timedelta(seconds=20)).isoformat()
        result = ThreatIntelResult(
            source="MockProvider",
            is_flagged=True,
            lookup_timestamp=past_iso,
            lookup_status="MATCH_FOUND",
            details="Old malicious match",
        )
        # Manually seed cache with timestamp in the past
        cache._cache["https://stale-example.com/"] = (result, datetime.now(timezone.utc).timestamp() - 30)

        # Current get should mark as stale
        stale_item = cache.get("https://stale-example.com/")
        self.assertIsNotNone(stale_item)
        self.assertTrue(stale_item.is_cached)
        self.assertEqual(stale_item.lookup_status, "STALE")
        self.assertIn("stale", stale_item.details.lower())

    def test_cache_capacity_eviction(self):
        """Verify oldest entry is evicted when max_entries is exceeded."""
        cache = ThreatIntelCache(ttl_seconds=300, max_entries=2)
        r1 = ThreatIntelResult(
            source="P", is_flagged=False, lookup_timestamp=datetime.now(timezone.utc).isoformat(), lookup_status="CLEAN"
        )
        r2 = ThreatIntelResult(
            source="P", is_flagged=False, lookup_timestamp=datetime.now(timezone.utc).isoformat(), lookup_status="CLEAN"
        )
        r3 = ThreatIntelResult(
            source="P", is_flagged=False, lookup_timestamp=datetime.now(timezone.utc).isoformat(), lookup_status="CLEAN"
        )

        cache.set("url1", r1)
        cache.set("url2", r2)
        cache.set("url3", r3)

        self.assertIsNone(cache.get("url1"))
        self.assertIsNotNone(cache.get("url2"))
        self.assertIsNotNone(cache.get("url3"))

    def test_do_not_cache_transient_failures(self):
        """Verify rate limits or errors are not cached as confirmed results."""
        cache = ThreatIntelCache(ttl_seconds=300, max_entries=10)
        res_rate = ThreatIntelResult(
            source="P", is_flagged=False, lookup_timestamp=datetime.now(timezone.utc).isoformat(), lookup_status="RATE_LIMITED"
        )
        res_unavail = ThreatIntelResult(
            source="P", is_flagged=False, lookup_timestamp=datetime.now(timezone.utc).isoformat(), lookup_status="SERVICE_UNAVAILABLE"
        )

        cache.set("url_rate", res_rate)
        cache.set("url_unavail", res_unavail)

        # Neither transient state should pollute the clean cache
        self.assertIsNone(cache.get("url_rate"))
        self.assertIsNone(cache.get("url_unavail"))


class TestVirusTotalAdapter(unittest.TestCase):
    """Test VirusTotal v3 adapter with mocked HTTP responses."""

    def test_unconfigured_when_no_api_key(self):
        """Verify adapter reports UNCONFIGURED without making HTTP calls."""
        adapter = VirusTotalAdapter(api_key="")
        res = adapter.check_reputation("https://example.com", "example.com")
        self.assertEqual(res.lookup_status, "UNCONFIGURED")
        self.assertFalse(res.is_flagged)

    @patch("requests.get")
    def test_mocked_virustotal_malicious_match(self, mock_get):
        """Verify flagged response when vendors detect malicious indicator."""
        adapter = VirusTotalAdapter(api_key="mock_vt_key_12345")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 8,
                        "suspicious": 2,
                        "harmless": 45,
                        "undetected": 15,
                    }
                }
            }
        }
        mock_get.return_value = mock_resp

        res = adapter.check_reputation("https://phishing-domain.net/login", "phishing-domain.net")
        self.assertEqual(res.lookup_status, "MATCH_FOUND")
        self.assertTrue(res.is_flagged)
        self.assertEqual(res.malicious_count, 8)
        self.assertEqual(res.suspicious_count, 2)
        self.assertIn("flagged by 8 malicious", res.details)

    @patch("requests.get")
    def test_mocked_virustotal_clean_verdict(self, mock_get):
        """Verify clean response when zero vendors flag URL."""
        adapter = VirusTotalAdapter(api_key="mock_vt_key_12345")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 70,
                        "undetected": 5,
                    }
                }
            }
        }
        mock_get.return_value = mock_resp

        res = adapter.check_reputation("https://legit-service.com", "legit-service.com")
        self.assertEqual(res.lookup_status, "CLEAN")
        self.assertFalse(res.is_flagged)
        self.assertEqual(res.malicious_count, 0)
        self.assertIn("0 vendor engines flagged", res.details)

    @patch("requests.get")
    def test_mocked_virustotal_rate_limit(self, mock_get):
        """Verify HTTP 429 returns RATE_LIMITED without crashing."""
        adapter = VirusTotalAdapter(api_key="mock_vt_key_12345")

        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        res = adapter.check_reputation("https://example.com", "example.com")
        self.assertEqual(res.lookup_status, "RATE_LIMITED")
        self.assertFalse(res.is_flagged)
        self.assertIn("rate limit", res.details.lower())

    @patch("requests.get")
    def test_mocked_virustotal_timeout(self, mock_get):
        """Verify network timeout returns SERVICE_UNAVAILABLE without crashing."""
        adapter = VirusTotalAdapter(api_key="mock_vt_key_12345")
        mock_get.side_effect = requests.Timeout("Connection timed out after 3.0s")

        res = adapter.check_reputation("https://example.com", "example.com")
        self.assertEqual(res.lookup_status, "SERVICE_UNAVAILABLE")
        self.assertFalse(res.is_flagged)
        self.assertIn("timed out", res.details.lower())


class TestURLScanAdapter(unittest.TestCase):
    """Test URLScan.io v1 adapter with mocked HTTP responses."""

    def test_unconfigured_when_no_api_key(self):
        """Verify URLScan adapter reports UNCONFIGURED without making network calls."""
        adapter = URLScanAdapter(api_key="")
        res = adapter.check_reputation("https://example.com", "example.com")
        self.assertEqual(res.lookup_status, "UNCONFIGURED")

    @patch("requests.get")
    def test_mocked_urlscan_malicious_match(self, mock_get):
        """Verify URLScan returns MATCH_FOUND when verdict indicates malicious."""
        adapter = URLScanAdapter(api_key="mock_urlscan_key")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": [
                {
                    "verdicts": {
                        "overall": {
                            "malicious": True,
                            "score": 100,
                            "categories": ["phishing"],
                        }
                    }
                }
            ]
        }
        mock_get.return_value = mock_resp

        res = adapter.check_reputation("https://fake-login-portal.biz", "fake-login-portal.biz")
        self.assertEqual(res.lookup_status, "MATCH_FOUND")
        self.assertTrue(res.is_flagged)


class TestThreatIntelServiceOrchestrator(unittest.TestCase):
    """Test ThreatIntelService caching and adapter orchestration."""

    def test_default_offline_service(self):
        """Verify default ThreatIntelService operates offline without external egress."""
        service = ThreatIntelService(adapters=[])
        service.enabled = False
        res = service.check_reputation("https://unknown-site.org/page")

        self.assertEqual(res.lookup_status, "UNCONFIGURED")
        self.assertFalse(res.is_flagged)

    @patch("requests.get")
    def test_service_caches_external_matches(self, mock_get):
        """Verify ThreatIntelService caches external responses and serves cached results on second query."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "harmless": 20,
                        "undetected": 10,
                    }
                }
            }
        }
        mock_get.return_value = mock_resp

        vt_adapter = VirusTotalAdapter(api_key="active_key_test")
        cache = ThreatIntelCache(ttl_seconds=300, max_entries=10)
        service = ThreatIntelService(adapters=[vt_adapter], cache=cache)
        service.enabled = True

        # First query: should make external request and cache result
        res1 = service.check_reputation("https://bad-site.com/verify?token=secret123")
        self.assertEqual(res1.lookup_status, "MATCH_FOUND")
        self.assertFalse(res1.is_cached)
        self.assertEqual(mock_get.call_count, 1)

        # Second query: same domain and sanitized path should hit cache and NOT make external request
        res2 = service.check_reputation("https://bad-site.com/verify?token=different_token_456")
        self.assertEqual(res2.lookup_status, "MATCH_FOUND")
        self.assertTrue(res2.is_cached)
        # External request call count remains 1 due to cache hit
        self.assertEqual(mock_get.call_count, 1)
