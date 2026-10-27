"""Domain Intelligence Service for FraudLens (WHOIS/RDAP, Domain Age & Security Indicators).

Integrates:
1. Authoritative RDAP lookup with WHOIS fallback.
2. Domain age calculation strictly from creation date to current UTC date.
3. TLS/HTTPS certificate inspection (handshake verification without content egress).
4. Configurable subscore weighting across age, structure, metadata, and TLS.
5. Thread-safe in-memory TTL caching by normalized registrable domain.
6. SSRF protections against internal, loopback, private, and IP-address hosts.
7. Data minimization and statistical humility (no false safety claims from clean lookups or HTTPS).
"""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import ipaddress
import logging
from pathlib import Path
import re
import socket
import ssl
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import dateutil.parser
import requests
import tldextract

from backend.app.config import settings
from backend.app.schemas.url import DomainIntelligenceResult
from backend.app.services.url_features import is_ip_host

logger = logging.getLogger(__name__)

_proj_root = Path(__file__).resolve().parent.parent.parent.parent
_tld_cache_dir = str(_proj_root / "data" / "processed" / "urls" / ".tld_cache")

# Offline TLDExtract instance (strictly zero network egress for public-suffix parsing)
_offline_tld_extract = tldextract.TLDExtract(
    cache_dir=_tld_cache_dir,
    suffix_list_urls=(),
)


def is_internal_or_private_host(hostname: str) -> bool:
    """Check if a hostname or IP is loopback, private, link-local, reserved, or localhost."""
    clean = (hostname or "").strip().lower()
    if not clean:
        return True
    if clean in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    if clean.endswith(".local") or clean.endswith(".internal") or clean.endswith(".lan"):
        return True
    try:
        ip = ipaddress.ip_address(clean)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        return False


def parse_datetime_flexible(dt_val: Any) -> Optional[datetime]:
    """Safely parse various datetime representations from RDAP or WHOIS into UTC datetime."""
    if not dt_val:
        return None
    if isinstance(dt_val, (list, tuple)):
        # If multiple dates returned (e.g. from whois), select the earliest creation date
        valid_dates = [parse_datetime_flexible(d) for d in dt_val]
        valid_dates = [d for d in valid_dates if d is not None]
        return min(valid_dates) if valid_dates else None
    if isinstance(dt_val, datetime):
        if dt_val.tzinfo is None:
            return dt_val.replace(tzinfo=timezone.utc)
        return dt_val.astimezone(timezone.utc)
    if isinstance(dt_val, str):
        cleaned_str = dt_val.strip()
        if not cleaned_str:
            return None
        try:
            # Try ISO 8601 / RFC 3339
            dt = dateutil.parser.isoparse(cleaned_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass
        try:
            dt = dateutil.parser.parse(cleaned_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass
    return None


class DomainIntelligenceCache:
    """Thread-safe in-memory TTL cache for domain registration intelligence."""

    def __init__(self, ttl_seconds: int = 86400, max_entries: int = 2000):
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._cache: Dict[str, Tuple[DomainIntelligenceResult, float]] = {}
        self._lock = threading.Lock()

    def get(self, domain_key: str) -> Optional[DomainIntelligenceResult]:
        key = (domain_key or "").strip().lower()
        with self._lock:
            item = self._cache.get(key)
            if not item:
                return None
            result, cached_at = item
            age = time.time() - cached_at
            if age > self.ttl:
                # Expired
                del self._cache[key]
                return None

            cached_copy = result.model_copy()
            cached_copy.is_cached = True
            return cached_copy

    def set(self, domain_key: str, result: DomainIntelligenceResult) -> None:
        key = (domain_key or "").strip().lower()
        if not key or result.lookup_status in ("TIMED_OUT", "NOT_APPLICABLE"):
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


class DomainIntelligenceService:
    """Reusable service evaluating domain registration, age, and security indicators."""

    def __init__(
        self,
        cache: Optional[DomainIntelligenceCache] = None,
        timeout: Optional[float] = None,
        rdap_base_url: Optional[str] = None,
        enabled: Optional[bool] = None,
    ):
        self.cache = cache or DomainIntelligenceCache(
            ttl_seconds=settings.DOMAIN_INTEL_CACHE_TTL_SECONDS,
            max_entries=settings.DOMAIN_INTEL_MAX_CACHE_ENTRIES,
        )
        self.timeout = timeout if timeout is not None else settings.DOMAIN_INTEL_TIMEOUT_SECONDS
        self.rdap_base_url = rdap_base_url or settings.DOMAIN_INTEL_RDAP_BASE_URL
        self.enabled = enabled if enabled is not None else settings.DOMAIN_INTEL_ENABLED

    def extract_domain_info(self, url_or_hostname: str) -> Tuple[str, str, bool, bool]:
        """Extract normalized hostname and registrable domain with public-suffix awareness.
        
        Returns:
            (normalized_hostname, registrable_domain, has_ip, is_internal)
        """
        raw = (url_or_hostname or "").strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
            raw = f"http://{raw}"

        try:
            parsed = urlparse(raw)
            hostname = (parsed.hostname or "").lower().strip()
        except Exception:
            hostname = raw.lower().strip()

        has_ip = is_ip_host(hostname)
        is_internal = is_internal_or_private_host(hostname)

        try:
            extracted = _offline_tld_extract(raw)
            if extracted.domain and extracted.suffix:
                registrable_domain = f"{extracted.domain}.{extracted.suffix}".lower()
            elif extracted.domain:
                registrable_domain = extracted.domain.lower()
            else:
                registrable_domain = hostname
        except Exception:
            registrable_domain = hostname

        return hostname, registrable_domain, has_ip, is_internal

    def lookup_rdap(self, domain: str) -> Optional[Dict[str, Any]]:
        """Query standard open RDAP endpoint for domain registration metadata."""
        clean_domain = (domain or "").strip().lower()
        if not clean_domain or is_internal_or_private_host(clean_domain) or is_ip_host(clean_domain):
            return None

        url = f"{self.rdap_base_url.rstrip('/')}/{clean_domain}"
        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "FraudLens-DomainIntelligence/1.0",
        }

        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)
            if resp.status_code == 200:
                data = resp.json()
                created_at: Optional[datetime] = None
                expires_at: Optional[datetime] = None

                # Parse events
                for event in data.get("events", []):
                    action = str(event.get("eventAction", "")).lower()
                    date_str = event.get("eventDate")
                    if action in ("registration", "created", "registration date"):
                        created_at = parse_datetime_flexible(date_str)
                    elif action in ("expiration", "expired", "expiration date"):
                        expires_at = parse_datetime_flexible(date_str)

                # Parse registrar from entities
                registrar: Optional[str] = None
                for entity in data.get("entities", []):
                    roles = [str(r).lower() for r in entity.get("roles", [])]
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [])
                        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                            for prop in vcard[1]:
                                if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn":
                                    registrar = str(prop[3]).strip()
                                    break
                        if not registrar and entity.get("handle"):
                            registrar = str(entity["handle"]).strip()

                # Status codes
                statuses = [str(s).strip() for s in data.get("status", []) if s]

                # Nameservers
                nameservers = []
                for ns in data.get("nameservers", []):
                    name = ns.get("ldhName") or ns.get("handle")
                    if name:
                        nameservers.append(str(name).strip().upper())

                return {
                    "created_at": created_at,
                    "expires_at": expires_at,
                    "registrar": registrar,
                    "status": statuses,
                    "nameservers": nameservers,
                    "source": "RDAP",
                }
            elif resp.status_code == 404:
                logger.info(f"RDAP 404 for domain '{clean_domain}'.")
                return None
            else:
                logger.info(f"RDAP lookup returned HTTP {resp.status_code} for '{clean_domain}'.")
                return None
        except requests.exceptions.Timeout:
            logger.warning(f"RDAP lookup timed out after {self.timeout}s for '{clean_domain}'.")
            raise TimeoutError(f"RDAP lookup timed out after {self.timeout}s")
        except Exception as exc:
            logger.info(f"RDAP lookup error for '{clean_domain}': {exc}")
            return None

    def lookup_whois(self, domain: str) -> Optional[Dict[str, Any]]:
        """Fallback lookup using python-whois protocol."""
        clean_domain = (domain or "").strip().lower()
        if not clean_domain or is_internal_or_private_host(clean_domain) or is_ip_host(clean_domain):
            return None

        try:
            import whois
            w = whois.whois(clean_domain)
            if not w:
                return None

            created_at = parse_datetime_flexible(w.creation_date)
            expires_at = parse_datetime_flexible(w.expiration_date)
            registrar = str(w.registrar).strip() if w.registrar else None

            # Nameservers
            nameservers = []
            if w.name_servers:
                ns_list = w.name_servers if isinstance(w.name_servers, (list, tuple, set)) else [w.name_servers]
                for ns in ns_list:
                    if ns:
                        nameservers.append(str(ns).strip().upper())

            # Status
            statuses = []
            if w.status:
                s_list = w.status if isinstance(w.status, (list, tuple, set)) else [w.status]
                for st in s_list:
                    if st:
                        statuses.append(str(st).strip())

            return {
                "created_at": created_at,
                "expires_at": expires_at,
                "registrar": registrar,
                "status": statuses,
                "nameservers": nameservers,
                "source": "WHOIS",
            }
        except Exception as exc:
            logger.info(f"WHOIS fallback lookup error for '{clean_domain}': {exc}")
            return None

    def check_tls(self, hostname: str) -> Tuple[Optional[bool], Optional[str], Optional[str]]:
        """Perform a safe TLS handshake on port 443 without downloading page content.
        
        Returns:
            (is_valid, issuer_org, expires_at_iso)
        """
        clean_host = (hostname or "").strip().lower()
        if not clean_host or is_internal_or_private_host(clean_host) or is_ip_host(clean_host):
            return None, None, None

        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((clean_host, 443), timeout=1.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return True, None, None

                    # Extract issuer
                    issuer_org = None
                    for rdn in cert.get("issuer", ()):
                        for attr in rdn:
                            if attr[0] in ("organizationName", "commonName"):
                                issuer_org = attr[1]
                                break
                        if issuer_org:
                            break

                    # Extract expiry
                    not_after_str = cert.get("notAfter")
                    not_after_iso = None
                    if not_after_str:
                        try:
                            dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            not_after_iso = dt.isoformat()
                        except Exception:
                            not_after_iso = None

                    return True, issuer_org, not_after_iso
        except (ssl.SSLError, ssl.CertificateError) as ssl_err:
            logger.info(f"TLS certificate error for '{clean_host}': {ssl_err}")
            return False, None, None
        except Exception:
            # Port 443 closed or connection timeout -> host may be HTTP-only
            return None, None, None

    @staticmethod
    def calculate_domain_age(
        created_at: Any,
        now_utc: Optional[datetime] = None,
    ) -> Tuple[Optional[int], str, float]:
        """Calculate domain age strictly from creation date and current UTC date.
        
        Returns:
            (age_days, age_explanation, age_risk_score)
            age_risk_score: 0.0 (safe) to 1.0 (very high risk)
        """
        if created_at is None:
            return (
                None,
                "Registration age could not be established; this check did not contribute negative evidence.",
                0.0,
            )

        parsed_created: Optional[datetime] = None
        if isinstance(created_at, str):
            parsed_created = parse_datetime_flexible(created_at)
        elif isinstance(created_at, datetime):
            parsed_created = created_at

        if parsed_created is None:
            return (
                None,
                "Registration age could not be established; this check did not contribute negative evidence.",
                0.0,
            )

        if parsed_created.tzinfo is None:
            parsed_created = parsed_created.replace(tzinfo=timezone.utc)

        now = now_utc or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        diff = now - parsed_created
        age_days = max(0, diff.days)

        # Configurable Domain-Age Risk Bands from Change 2 B:
        # - Under 7 days: very strong new-domain warning.
        # - 7–30 days: strong warning.
        # - 31–90 days: moderate warning.
        # - 91–180 days: mild warning.
        # - Over 180 days: no age-based warning by itself.
        if age_days < 7:
            return (
                age_days,
                f"Very strong new-domain warning: registered only {age_days} day(s) ago (under 7 days). Recently created domains carry elevated fraud risk.",
                1.0,
            )
        elif age_days <= 30:
            return (
                age_days,
                f"Strong new-domain warning: registered {age_days} days ago (within 30 days). Common in disposable phishing campaigns.",
                0.75,
            )
        elif age_days <= 90:
            return (
                age_days,
                f"Moderate warning: registered {age_days} days ago (within 90 days). Caution advised when combined with other indicators.",
                0.45,
            )
        elif age_days <= 180:
            return (
                age_days,
                f"Mild warning: registered {age_days} days ago (within 180 days).",
                0.20,
            )
        else:
            years = age_days / 365.25
            return (
                age_days,
                f"Established domain: registered {age_days:,} days ago ({years:.1f} years). No age-based warning detected.",
                0.0,
            )

    def evaluate_subscore(
        self,
        age_score: float,
        is_age_available: bool,
        is_impersonation: bool,
        is_excessive_subdomains: bool,
        registration_status: List[str],
        tls_valid: Optional[bool],
    ) -> Tuple[float, List[str]]:
        """Calculate domain-intelligence subscore (0.0 to 1.0) with normalized weights.
        
        Initial subscore distribution:
        - Domain registration age: 40%
        - Domain structure & impersonation indicators: 25%
        - Registration metadata & registrar signals: 15%
        - HTTPS/TLS certificate indicators: 20%
        """
        weights: Dict[str, float] = {
            "age": 0.40,
            "structure": 0.25,
            "metadata": 0.15,
            "tls": 0.20,
        }
        scores: Dict[str, float] = {}
        findings: List[str] = []

        # 1. Registration Age (40%)
        if is_age_available:
            scores["age"] = age_score
        else:
            # Re-normalize: missing registration age does not contribute negative evidence
            weights.pop("age", None)

        # 2. Domain Structure & Impersonation (25%)
        structure_score = 0.0
        if is_impersonation:
            structure_score = 1.0
            findings.append("Domain structure reflects brand typosquatting or lookalike impersonation.")
        elif is_excessive_subdomains:
            structure_score = 0.5
            findings.append("Excessive subdomain depth detected, frequently used in domain cloaking.")
        scores["structure"] = structure_score

        # 3. Registration Metadata & Registrar Signals (15%)
        # Note: missing metadata is never penalized per specification
        metadata_score = 0.0
        suspicious_statuses = [
            s for s in registration_status
            if any(term in s.lower() for term in ("pendingdelete", "redemption", "hold", "prohibited", "banned"))
        ]
        if any("pendingdelete" in s.lower() or "redemption" in s.lower() for s in suspicious_statuses):
            metadata_score = 0.8
            findings.append("Domain lifecycle status indicates pending deletion or redemption state.")
        scores["metadata"] = metadata_score

        # 4. HTTPS/TLS Certificate Indicators (20%)
        if tls_valid is not None:
            if not tls_valid:
                scores["tls"] = 0.7
                findings.append("TLS/HTTPS certificate verification failed or returned an invalid certificate.")
            else:
                # Note: valid certificate is NOT treated as proof of legitimacy
                scores["tls"] = 0.0
        else:
            # TLS not evaluated or HTTP-only
            weights.pop("tls", None)

        # Normalize weights
        total_weight = sum(weights.values())
        if total_weight <= 0:
            return 0.0, findings

        final_subscore = sum(scores[cat] * (weights[cat] / total_weight) for cat in weights)
        return min(1.0, max(0.0, round(final_subscore, 3))), findings

    def analyze_domain(
        self,
        url_or_hostname: str = "",
        is_impersonation: bool = False,
        is_excessive_subdomains: bool = False,
        url_or_domain: Optional[str] = None,
    ) -> DomainIntelligenceResult:
        """Execute comprehensive domain intelligence lookup and evaluation."""
        target_str = url_or_domain if url_or_domain is not None else url_or_hostname
        now_iso = datetime.now(timezone.utc).isoformat()
        hostname, reg_domain, has_ip, is_internal = self.extract_domain_info(target_str)

        # Case 1: IP-address host or internal/private host -> NOT_APPLICABLE
        if has_ip or is_internal:
            findings = [
                "Host is an IP address or internal/loopback destination. Domain registration checks are not applicable."
            ]
            return DomainIntelligenceResult(
                domain=reg_domain,
                hostname=hostname,
                domain_age_days=None,
                domain_created_at=None,
                domain_expires_at=None,
                registrar=None,
                registration_status=[],
                nameservers=[],
                rdap_available=False,
                whois_available=False,
                lookup_status="NOT_APPLICABLE",
                domain_intelligence_score=0.0,
                domain_intelligence_findings=findings,
                checked_at=now_iso,
                tls_certificate_valid=None,
                tls_issuer=None,
                tls_expires_at=None,
                is_cached=False,
            )

        # Case 2: Check in-memory cache by registrable domain
        cached = self.cache.get(reg_domain)
        if cached is not None:
            # Re-evaluate structure findings for current URL if cached
            return cached

        # Case 3: Domain intelligence disabled
        if not self.enabled:
            return DomainIntelligenceResult(
                domain=reg_domain,
                hostname=hostname,
                domain_age_days=None,
                domain_created_at=None,
                domain_expires_at=None,
                registrar=None,
                registration_status=[],
                nameservers=[],
                rdap_available=False,
                whois_available=False,
                lookup_status="UNCONFIGURED",
                domain_intelligence_score=0.0,
                domain_intelligence_findings=["Domain intelligence service is disabled or unconfigured."],
                checked_at=now_iso,
                tls_certificate_valid=None,
                tls_issuer=None,
                tls_expires_at=None,
                is_cached=False,
            )

        # Case 4: Live query (RDAP preferred, WHOIS fallback)
        rdap_data: Optional[Dict[str, Any]] = None
        whois_data: Optional[Dict[str, Any]] = None
        is_timed_out = False
        rdap_ok = False
        whois_ok = False

        try:
            rdap_data = self.lookup_rdap(reg_domain)
            if rdap_data:
                rdap_ok = True
        except TimeoutError:
            is_timed_out = True
        except Exception:
            rdap_data = None

        if not rdap_data and not is_timed_out:
            try:
                whois_data = self.lookup_whois(reg_domain)
                if whois_data:
                    whois_ok = True
            except Exception:
                whois_data = None

        data = rdap_data or whois_data

        # TLS check
        tls_valid, tls_issuer, tls_expires = self.check_tls(hostname)

        if data:
            created_at = data.get("created_at")
            expires_at = data.get("expires_at")
            registrar = data.get("registrar")
            statuses = data.get("status") or []
            nameservers = data.get("nameservers") or []
            lookup_status = "SUCCESS" if (created_at and registrar) else "PARTIAL"

            age_days, age_exp, age_risk = self.calculate_domain_age(created_at)

            subscore, findings = self.evaluate_subscore(
                age_score=age_risk,
                is_age_available=age_days is not None,
                is_impersonation=is_impersonation,
                is_excessive_subdomains=is_excessive_subdomains,
                registration_status=statuses,
                tls_valid=tls_valid,
            )

            all_findings = [age_exp] + findings
            if tls_issuer:
                all_findings.append(f"TLS certificate issued by '{tls_issuer}'.")

            def _to_iso(val: Any) -> Optional[str]:
                if val is None:
                    return None
                if isinstance(val, str):
                    return val
                if hasattr(val, "isoformat"):
                    return val.isoformat()
                return str(val)

            result = DomainIntelligenceResult(
                domain=reg_domain,
                hostname=hostname,
                domain_age_days=age_days,
                domain_created_at=_to_iso(created_at),
                domain_expires_at=_to_iso(expires_at),
                registrar=registrar,
                registration_status=statuses,
                nameservers=nameservers,
                rdap_available=rdap_ok,
                whois_available=whois_ok,
                lookup_status=lookup_status,
                domain_intelligence_score=subscore,
                domain_intelligence_findings=all_findings,
                checked_at=now_iso,
                tls_certificate_valid=tls_valid,
                tls_issuer=tls_issuer,
                tls_expires_at=tls_expires,
                is_cached=False,
            )
            self.cache.set(reg_domain, result)
            return result
        else:
            # Lookup failed or timed out
            status_str = "TIMED_OUT" if is_timed_out else "UNAVAILABLE"
            reason = "Registration lookup timed out." if is_timed_out else "Registration metadata unavailable for domain."
            findings = [
                f"{reason} Domain age could not be established; this check did not contribute negative evidence."
            ]

            subscore, eval_findings = self.evaluate_subscore(
                age_score=0.0,
                is_age_available=False,
                is_impersonation=is_impersonation,
                is_excessive_subdomains=is_excessive_subdomains,
                registration_status=[],
                tls_valid=tls_valid,
            )
            findings.extend(eval_findings)

            return DomainIntelligenceResult(
                domain=reg_domain,
                hostname=hostname,
                domain_age_days=None,
                domain_created_at=None,
                domain_expires_at=None,
                registrar=None,
                registration_status=[],
                nameservers=[],
                rdap_available=False,
                whois_available=False,
                lookup_status=status_str,
                domain_intelligence_score=subscore,
                domain_intelligence_findings=findings,
                checked_at=now_iso,
                tls_certificate_valid=tls_valid,
                tls_issuer=tls_issuer,
                tls_expires_at=tls_expires,
                is_cached=False,
            )


_global_domain_intel_service: Optional[DomainIntelligenceService] = None


def get_domain_intelligence_service() -> DomainIntelligenceService:
    """Dependency injector for singleton DomainIntelligenceService."""
    global _global_domain_intel_service
    if _global_domain_intel_service is None:
        _global_domain_intel_service = DomainIntelligenceService()
    return _global_domain_intel_service
