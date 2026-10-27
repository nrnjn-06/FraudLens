"""Reusable lexical and structural URL feature extraction engine for FraudLens.

Operates deterministically without network calls, DNS lookups, or live website scanning.
Extracts 34 lexical, structural, entropy, and local heuristic indicators.
"""

from collections import Counter
from datetime import datetime
import ipaddress
import math
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse
from pathlib import Path
import tldextract

# Fixed list of 34 deterministic feature names in canonical schema order
FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "count_dots",
    "count_hyphens",
    "count_underscores",
    "count_slashes",
    "count_question_marks",
    "count_equal_signs",
    "count_at_symbols",
    "count_ampersands",
    "count_exclamations",
    "count_percent_signs",
    "count_digits",
    "count_letters",
    "ratio_digits_url",
    "ratio_digits_hostname",
    "count_subdomains",
    "has_ip_address",
    "is_https",
    "is_http",
    "has_non_standard_port",
    "has_at_symbol",
    "has_double_slash_path",
    "count_query_parameters",
    "suspicious_token_count",
    "has_suspicious_token",
    "url_entropy",
    "hostname_entropy",
    "has_punycode",
    "brand_impersonation_score",
    "suspicious_tld",
    "consecutive_hyphens",
]

# High-profile brand targets commonly spoofed in phishing campaigns
TARGET_BRANDS: List[str] = [
    "paypal",
    "google",
    "apple",
    "microsoft",
    "amazon",
    "netflix",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "citi",
    "sbi",
    "hdfc",
    "icici",
    "facebook",
    "instagram",
    "whatsapp",
    "yahoo",
    "ebay",
    "dropbox",
    "binance",
    "coinbase",
    "dhl",
    "fedex",
    "usps",
]

# Sensitive action/credential tokens frequently observed in phishing lures
SUSPICIOUS_TOKENS: List[str] = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "update",
    "secure",
    "security",
    "account",
    "banking",
    "confirm",
    "confirmation",
    "password",
    "credential",
    "wallet",
    "admin",
    "recover",
    "webscr",
    "authenticate",
    "auth",
    "validate",
    "validation",
    "portal",
]

# Top-level domains historically exhibiting disproportionate abuse or free/cheap registration
SUSPICIOUS_TLDS: set[str] = {
    "xyz",
    "top",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "work",
    "click",
    "fit",
    "buzz",
    "monster",
    "club",
    "rest",
    "cam",
    "icu",
    "stream",
}

_proj_root = Path(__file__).resolve().parent.parent.parent.parent
_tld_cache_dir = str(_proj_root / "data" / "processed" / "urls" / ".tld_cache")

# Offline TLDExtract singleton: suffix_list_urls=() guarantees zero network egress
_offline_tld_extract = tldextract.TLDExtract(
    cache_dir=_tld_cache_dir,
    suffix_list_urls=(),
)


def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of character distribution in text."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_ip_host(hostname: str) -> bool:
    """Check whether a host string is a valid IPv4 or IPv6 address."""
    if not hostname:
        return False
    clean = hostname.strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            ins = prev[j + 1] + 1
            dels = curr[j] + 1
            subs = prev[j] + (c1 != c2)
            curr.append(min(ins, dels, subs))
        prev = curr
    return prev[-1]


# Official academic, research, and government top-level and second-level domains
EXEMPT_ACADEMIC_GOV_TLDS: set[str] = {
    "ac.in",
    "edu",
    "edu.in",
    "gov.in",
    "gov",
    "mil",
    "ac.uk",
    "gov.uk",
    "edu.au",
    "gov.au",
    "nic.in",
    "ernet.in",
    "res.in",
}


def is_exempt_academic_or_gov(tld: Optional[str] = None, hostname: Optional[str] = None) -> bool:
    """Return True if the domain suffix or hostname belongs to an authoritative academic, research, or government TLD."""
    clean_tld = (tld or "").strip().lower().lstrip(".")
    if clean_tld in EXEMPT_ACADEMIC_GOV_TLDS:
        return True
    if (
        clean_tld.startswith("ac.")
        or clean_tld.endswith(".ac")
        or clean_tld.startswith("edu.")
        or clean_tld.endswith(".edu")
        or clean_tld.startswith("gov.")
        or clean_tld.endswith(".gov")
    ):
        return True
    if hostname:
        clean_host = hostname.strip().lower()
        if any(clean_host.endswith(f".{suffix}") for suffix in EXEMPT_ACADEMIC_GOV_TLDS):
            return True
        if ".ac." in clean_host or ".edu." in clean_host or ".gov." in clean_host or ".nic." in clean_host:
            return True
        if clean_host.endswith(".edu") or clean_host.endswith(".gov") or clean_host.endswith(".mil"):
            return True
    return False


def check_brand_impersonation(
    registered_domain: str,
    subdomain: str,
    path: str,
    hostname: str,
    tld: str = "",
) -> Tuple[float, Optional[str], Optional[float], str]:
    """Check for brand impersonation or typosquatting using offline heuristics.

    Returns:
        (score, target_brand, similarity, description)
        score: 1.0 if brand impersonation detected, 0.0 otherwise.
    """
    clean_domain = registered_domain.lower().strip()
    clean_sub = subdomain.lower().strip()
    clean_path = path.lower().strip()
    clean_host = hostname.lower().strip()
    clean_tld = (tld or "").lower().strip().lstrip(".")

    # 0. Academic & Government TLD Exemption:
    # Domains under official academic, research, and government suffixes
    # (.ac.in, .edu, .gov.in, etc.) are strictly allocated by accredited registries
    # (e.g. ERNET India, Educause, NIC) and are excluded from commercial banking typosquatting heuristics.
    if is_exempt_academic_or_gov(tld=clean_tld, hostname=clean_host):
        return (
            0.0,
            None,
            None,
            f"Domain belongs to authoritative academic/government namespace (.{clean_tld or 'ac/gov'}), exempt from commercial typosquatting checks.",
        )

    # 1. Check exact match: if clean_domain is the brand itself, it is not impersonating
    for brand in TARGET_BRANDS:
        if clean_domain == brand:
            return 0.0, brand, 1.0, f"Registered domain matches official brand '{brand}'."

    # 2. Check Typosquatting and compound brand names in registered domain
    domain_parts = [p for p in re.split(r"[-_.]", clean_domain) if p]
    for brand in TARGET_BRANDS:
        # Check whole domain Levenshtein distance
        if len(clean_domain) >= 3 and len(brand) >= 4:
            dist = levenshtein_distance(clean_domain, brand)
            sim = 1.0 - (dist / max(len(clean_domain), len(brand)))
            # Require minimum 65% similarity and distance 1 for short words to prevent false positives (e.g., 'vit' vs 'citi')
            if (dist == 1 and sim >= 0.65) or (dist == 2 and sim >= 0.65 and min(len(clean_domain), len(brand)) >= 4):
                return (
                    1.0,
                    brand,
                    round(sim, 3),
                    f"Registered domain '{clean_domain}' appears to be a lookalike typosquat of brand '{brand}'.",
                )

        # Check compound domain parts (e.g. paypal-security, paypa1-update)
        for part in domain_parts:
            if part == brand:
                return (
                    1.0,
                    brand,
                    0.95,
                    f"Registered domain '{clean_domain}' incorporates brand name '{brand}'.",
                )
            if len(part) >= 3 and len(brand) >= 4:
                dist = levenshtein_distance(part, brand)
                sim = 1.0 - (dist / max(len(part), len(brand)))
                if (dist == 1 and sim >= 0.65) or (dist == 2 and sim >= 0.65 and min(len(part), len(brand)) >= 4):
                    return (
                        1.0,
                        brand,
                        round(sim, 3),
                        f"Domain token '{part}' appears to be a typosquat of brand '{brand}'.",
                    )

    # 3. Check brand name embedded in subdomain or path when registered domain is DIFFERENT
    for brand in TARGET_BRANDS:
        brand_in_sub = brand in clean_sub
        brand_in_path = brand in clean_path
        if brand_in_sub or brand_in_path:
            location = "subdomain" if brand_in_sub else "path"
            return (
                1.0,
                brand,
                0.9,
                f"Brand name '{brand}' embedded in {location} under unrelated registered domain '{clean_domain}'.",
            )

    return 0.0, None, None, "No brand impersonation detected by local heuristics."


def extract_url_feature_dict(raw_url: str) -> Dict[str, float]:
    """Extract 34 numerical features from a URL string.

    Never makes external network calls.
    Safe against empty input, malformed syntax, and Unicode.
    """
    url = (raw_url or "").strip()
    if not url:
        return {feat: 0.0 for feat in FEATURE_NAMES}

    # Normalize protocol for parser if missing
    target = url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target):
        target = f"http://{target}"

    try:
        parsed = urlparse(target)
    except Exception:
        # Fallback for severely broken syntax
        return {feat: 0.0 for feat in FEATURE_NAMES}

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = (parsed.scheme or "").lower()

    # TLD extraction (offline)
    try:
        extracted = _offline_tld_extract(target)
        subdomain = extracted.subdomain
        reg_domain = extracted.domain
        suffix = extracted.suffix
    except Exception:
        subdomain, reg_domain, suffix = "", "", ""

    # Character counts
    count_dots = float(url.count("."))
    count_hyphens = float(url.count("-"))
    count_underscores = float(url.count("_"))
    count_slashes = float(url.count("/"))
    count_question = float(url.count("?"))
    count_equal = float(url.count("="))
    count_at = float(url.count("@"))
    count_amp = float(url.count("&"))
    count_excl = float(url.count("!"))
    count_percent = float(url.count("%"))
    count_digits = float(sum(c.isdigit() for c in url))
    count_letters = float(sum(c.isalpha() for c in url))

    # Lengths and ratios
    url_len = float(len(url))
    host_len = float(len(hostname))
    path_len = float(len(path))
    query_len = float(len(query))

    ratio_digits_url = count_digits / max(url_len, 1.0)
    host_digits = float(sum(c.isdigit() for c in hostname))
    ratio_digits_hostname = host_digits / max(host_len, 1.0)

    # Subdomain depth
    subdomain_parts = [p for p in subdomain.split(".") if p] if subdomain else []
    count_subdomains = float(len(subdomain_parts))

    # IP host check
    has_ip = 1.0 if is_ip_host(hostname) else 0.0

    # Scheme
    is_https = 1.0 if scheme == "https" else 0.0
    is_http = 1.0 if scheme == "http" else 0.0

    # Ports
    has_non_standard_port = 0.0
    try:
        if parsed.port is not None and parsed.port not in (80, 443):
            has_non_standard_port = 1.0
    except (ValueError, Exception):
        # Malformed colon/port string in netloc
        has_non_standard_port = 1.0

    # Structural anomalies
    has_at_symbol = 1.0 if count_at > 0 else 0.0
    has_double_slash_path = 1.0 if "//" in path else 0.0

    # Query parameters
    try:
        query_params = parse_qs(query)
        count_query_parameters = float(len(query_params))
    except Exception:
        count_query_parameters = 0.0

    # Suspicious tokens in path, query, or subdomains
    search_space = f"{subdomain.lower()} {path.lower()} {query.lower()}"
    suspicious_token_count = 0.0
    for tok in SUSPICIOUS_TOKENS:
        if tok in search_space:
            suspicious_token_count += 1.0
    has_suspicious_token = 1.0 if suspicious_token_count > 0 else 0.0

    # Shannon entropy
    url_entropy = calculate_shannon_entropy(url)
    hostname_entropy = calculate_shannon_entropy(hostname)

    # Punycode / IDN
    has_punycode = 1.0 if "xn--" in hostname.lower() else 0.0

    # Brand impersonation heuristic
    brand_score, _, _, _ = check_brand_impersonation(reg_domain, subdomain, path, hostname, tld=suffix)

    # Suspicious TLD
    suspicious_tld = 1.0 if suffix.lower() in SUSPICIOUS_TLDS else 0.0

    # Consecutive hyphens in hostname
    consecutive_hyphens = 1.0 if "--" in hostname else 0.0

    features: Dict[str, float] = {
        "url_length": url_len,
        "hostname_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_underscores": count_underscores,
        "count_slashes": count_slashes,
        "count_question_marks": count_question,
        "count_equal_signs": count_equal,
        "count_at_symbols": count_at,
        "count_ampersands": count_amp,
        "count_exclamations": count_excl,
        "count_percent_signs": count_percent,
        "count_digits": count_digits,
        "count_letters": count_letters,
        "ratio_digits_url": round(ratio_digits_url, 4),
        "ratio_digits_hostname": round(ratio_digits_hostname, 4),
        "count_subdomains": count_subdomains,
        "has_ip_address": has_ip,
        "is_https": is_https,
        "is_http": is_http,
        "has_non_standard_port": has_non_standard_port,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_path": has_double_slash_path,
        "count_query_parameters": count_query_parameters,
        "suspicious_token_count": suspicious_token_count,
        "has_suspicious_token": has_suspicious_token,
        "url_entropy": round(url_entropy, 4),
        "hostname_entropy": round(hostname_entropy, 4),
        "has_punycode": has_punycode,
        "brand_impersonation_score": brand_score,
        "suspicious_tld": suspicious_tld,
        "consecutive_hyphens": consecutive_hyphens,
    }

    return features


def extract_url_feature_vector(raw_url: str) -> List[float]:
    """Extract numerical feature vector matching FEATURE_NAMES order exactly."""
    fdict = extract_url_feature_dict(raw_url)
    return [fdict[name] for name in FEATURE_NAMES]
