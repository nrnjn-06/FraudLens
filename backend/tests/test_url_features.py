"""Unit tests for URL feature extraction and local heuristics."""

import socket
import pytest

from backend.app.services.url_features import (
    FEATURE_NAMES,
    calculate_shannon_entropy,
    check_brand_impersonation,
    extract_url_feature_dict,
    extract_url_feature_vector,
    is_ip_host,
    levenshtein_distance,
)


def test_feature_names_count_and_order():
    """Verify exactly 34 deterministic features in canonical order."""
    assert len(FEATURE_NAMES) == 34
    assert len(set(FEATURE_NAMES)) == 34
    assert FEATURE_NAMES[0] == "url_length"
    assert FEATURE_NAMES[-1] == "consecutive_hyphens"
    # Ensure no dataset targets or leaky string metadata
    assert "label" not in FEATURE_NAMES
    assert "is_phishing" not in FEATURE_NAMES
    assert "registered_domain" not in FEATURE_NAMES
    assert "domain" not in FEATURE_NAMES


def test_ordinary_legitimate_url_features():
    """Verify feature values for an ordinary legitimate URL."""
    url = "https://www.example.com/about/team"
    fdict = extract_url_feature_dict(url)
    assert len(fdict) == 34
    assert fdict["url_length"] == len(url)
    assert fdict["hostname_length"] == len("www.example.com")
    assert fdict["is_https"] == 1.0
    assert fdict["is_http"] == 0.0
    assert fdict["has_ip_address"] == 0.0
    assert fdict["count_dots"] == 2.0
    assert fdict["count_slashes"] == 4.0
    assert fdict["count_subdomains"] == 1.0  # 'www'
    assert fdict["brand_impersonation_score"] == 0.0


def test_ip_address_host_detection():
    """Verify IP address hosts (IPv4 & IPv6) are correctly detected and parsed."""
    ipv4_url = "http://192.168.1.100:8080/admin/login.php"
    fdict_v4 = extract_url_feature_dict(ipv4_url)
    assert fdict_v4["has_ip_address"] == 1.0
    assert fdict_v4["has_non_standard_port"] == 1.0
    assert fdict_v4["is_http"] == 1.0
    assert fdict_v4["is_https"] == 0.0

    assert is_ip_host("192.168.1.1") is True
    assert is_ip_host("10.0.0.254") is True
    assert is_ip_host("999.999.999.999") is False
    assert is_ip_host("example.com") is False


def test_missing_scheme_handling():
    """Verify URLs without http/https schemes are handled gracefully."""
    naked_url = "sub.domain.org/path/resource?user=1"
    fdict = extract_url_feature_dict(naked_url)
    assert fdict["url_length"] == len(naked_url)
    assert fdict["hostname_length"] > 0
    assert fdict["count_query_parameters"] == 1.0
    assert fdict["has_ip_address"] == 0.0


def test_unicode_and_punycode_handling():
    """Verify Internationalized Domain Names (IDN) and punycode domains."""
    puny_url = "https://xn--e1afmkfd.xn--p1ai/test"
    fdict = extract_url_feature_dict(puny_url)
    assert fdict["has_punycode"] == 1.0

    unicode_url = "https://москва.рф/новости"
    fdict_uni = extract_url_feature_dict(unicode_url)
    assert fdict_uni["url_length"] > 0
    assert fdict_uni["hostname_length"] > 0


def test_malformed_and_empty_input_handling():
    """Verify empty or severely malformed URLs return safe zero vectors without crashing."""
    fdict_empty = extract_url_feature_dict("")
    assert len(fdict_empty) == 34
    assert all(val == 0.0 for val in fdict_empty.values())

    vec_empty = extract_url_feature_vector("   ")
    assert len(vec_empty) == 34
    assert all(val == 0.0 for val in vec_empty)

    fdict_malformed = extract_url_feature_dict(":::bad_url:::")
    assert len(fdict_malformed) == 34


def test_suspicious_tokens_and_structural_anomalies():
    """Verify detection of sensitive keywords, '@' symbol, and double slashes."""
    suspicious_url = "http://victim.com:8080/secure/login/verify//redirect?account=1#ref"
    fdict = extract_url_feature_dict(suspicious_url)
    assert fdict["suspicious_token_count"] >= 3.0  # 'secure', 'login', 'verify', 'account'
    assert fdict["has_suspicious_token"] == 1.0
    assert fdict["has_double_slash_path"] == 1.0
    assert fdict["has_non_standard_port"] == 1.0

    at_url = "http://fake-site.com@actual-site.com/test"
    fdict_at = extract_url_feature_dict(at_url)
    assert fdict_at["has_at_symbol"] == 1.0


def test_shannon_entropy_calculation():
    """Verify Shannon entropy computation properties."""
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("aaaa") == 0.0
    assert calculate_shannon_entropy("abab") == 1.0
    # Higher diversity yields higher entropy
    h_low = calculate_shannon_entropy("abc")
    h_high = calculate_shannon_entropy("abcdefghijk123456789!@#$%")
    assert h_high > h_low


def test_levenshtein_distance_metric():
    """Verify Levenshtein distance calculations."""
    assert levenshtein_distance("", "") == 0
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("google", "g00gle") == 2
    assert levenshtein_distance("apple", "banana") == 5


def test_brand_impersonation_heuristics():
    """Verify brand spoofing and lookalike heuristics."""
    # Official brand domain is clean
    score, brand, sim, desc = check_brand_impersonation("paypal", "www", "/", "www.paypal.com")
    assert score == 0.0
    assert brand == "paypal"

    # Typosquat in registered domain
    score, brand, sim, desc = check_brand_impersonation("paypa1", "www", "/", "www.paypa1.com")
    assert score == 1.0
    assert brand == "paypal"
    assert sim >= 0.8

    # Compound brand in registered domain
    score, brand, sim, desc = check_brand_impersonation("paypal-security", "", "/login", "paypal-security.com")
    assert score == 1.0
    assert brand == "paypal"

    # Brand embedded in subdomain under unrelated domain
    score, brand, sim, desc = check_brand_impersonation("evil-domain", "paypal.verify", "/auth", "paypal.verify.evil-domain.com")
    assert score == 1.0
    assert brand == "paypal"

    # Unrelated benign domain
    score, brand, sim, desc = check_brand_impersonation("example", "sub", "/page", "sub.example.com")
    assert score == 0.0
    assert brand is None


def test_feature_extraction_zero_network_calls(monkeypatch):
    """Verify feature extraction performs strictly zero network requests."""
    def guarded_socket(*args, **kwargs):
        raise RuntimeError("Network egress attempted during URL feature extraction!")

    monkeypatch.setattr(socket, "socket", guarded_socket)

    # Must extract cleanly without socket activity
    fdict = extract_url_feature_dict("https://paypal.com.account-verification-auth.xyz/login.php?id=99")
    assert fdict["url_length"] > 0
    assert fdict["brand_impersonation_score"] == 1.0


def test_academic_and_gov_tld_exemption():
    """Verify official academic and government domains (.ac.in, .edu, .gov.in) are exempt from brand typosquatting."""
    # vit.ac.in (ac.in namespace) should NOT trigger 'citi' typosquatting
    score, brand, sim, desc = check_brand_impersonation("vit", "vtop", "/", "vtop.vit.ac.in", tld="ac.in")
    assert score == 0.0
    assert brand is None
    assert "academic" in desc.lower() or "exempt" in desc.lower()

    # mit.edu (.edu namespace)
    score, brand, sim, desc = check_brand_impersonation("mit", "www", "/", "www.mit.edu", tld="edu")
    assert score == 0.0
    assert brand is None

    # portal.gov.in (.gov.in namespace)
    score, brand, sim, desc = check_brand_impersonation("portal", "sbi", "/login", "sbi.portal.gov.in", tld="gov.in")
    assert score == 0.0
    assert brand is None

