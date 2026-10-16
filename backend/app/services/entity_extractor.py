"""Entity extraction engine for FraudLens (Feature 4).

Extracts and validates indicators from message text:
- URLs (http/https and naked domains) with punctuation stripping and position offsets
- Phone numbers (domestic Indian and international formats)
- UPI IDs / payment handles (distinguished from normal email addresses)
- Email addresses and digital artifacts

Guarantees:
- message[start:end] == raw_text for all extracted entity spans
- Never executes or makes live network requests to extracted entities
- Avoids false positives from version numbers, dates, or ordinary punctuation
"""

import re
from typing import List, Optional, Set, Tuple
from backend.app.schemas.message import EntitySpan, ExtractedEntities


# Known Indian bank / payment service provider handles for UPI VPAs
UPI_PSP_HANDLES = {
    "upi",
    "okhdfcbank",
    "okaxis",
    "oksbi",
    "okicici",
    "paytm",
    "ybl",
    "axl",
    "ibl",
    "sbi",
    "icici",
    "hdfcbank",
    "axisbank",
    "kotak",
    "barodampay",
    "federal",
    "airtel",
    "amazonpay",
    "postbank",
    "indus",
    "citi",
    "pnb",
    "unionbank",
    "idfcbank",
    "freecharge",
    "apl",
    "waaxis",
    "wahdfc",
    "wasbi",
    "waicici",
}

# Common top-level domains for naked domain recognition
KNOWN_TLDS = (
    "com", "org", "net", "edu", "gov", "mil", "int",
    "in", "co.in", "net.in", "org.in", "gen.in",
    "uk", "co.uk", "us", "io", "ai", "co", "me", "info", "biz",
    "xyz", "online", "site", "top", "club", "live", "vip", "app", "dev",
    "tech", "store", "shop", "icu", "link", "click", "cloud",
)

# Regex to identify URLs with scheme
SCHEME_URL_REGEX = re.compile(
    r"\bhttps?://[^\s<>\"']+",
    re.IGNORECASE,
)

# Regex for naked domains (e.g. www.example.com, sbi-kyc.com/login, bit.ly/3xyz)
NAKED_DOMAIN_REGEX = re.compile(
    r"\b(?:www\.)?[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)

# Email address regex
EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    re.IGNORECASE,
)

# UPI handle regex
UPI_HANDLE_REGEX = re.compile(
    r"\b([a-zA-Z0-9.\-_]{2,256})@([a-zA-Z]{2,64})\b",
    re.IGNORECASE,
)

# Phone number patterns:
# 1. International with country code: +91 98765 43210, +1-800-555-0199, +44 20 7946 0958
# 2. Indian 10-digit mobile: 9876543210, 98765 43210, 98765-43210, 09876543210
# 3. Formatted with parentheses: (800) 555-0199
PHONE_REGEX = re.compile(
    r"(?:(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,5}[-.\s]?\d{4,5})",
    re.IGNORECASE,
)


def _strip_surrounding_punctuation(text: str, start: int, end: int) -> Tuple[str, int, int]:
    """Clean trailing/leading punctuation belonging to surrounding prose rather than URL."""
    val = text[start:end]
    trailing_strip = ".,;:!?'\")>]"
    leading_strip = "('\"<["

    while val and val[-1] in trailing_strip:
        end -= 1
        val = text[start:end]

    while val and val[0] in leading_strip:
        start += 1
        val = text[start:end]

    return val, start, end


class EntityExtractor:
    """Extracts verifiable digital entities and indicators from message text."""

    def extract(self, text: str) -> ExtractedEntities:
        """Extract URLs, phone numbers, UPI handles, and indicators with exact character spans."""
        if not text or not text.strip():
            return ExtractedEntities()

        spans: List[EntitySpan] = []
        urls: List[str] = []
        phones: List[str] = []
        upis: List[str] = []
        indicators: List[str] = []

        seen_ranges: List[Tuple[int, int]] = []

        def is_overlapping(s: int, e: int) -> bool:
            for ex_s, ex_e in seen_ranges:
                if max(s, ex_s) < min(e, ex_e):
                    return True
            return False

        # -------------------------------------------------------------
        # 1. Identify Email Addresses (prevents misclassifying as UPI / URLs)
        # -------------------------------------------------------------
        email_spans: List[Tuple[int, int]] = []
        for match in EMAIL_REGEX.finditer(text):
            s, e = match.start(), match.end()
            email_spans.append((s, e))
            seen_ranges.append((s, e))
            val = text[s:e]
            indicators.append(f"Email: {val}")
            spans.append(
                EntitySpan(
                    entity_type="INDICATOR",
                    value=val,
                    raw_text=val,
                    start=s,
                    end=e,
                )
            )

        # -------------------------------------------------------------
        # 2. URLs with Scheme (http://, https://)
        # -------------------------------------------------------------
        for match in SCHEME_URL_REGEX.finditer(text):
            s, e = match.start(), match.end()
            val, s, e = _strip_surrounding_punctuation(text, s, e)
            if not val or is_overlapping(s, e):
                continue

            seen_ranges.append((s, e))
            urls.append(val)
            spans.append(
                EntitySpan(
                    entity_type="URL",
                    value=val,
                    raw_text=val,
                    start=s,
                    end=e,
                )
            )

        # -------------------------------------------------------------
        # 3. Naked Domains (e.g. www.site.com, kyc-sbi.com/verify)
        # -------------------------------------------------------------
        for match in NAKED_DOMAIN_REGEX.finditer(text):
            s, e = match.start(), match.end()
            val, s, e = _strip_surrounding_punctuation(text, s, e)
            if not val or is_overlapping(s, e):
                continue

            # Exclude version strings like 1.0.0 or 2.5
            if re.match(r"^\d+(?:\.\d+)+$", val):
                continue

            # Verify it has a valid domain structure or known TLD
            domain_part = val.split("/")[0].lower()
            parts = domain_part.split(".")
            if len(parts) >= 2 and (parts[-1] in KNOWN_TLDS or len(parts[-1]) >= 2):
                # Ensure the domain part is not solely numbers
                if not all(p.isdigit() for p in parts):
                    seen_ranges.append((s, e))
                    urls.append(val)
                    spans.append(
                        EntitySpan(
                            entity_type="URL",
                            value=val,
                            raw_text=val,
                            start=s,
                            end=e,
                        )
                    )

        # -------------------------------------------------------------
        # 4. UPI Handles / VPAs (username@bank)
        # -------------------------------------------------------------
        for match in UPI_HANDLE_REGEX.finditer(text):
            s, e = match.start(), match.end()
            if is_overlapping(s, e):
                continue

            user_part, handle_part = match.group(1), match.group(2).lower()
            val = text[s:e]

            # If handle matches a known UPI PSP handle, or user part is a phone number, classify as UPI
            if handle_part in UPI_PSP_HANDLES or re.match(r"^\d{10}$", user_part):
                seen_ranges.append((s, e))
                upis.append(val)
                spans.append(
                    EntitySpan(
                        entity_type="UPI",
                        value=val,
                        raw_text=val,
                        start=s,
                        end=e,
                    )
                )

        # -------------------------------------------------------------
        # 5. Phone Numbers
        # -------------------------------------------------------------
        for match in PHONE_REGEX.finditer(text):
            s, e = match.start(), match.end()
            val, s, e = _strip_surrounding_punctuation(text, s, e)
            if not val or is_overlapping(s, e):
                continue

            # Digits-only count
            digits = re.sub(r"\D", "", val)
            total_digits = len(digits)

            # Valid phone numbers require 10 to 15 digits (or 7 for local landlines)
            if 10 <= total_digits <= 15:
                # Avoid matching timestamps or currency sequences like 20261011
                if not re.match(r"^(?:19|20)\d{2}", digits) or total_digits > 8:
                    seen_ranges.append((s, e))
                    phones.append(val)
                    spans.append(
                        EntitySpan(
                            entity_type="PHONE",
                            value=val,
                            raw_text=val,
                            start=s,
                            end=e,
                        )
                    )

        # Sort spans by character offset start position
        spans.sort(key=lambda sp: sp.start)

        return ExtractedEntities(
            urls=list(dict.fromkeys(urls)),
            phone_numbers=list(dict.fromkeys(phones)),
            upi_ids=list(dict.fromkeys(upis)),
            indicators=list(dict.fromkeys(indicators)),
            spans=spans,
        )


_global_extractor: Optional[EntityExtractor] = None


def get_entity_extractor() -> EntityExtractor:
    """Singleton provider for EntityExtractor."""
    global _global_extractor
    if _global_extractor is None:
        _global_extractor = EntityExtractor()
    return _global_extractor
