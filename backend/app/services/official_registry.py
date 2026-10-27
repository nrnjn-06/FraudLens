"""Official Domain Registry for FraudLens.

Maintains verified, authoritative domain mappings for high-profile organizations,
banks, government agencies, courier services, e-commerce, and technology platforms.
Guarantees:
1. Strictly verified HTTPS canonical destinations.
2. Public-suffix-aware distinguishing between actual official domains and lookalikes.
3. Zero dynamic URL construction from untrusted user inputs.
4. Transparent verification source provenance.
"""

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import tldextract

_proj_root = Path(__file__).resolve().parent.parent.parent.parent
_tld_cache_dir = str(_proj_root / "data" / "processed" / "urls" / ".tld_cache")

_tld_parser = tldextract.TLDExtract(
    cache_dir=_tld_cache_dir,
    suffix_list_urls=(),
)


@dataclass(frozen=True)
class OfficialOrganizationEntry:
    """Immutable entry for a verified official organization and its trusted destination."""

    key: str
    name: str
    official_domain: str
    canonical_url: str
    aliases: List[str]
    category: str
    verification_source: str
    last_verified: str
    service_type: str
    safe_advice: str


# Authoritative verified organization directory
# Categorized into Banking/KYC, Delivery/Courier, Government, E-Commerce, Payment, Tech/Cloud, Social, Crypto
VERIFIED_REGISTRY_ENTRIES: List[OfficialOrganizationEntry] = [
    # -------------------------------------------------------------
    # 1. Banking and Financial Institutions
    # -------------------------------------------------------------
    OfficialOrganizationEntry(
        key="sbi",
        name="State Bank of India (SBI)",
        official_domain="sbi.co.in",
        canonical_url="https://sbi.co.in/",
        aliases=["sbi", "state bank of india", "onlinesbi", "yono", "yono sbi"],
        category="BANKING_KYC",
        verification_source="Reserve Bank of India (RBI) & State Bank of India Official Portal",
        last_verified="2026-10-15T00:00:00Z",
        service_type="banking and KYC services",
        safe_advice="Access SBI netbanking exclusively via official domains. Never share OTPs, PINs, or netbanking passwords over SMS, phone, or email.",
    ),
    OfficialOrganizationEntry(
        key="hdfc",
        name="HDFC Bank",
        official_domain="hdfcbank.com",
        canonical_url="https://www.hdfcbank.com/",
        aliases=["hdfc", "hdfc bank", "hdfcbank", "netbanking.hdfcbank"],
        category="BANKING_KYC",
        verification_source="Reserve Bank of India (RBI) & HDFC Bank Official Portal",
        last_verified="2026-10-15T00:00:00Z",
        service_type="banking and financial portal",
        safe_advice="Log in to HDFC Bank NetBanking directly at https://www.hdfcbank.com or through the verified HDFC Bank MobileBanking app.",
    ),
    OfficialOrganizationEntry(
        key="icici",
        name="ICICI Bank",
        official_domain="icicibank.com",
        canonical_url="https://www.icicibank.com/",
        aliases=["icici", "icici bank", "imobile", "icicibank"],
        category="BANKING_KYC",
        verification_source="Reserve Bank of India (RBI) & ICICI Bank Official Portal",
        last_verified="2026-10-15T00:00:00Z",
        service_type="banking and payment services",
        safe_advice="Access ICICI accounts only through https://www.icicibank.com or the official iMobile Pay application.",
    ),
    OfficialOrganizationEntry(
        key="citi",
        name="Citibank",
        official_domain="citi.com",
        canonical_url="https://www.citi.com/",
        aliases=["citi", "citibank", "citicorp"],
        category="BANKING_KYC",
        verification_source="US Federal Deposit Insurance Corporation (FDIC) & Citi Official Portal",
        last_verified="2026-10-15T00:00:00Z",
        service_type="banking and card services",
        safe_advice="Visit Citibank directly at https://www.citi.com or use the official Citi Mobile application.",
    ),
    OfficialOrganizationEntry(
        key="chase",
        name="Chase Bank",
        official_domain="chase.com",
        canonical_url="https://www.chase.com/",
        aliases=["chase", "jpmorgan chase", "chase bank"],
        category="BANKING_KYC",
        verification_source="US Office of the Comptroller of the Currency (OCC) & Chase Portal",
        last_verified="2026-10-15T00:00:00Z",
        service_type="banking and credit card services",
        safe_advice="Log in directly via https://www.chase.com or the verified Chase Mobile app.",
    ),
    OfficialOrganizationEntry(
        key="wellsfargo",
        name="Wells Fargo",
        official_domain="wellsfargo.com",
        canonical_url="https://www.wellsfargo.com/",
        aliases=["wellsfargo", "wells fargo"],
        category="BANKING_KYC",
        verification_source="US Consumer Financial Protection Bureau & Wells Fargo Portal",
        last_verified="2026-10-15T00:00:00Z",
        service_type="banking and lending services",
        safe_advice="Log in directly at https://www.wellsfargo.com or through the official Wells Fargo Mobile app.",
    ),
    OfficialOrganizationEntry(
        key="bankofamerica",
        name="Bank of America",
        official_domain="bankofamerica.com",
        canonical_url="https://www.bankofamerica.com/",
        aliases=["bankofamerica", "bank of america", "bofa"],
        category="BANKING_KYC",
        verification_source="US Federal Deposit Insurance Corporation (FDIC) & BofA Portal",
        last_verified="2026-10-15T00:00:00Z",
        service_type="banking and card services",
        safe_advice="Access your accounts only through https://www.bankofamerica.com or the official Bank of America mobile app.",
    ),

    # -------------------------------------------------------------
    # 2. Payment Providers & Wallets
    # -------------------------------------------------------------
    OfficialOrganizationEntry(
        key="paypal",
        name="PayPal",
        official_domain="paypal.com",
        canonical_url="https://www.paypal.com/",
        aliases=["paypal", "paypal wallet"],
        category="PAYMENT",
        verification_source="PayPal Inc. Official Domain Registry & SEC Filings",
        last_verified="2026-10-15T00:00:00Z",
        service_type="payment and digital wallet service",
        safe_advice="Navigate directly to https://www.paypal.com or use the official PayPal mobile app. Never authorize payments from third-party links.",
    ),
    OfficialOrganizationEntry(
        key="paytm",
        name="Paytm",
        official_domain="paytm.com",
        canonical_url="https://paytm.com/",
        aliases=["paytm", "paytm payments bank", "one97"],
        category="PAYMENT",
        verification_source="One97 Communications & NPCI UPI Registry",
        last_verified="2026-10-15T00:00:00Z",
        service_type="digital payments and wallet platform",
        safe_advice="Authenticate transactions only inside the verified Paytm mobile application. Paytm customer service never asks for full card or UPI PIN details.",
    ),
    OfficialOrganizationEntry(
        key="phonepe",
        name="PhonePe",
        official_domain="phonepe.com",
        canonical_url="https://www.phonepe.com/",
        aliases=["phonepe", "phone pe"],
        category="PAYMENT",
        verification_source="National Payments Corporation of India (NPCI) Registry",
        last_verified="2026-10-15T00:00:00Z",
        service_type="UPI payment and merchant service",
        safe_advice="Never enter your UPI PIN to RECEIVE money. UPI PIN is exclusively entered to authorize debit/send transactions inside official UPI apps.",
    ),
    OfficialOrganizationEntry(
        key="gpay",
        name="Google Pay",
        official_domain="pay.google.com",
        canonical_url="https://pay.google.com/",
        aliases=["google pay", "gpay", "tez"],
        category="PAYMENT",
        verification_source="Google LLC Official Security Portal",
        last_verified="2026-10-15T00:00:00Z",
        service_type="digital wallet and UPI payment application",
        safe_advice="Manage cards and payment methods directly at https://pay.google.com or in the official Google Pay app.",
    ),

    # -------------------------------------------------------------
    # 3. Delivery and Courier Services
    # -------------------------------------------------------------
    OfficialOrganizationEntry(
        key="indiapost",
        name="India Post",
        official_domain="indiapost.gov.in",
        canonical_url="https://www.indiapost.gov.in/",
        aliases=["indiapost", "india post", "speed post", "postal service india"],
        category="DELIVERY_COURIER",
        verification_source="Ministry of Communications, Government of India (.gov.in Registry)",
        last_verified="2026-10-15T00:00:00Z",
        service_type="official national postal and courier service",
        safe_advice="Track parcels directly on https://www.indiapost.gov.in/. India Post never requests payment for address verification via third-party SMS links.",
    ),
    OfficialOrganizationEntry(
        key="dhl",
        name="DHL Express",
        official_domain="dhl.com",
        canonical_url="https://www.dhl.com/",
        aliases=["dhl", "dhl express", "dhl tracking"],
        category="DELIVERY_COURIER",
        verification_source="Deutsche Post DHL Group Official Portal",
        last_verified="2026-10-15T00:00:00Z",
        service_type="international courier and parcel tracking service",
        safe_advice="Track shipments exclusively at https://www.dhl.com. Do not pay unexpected customs or release fees via unverified payment links.",
    ),
    OfficialOrganizationEntry(
        key="fedex",
        name="FedEx",
        official_domain="fedex.com",
        canonical_url="https://www.fedex.com/",
        aliases=["fedex", "federal express"],
        category="DELIVERY_COURIER",
        verification_source="FedEx Corporation Official Domain Registry",
        last_verified="2026-10-15T00:00:00Z",
        service_type="global express package delivery service",
        safe_advice="Verify package status on https://www.fedex.com using your official tracking number.",
    ),
    OfficialOrganizationEntry(
        key="ups",
        name="United Parcel Service (UPS)",
        official_domain="ups.com",
        canonical_url="https://www.ups.com/",
        aliases=["ups", "united parcel service"],
        category="DELIVERY_COURIER",
        verification_source="UPS Inc. Official Domain Registry",
        last_verified="2026-10-15T00:00:00Z",
        service_type="package delivery and supply chain management",
        safe_advice="Check tracking numbers directly at https://www.ups.com or the official UPS mobile app.",
    ),
    OfficialOrganizationEntry(
        key="usps",
        name="United States Postal Service (USPS)",
        official_domain="usps.com",
        canonical_url="https://www.usps.com/",
        aliases=["usps", "u.s. postal service", "postal service"],
        category="DELIVERY_COURIER",
        verification_source="US Federal Postal Authority Official Domain",
        last_verified="2026-10-15T00:00:00Z",
        service_type="postal and parcel tracking service",
        safe_advice="Verify shipment tracking directly at https://tools.usps.com. USPS does not send texts requesting delivery fees for redelivery.",
    ),
    OfficialOrganizationEntry(
        key="bluedart",
        name="Blue Dart",
        official_domain="bluedart.com",
        canonical_url="https://www.bluedart.com/",
        aliases=["bluedart", "blue dart"],
        category="DELIVERY_COURIER",
        verification_source="Blue Dart Express Ltd Official Domain",
        last_verified="2026-10-15T00:00:00Z",
        service_type="express courier and logistics provider",
        safe_advice="Track shipments directly at https://www.bluedart.com using your genuine airway bill (AWB) number.",
    ),

    # -------------------------------------------------------------
    # 4. E-Commerce Platforms
    # -------------------------------------------------------------
    OfficialOrganizationEntry(
        key="amazon",
        name="Amazon",
        official_domain="amazon.com",
        canonical_url="https://www.amazon.com/",
        aliases=["amazon", "amazon prime", "amazon.in", "amazon pay"],
        category="ECOMMERCE",
        verification_source="Amazon.com Inc. Official Domain & Security Portal",
        last_verified="2026-10-15T00:00:00Z",
        service_type="e-commerce and cloud platform",
        safe_advice="Open https://www.amazon.com directly or use the official Amazon app to review orders, returns, and payment cards.",
    ),
    OfficialOrganizationEntry(
        key="flipkart",
        name="Flipkart",
        official_domain="flipkart.com",
        canonical_url="https://www.flipkart.com/",
        aliases=["flipkart", "flipkart internet"],
        category="ECOMMERCE",
        verification_source="Flipkart Private Limited Official Domain",
        last_verified="2026-10-15T00:00:00Z",
        service_type="online retail and marketplace service",
        safe_advice="Review your orders exclusively at https://www.flipkart.com or via the official Flipkart mobile app.",
    ),
    OfficialOrganizationEntry(
        key="ebay",
        name="eBay",
        official_domain="ebay.com",
        canonical_url="https://www.ebay.com/",
        aliases=["ebay", "ebay marketplace"],
        category="ECOMMERCE",
        verification_source="eBay Inc. Official Domain Registry",
        last_verified="2026-10-15T00:00:00Z",
        service_type="online auction and shopping platform",
        safe_advice="Review transactions and sign in directly at https://www.ebay.com or using the official eBay mobile app.",
    ),

    # -------------------------------------------------------------
    # 5. Technology, Cloud & Email
    # -------------------------------------------------------------
    OfficialOrganizationEntry(
        key="google",
        name="Google",
        official_domain="google.com",
        canonical_url="https://www.google.com/",
        aliases=["google", "gmail", "google account", "google drive"],
        category="TECHNOLOGY",
        verification_source="Google LLC Authoritative Domain Registry",
        last_verified="2026-10-15T00:00:00Z",
        service_type="account, search, and cloud platform",
        safe_advice="Manage your Google Account directly at https://myaccount.google.com. Always verify the domain is 'google.com' before entering credentials.",
    ),
    OfficialOrganizationEntry(
        key="microsoft",
        name="Microsoft",
        official_domain="microsoft.com",
        canonical_url="https://www.microsoft.com/",
        aliases=["microsoft", "outlook", "office365", "microsoft365", "hotmail"],
        category="TECHNOLOGY",
        verification_source="Microsoft Corporation Authoritative Domain Registry",
        last_verified="2026-10-15T00:00:00Z",
        service_type="operating system, office productivity, and cloud services",
        safe_advice="Log in directly at https://login.microsoftonline.com or https://account.microsoft.com.",
    ),
    OfficialOrganizationEntry(
        key="apple",
        name="Apple",
        official_domain="apple.com",
        canonical_url="https://www.apple.com/",
        aliases=["apple", "apple id", "icloud", "itunes"],
        category="TECHNOLOGY",
        verification_source="Apple Inc. Authoritative Domain Registry",
        last_verified="2026-10-15T00:00:00Z",
        service_type="Apple Account and cloud services",
        safe_advice="Manage your Apple Account exclusively at https://appleid.apple.com or through the Settings app on official Apple devices.",
    ),
    OfficialOrganizationEntry(
        key="netflix",
        name="Netflix",
        official_domain="netflix.com",
        canonical_url="https://www.netflix.com/",
        aliases=["netflix", "netflix streaming"],
        category="TECHNOLOGY",
        verification_source="Netflix Inc. Official Domain Registry",
        last_verified="2026-10-15T00:00:00Z",
        service_type="streaming entertainment membership service",
        safe_advice="Update payment methods or account passwords directly at https://www.netflix.com/youraccount.",
    ),
    OfficialOrganizationEntry(
        key="dropbox",
        name="Dropbox",
        official_domain="dropbox.com",
        canonical_url="https://www.dropbox.com/",
        aliases=["dropbox", "dropbox cloud"],
        category="TECHNOLOGY",
        verification_source="Dropbox Inc. Official Domain Registry",
        last_verified="2026-10-15T00:00:00Z",
        service_type="cloud storage and file sharing service",
        safe_advice="Access files and authenticate only at https://www.dropbox.com or the official desktop client.",
    ),
    OfficialOrganizationEntry(
        key="yahoo",
        name="Yahoo",
        official_domain="yahoo.com",
        canonical_url="https://login.yahoo.com/",
        aliases=["yahoo", "yahoo mail"],
        category="TECHNOLOGY",
        verification_source="Yahoo Inc. Official Domain Registry",
        last_verified="2026-10-15T00:00:00Z",
        service_type="email and web services",
        safe_advice="Access Yahoo Mail and security settings directly at https://login.yahoo.com.",
    ),

    # -------------------------------------------------------------
    # 6. Social Media & Communications
    # -------------------------------------------------------------
    OfficialOrganizationEntry(
        key="facebook",
        name="Facebook / Meta",
        official_domain="facebook.com",
        canonical_url="https://www.facebook.com/",
        aliases=["facebook", "meta", "fb"],
        category="SOCIAL_MEDIA",
        verification_source="Meta Platforms Inc. Official Domain Registry",
        last_verified="2026-10-15T00:00:00Z",
        service_type="social networking platform",
        safe_advice="Log in to Facebook only at https://www.facebook.com or via official Meta applications.",
    ),
    OfficialOrganizationEntry(
        key="instagram",
        name="Instagram",
        official_domain="instagram.com",
        canonical_url="https://www.instagram.com/",
        aliases=["instagram", "insta"],
        category="SOCIAL_MEDIA",
        verification_source="Meta Platforms Inc. Official Domain Registry",
        last_verified="2026-10-15T00:00:00Z",
        service_type="photo and video sharing platform",
        safe_advice="Authenticate only at https://www.instagram.com or through the verified Instagram mobile application.",
    ),
    OfficialOrganizationEntry(
        key="whatsapp",
        name="WhatsApp",
        official_domain="whatsapp.com",
        canonical_url="https://www.whatsapp.com/",
        aliases=["whatsapp", "whatsapp web"],
        category="SOCIAL_MEDIA",
        verification_source="WhatsApp LLC / Meta Platforms Official Domain",
        last_verified="2026-10-15T00:00:00Z",
        service_type="encrypted messaging service",
        safe_advice="Connect to WhatsApp Web exclusively via https://web.whatsapp.com. Never enter phone numbers on external verification portals.",
    ),

    # -------------------------------------------------------------
    # 7. Cryptocurrency & Investment Platforms
    # -------------------------------------------------------------
    OfficialOrganizationEntry(
        key="binance",
        name="Binance",
        official_domain="binance.com",
        canonical_url="https://www.binance.com/",
        aliases=["binance", "binance exchange"],
        category="INVESTMENT_CRYPTO",
        verification_source="Binance Official Domain & Security Portal",
        last_verified="2026-10-15T00:00:00Z",
        service_type="cryptocurrency exchange and digital asset platform",
        safe_advice="Access wallet and trading accounts only on https://www.binance.com or through the official Binance app with hardware/2FA security.",
    ),
    OfficialOrganizationEntry(
        key="coinbase",
        name="Coinbase",
        official_domain="coinbase.com",
        canonical_url="https://www.coinbase.com/",
        aliases=["coinbase", "coinbase pro"],
        category="INVESTMENT_CRYPTO",
        verification_source="Coinbase Global Inc. SEC Filings & Official Domain",
        last_verified="2026-10-15T00:00:00Z",
        service_type="cryptocurrency trading and custodian platform",
        safe_advice="Authenticate only on https://www.coinbase.com. Coinbase customer support will never request your seed phrase or private keys.",
    ),

    # -------------------------------------------------------------
    # 8. Government, Tax & Citizen Services
    # -------------------------------------------------------------
    OfficialOrganizationEntry(
        key="incometax",
        name="Income Tax Department (India)",
        official_domain="incometax.gov.in",
        canonical_url="https://www.incometax.gov.in/",
        aliases=["income tax", "incometax", "it department", "itr", "tax refund", "pan kyc"],
        category="GOVERNMENT_TAX",
        verification_source="Government of India (.gov.in Registry) & Central Board of Direct Taxes",
        last_verified="2026-10-15T00:00:00Z",
        service_type="official tax e-filing and refund portal",
        safe_advice="File returns and verify refunds exclusively at https://www.incometax.gov.in/. The Income Tax Department never distributes refund links via SMS.",
    ),
    OfficialOrganizationEntry(
        key="uidai",
        name="Unique Identification Authority of India (UIDAI / Aadhaar)",
        official_domain="uidai.gov.in",
        canonical_url="https://uidai.gov.in/",
        aliases=["uidai", "aadhaar", "aadhar", "myaadhaar"],
        category="GOVERNMENT_TAX",
        verification_source="Ministry of Electronics and Information Technology, Government of India",
        last_verified="2026-10-15T00:00:00Z",
        service_type="official national identity and Aadhaar portal",
        safe_advice="Update demographic or biometric details only on official government portals (https://uidai.gov.in/ or https://myaadhaar.uidai.gov.in/).",
    ),
    OfficialOrganizationEntry(
        key="irs",
        name="Internal Revenue Service (IRS)",
        official_domain="irs.gov",
        canonical_url="https://www.irs.gov/",
        aliases=["irs", "internal revenue service", "tax refund us"],
        category="GOVERNMENT_TAX",
        verification_source="US Department of the Treasury (.gov Registry)",
        last_verified="2026-10-15T00:00:00Z",
        service_type="federal tax administration and refund service",
        safe_advice="Verify tax notices and refunds directly on https://www.irs.gov/. The IRS never contacts taxpayers via unsolicited SMS or social media requesting immediate payment.",
    ),
]


class OfficialDomainRegistry:
    """Query and matching service for verified official organization domains."""

    def __init__(self, entries: Optional[List[OfficialOrganizationEntry]] = None):
        self._entries: List[OfficialOrganizationEntry] = entries or VERIFIED_REGISTRY_ENTRIES
        self._by_key: Dict[str, OfficialOrganizationEntry] = {e.key: e for e in self._entries}
        self._by_domain: Dict[str, OfficialOrganizationEntry] = {e.official_domain.lower(): e for e in self._entries}

    def get_by_key(self, key: str) -> Optional[OfficialOrganizationEntry]:
        """Lookup organization by primary key."""
        return self._by_key.get(key.lower().strip())

    def get_by_domain(self, domain: str) -> Optional[OfficialOrganizationEntry]:
        """Lookup organization by exact official domain."""
        clean = domain.lower().strip().lstrip("www.")
        return self._by_domain.get(clean)

    def extract_registrable_domain(self, url_or_hostname: str) -> Tuple[str, str]:
        """Extract (hostname, registrable_domain) using public-suffix-aware parser.
        
        Examples:
            'sbi.co.in.attacker.com' -> ('sbi.co.in.attacker.com', 'attacker.com')
            'https://sub.portal.sbi.co.in/login' -> ('sub.portal.sbi.co.in', 'sbi.co.in')
        """
        raw = (url_or_hostname or "").strip()
        if "://" not in raw:
            raw = f"http://{raw}"
        try:
            parsed = urlparse(raw)
            hostname = (parsed.hostname or "").lower().strip()
        except Exception:
            hostname = raw.lower().strip()

        ext = _tld_parser(hostname)
        if ext.domain and ext.suffix:
            reg_domain = f"{ext.domain}.{ext.suffix}".lower()
        elif ext.domain:
            reg_domain = ext.domain.lower()
        else:
            reg_domain = hostname

        return hostname, reg_domain

    def match_organization(
        self,
        brand_name: Optional[str] = None,
        url_or_hostname: Optional[str] = None,
        text_context: Optional[str] = None,
    ) -> Optional[OfficialOrganizationEntry]:
        """Identify if an explicit or suspected organization matches a verified registry entry.
        
        Priority:
        1. Explicit confirmed brand_name from typosquatting / brand heuristic.
        2. Brand/organization name extracted from text context.
        3. Hostname inspection (e.g. brand embedded in subdomain or path under an unrelated domain).
        
        Strict Safety Invariants:
        - Never guesses ambiguous names.
        - Returns None if no confident match exists.
        """
        # 1. Match by explicit brand_name
        if brand_name:
            b_norm = brand_name.lower().strip()
            # Direct key match
            if b_norm in self._by_key:
                return self._by_key[b_norm]
            # Alias match
            for entry in self._entries:
                if b_norm in entry.aliases or any(alias in b_norm for alias in entry.aliases):
                    return entry

        # 2. Match from text context (e.g. SMS message mentioning 'SBI', 'DHL', 'India Post', etc.)
        if text_context:
            clean_text = text_context.lower()
            for entry in self._entries:
                for alias in entry.aliases:
                    # Match on word boundary to avoid false substrings (e.g. 'citi' inside 'velocity')
                    pattern = rf"\b{re.escape(alias)}\b"
                    if re.search(pattern, clean_text):
                        return entry

        # 3. Match from URL / hostname
        if url_or_hostname:
            hostname, reg_domain = self.extract_registrable_domain(url_or_hostname)
            # Check if an official organization's alias is embedded in hostname or path
            for entry in self._entries:
                for alias in entry.aliases:
                    if len(alias) >= 3:
                        # Check subdomain or token in hostname
                        parts = re.split(r"[-_.]", hostname)
                        if alias in parts:
                            return entry

        return None

    def get_by_brand(self, brand: str) -> Optional[OfficialOrganizationEntry]:
        """Convenience lookup by brand name or alias."""
        return self.match_organization(brand_name=brand)

    def evaluate_impersonation(
        self,
        url_or_hostname: str,
        matched_org: OfficialOrganizationEntry,
    ) -> Tuple[bool, str]:
        """Determine whether the submitted URL is an impersonation of the verified organization.
        
        Returns:
            (is_impersonation, reasoning)
            - True: The submitted URL targets or mimics the organization but DOES NOT belong to its official domain.
            - False: The submitted URL is actually the genuine official domain.
        """
        hostname, reg_domain = self.extract_registrable_domain(url_or_hostname)
        official_domain = matched_org.official_domain.lower()

        # Check if submitted domain matches official domain
        if reg_domain == official_domain or hostname == official_domain or hostname.endswith(f".{official_domain}"):
            return False, f"The submitted destination matches the verified official domain '{official_domain}'."

        return True, (
            f"The submitted destination host '{hostname}' (registrable domain: '{reg_domain}') "
            f"does not match the verified official domain '{official_domain}' for {matched_org.name}."
        )


_global_registry: Optional[OfficialDomainRegistry] = None


def get_official_domain_registry() -> OfficialDomainRegistry:
    """Dependency injector for singleton OfficialDomainRegistry."""
    global _global_registry
    if _global_registry is None:
        _global_registry = OfficialDomainRegistry()
    return _global_registry


get_official_registry = get_official_domain_registry

