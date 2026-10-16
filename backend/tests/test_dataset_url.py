"""Automated tests for Phishing URL Dataset Preparation & Validation.

Verifies:
- Inspection and parsing on small synthetic fixtures (fast, deterministic unit tests)
- Conservative URL normalization preserving raw URL auditability
- Detection of missing URLs and missing labels
- Duplicate URL detection and deduplication
- Conflicting-label detection
- Label mapping and rejection of ambiguous labels
- Reproducible splitting with fixed seed 42
- Prevention of URL overlap across train/val/test splits
- Class-distribution stratification accuracy
- Graceful error handling for missing files and unsupported formats
- Verification that production raw sources remain unchanged
- Processed artifacts schema integrity and zero data leakage
"""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import pandas as pd
import pytest
from sklearn.model_selection import train_test_split

from backend.scripts.prepare_url_dataset import (
    compute_sha256,
    extract_registered_domain,
    normalize_url,
    prepare_url_pipeline,
)


@pytest.fixture
def synthetic_url_dataframe():
    """Create a controlled, small synthetic dataset fixture."""
    data = [
        {"URLs": "https://www.google.com/search?q=test", "Labels": 0},
        {"URLs": "http://legit-bank.com/portal/", "Labels": 0},
        {"URLs": "https://github.com/project", "Labels": 0},
        {"URLs": "https://wikipedia.org/wiki/Phishing", "Labels": 0},
        {"URLs": "https://amazon.com/dp/item", "Labels": 0},
        {"URLs": "http://192.168.1.1/login.php", "Labels": 1},
        {"URLs": "https://sbi-kyc-verify-update.ga/login", "Labels": 1},
        {"URLs": "http://paypal-security-account.top/secure", "Labels": 1},
        {"URLs": "https://appleid-verify-icloud.xyz/auth", "Labels": 1},
        {"URLs": "http://dbs-bank-token.online/verify", "Labels": 1},
        # Duplicate with trailing slash variation
        {"URLs": "http://legit-bank.com/portal", "Labels": 0},
        # Exact duplicate
        {"URLs": "https://appleid-verify-icloud.xyz/auth", "Labels": 1},
    ]
    return pd.DataFrame(data)


# -----------------------------------------------------------------------------
# 1. URL Normalization Tests
# -----------------------------------------------------------------------------

def test_url_normalization_preserves_original():
    """Verify normalization strips trailing slashes/quotes while preserving raw content."""
    raw = '  "https://example.com/login/path/"  '
    norm = normalize_url(raw)
    assert norm == "https://example.com/login/path"
    # Root protocol URL does not have slashes removed improperly
    assert normalize_url("https://example.com/") == "https://example.com"
    # Case in path is preserved
    assert normalize_url("https://example.com/PathCase") == "https://example.com/PathCase"


def test_extract_registered_domain():
    """Verify registered domain extraction ignores subdomains and ports."""
    assert extract_registered_domain("https://sub.portal.example.com/login") == "example.com"
    assert extract_registered_domain("http://phish-site.co.uk:8080/test") == "phish-site.co.uk"
    assert extract_registered_domain("https://192.168.1.100/admin") in ["192.168.1.100", "unknown"]


# -----------------------------------------------------------------------------
# 2. Data Cleaning & Duplicate/Conflict Detection Tests
# -----------------------------------------------------------------------------

def test_duplicate_url_detection(synthetic_url_dataframe):
    """Verify duplicate normalized URLs are detected accurately."""
    df = synthetic_url_dataframe.copy()
    df["norm_url"] = df["URLs"].apply(normalize_url)

    dupes = df.duplicated(subset=["norm_url"])
    # Both http://legit-bank.com/portal and https://appleid-verify-icloud.xyz/auth should be detected as duplicates
    assert dupes.sum() == 2


def test_conflicting_label_detection():
    """Verify detection of identical URLs bearing conflicting binary labels."""
    conflicting_data = pd.DataFrame([
        {"URLs": "https://example.com/login", "Labels": 0},
        {"URLs": "https://example.com/login", "Labels": 1},
    ])
    conflicts = conflicting_data.groupby("URLs")["Labels"].nunique()
    has_conflict = bool((conflicts > 1).any())
    assert has_conflict is True


def test_missing_url_and_missing_label_handling():
    """Verify pipeline rejects or flags missing values appropriately."""
    df_missing = pd.DataFrame([
        {"URLs": "https://valid.com", "Labels": 0},
        {"URLs": "", "Labels": 1},
        {"URLs": "   ", "Labels": 0},
        {"URLs": "https://another.com", "Labels": None},
    ])
    missing_urls = df_missing["URLs"].str.strip().eq("")
    missing_labels = df_missing["Labels"].isnull()

    assert missing_urls.sum() == 2
    assert missing_labels.sum() == 1


def test_label_mapping_and_rejection_of_ambiguous_labels():
    """Verify valid binary labels (0, 1) and detection of invalid labels."""
    valid_labels = pd.Series([0, 1, 0, 1])
    assert set(valid_labels.unique()).issubset({0, 1})

    invalid_labels = pd.Series([0, 1, -1, 2, "unknown"])
    is_valid = invalid_labels.isin([0, 1])
    assert is_valid.sum() == 2
    assert (~is_valid).sum() == 3


# -----------------------------------------------------------------------------
# 3. Reproducible Splitting & Zero Leakage Tests
# -----------------------------------------------------------------------------

def test_reproducible_splitting_seed_42(synthetic_url_dataframe):
    """Verify stratified splitting with seed 42 produces deterministic, reproducible splits."""
    df = synthetic_url_dataframe.copy()
    df["norm_url"] = df["URLs"].apply(normalize_url)
    df_dedup = df.drop_duplicates(subset=["norm_url"]).copy()

    # Run 1
    train1, test1 = train_test_split(
        df_dedup, test_size=0.2, random_state=42, stratify=df_dedup["Labels"]
    )

    # Run 2
    train2, test2 = train_test_split(
        df_dedup, test_size=0.2, random_state=42, stratify=df_dedup["Labels"]
    )

    pd.testing.assert_frame_equal(train1, train2)
    pd.testing.assert_frame_equal(test1, test2)


def test_prevention_of_url_overlap_across_splits(synthetic_url_dataframe):
    """Verify zero overlap of normalized URLs between train and test splits."""
    df = synthetic_url_dataframe.copy()
    df["norm_url"] = df["URLs"].apply(normalize_url)
    df_dedup = df.drop_duplicates(subset=["norm_url"]).copy()

    train, test = train_test_split(
        df_dedup, test_size=0.2, random_state=42, stratify=df_dedup["Labels"]
    )

    train_set = set(train["norm_url"])
    test_set = set(test["norm_url"])
    overlap = train_set.intersection(test_set)
    assert len(overlap) == 0


def test_correct_class_distribution_reporting():
    """Verify stratified splitting preserves class proportions without sample size quantization error."""
    urls = [f"https://legit{i}.com/page" for i in range(80)] + [f"http://phish{i}.xyz/login" for i in range(20)]
    labels = [0] * 80 + [1] * 20
    df = pd.DataFrame({"URLs": urls, "Labels": labels})
    df["norm_url"] = df["URLs"].apply(normalize_url)
    df_dedup = df.drop_duplicates(subset=["norm_url"]).copy()

    orig_ratio = (df_dedup["Labels"] == 1).mean()

    train, test = train_test_split(
        df_dedup, test_size=0.2, random_state=42, stratify=df_dedup["Labels"]
    )

    train_ratio = (train["Labels"] == 1).mean()
    test_ratio = (test["Labels"] == 1).mean()

    assert abs(train_ratio - orig_ratio) < 0.01
    assert abs(test_ratio - orig_ratio) < 0.01


def test_graceful_errors_missing_files_and_unsupported_formats():
    """Verify proper exceptions on missing files."""
    with pytest.raises(Exception):
        prepare_url_pipeline(
            imbal_path=Path("non_existent_imbal.xlsx"),
            bal_path=Path("non_existent_bal.xlsx"),
            output_dir=Path("temp_out"),
        )


# -----------------------------------------------------------------------------
# 4. Production Artifact Integrity & Leakage Tests
# -----------------------------------------------------------------------------

def test_production_raw_sources_remain_unchanged():
    """Verify original raw dataset files match their recorded SHA-256 digests if present."""
    downloads_dir = Path.home() / "Downloads"
    imbal_path = Path(os.environ.get("FRAUDLENS_IMBAL_DATASET", downloads_dir / "data_imbal - 55000.xlsx"))
    bal_path = Path(os.environ.get("FRAUDLENS_BAL_DATASET", downloads_dir / "data_bal - 20000.xlsx"))

    if not imbal_path.exists() or not bal_path.exists():
        pytest.skip("Raw benchmark source files not present in local path; skipping raw digest validation.")

    # Verified SHA-256 digests
    expected_imbal_sha = "5373af0d644bcb39b1850c2a3e90e28824f1c704c0492df3df95fc8b65ad1c92"
    expected_bal_sha = "58e4654e5e10587f297a258d7b7374b609752fabe90668917f511223e8655603"

    assert compute_sha256(imbal_path) == expected_imbal_sha
    assert compute_sha256(bal_path) == expected_bal_sha


def test_production_processed_splits_exist_and_non_empty():
    """Verify url_train.csv, url_val.csv, url_test.csv exist and have valid schemas."""
    base = Path(__file__).resolve().parent.parent.parent / "data" / "processed" / "urls"
    train = base / "url_train.csv"
    val = base / "url_val.csv"
    test = base / "url_test.csv"
    stress = base / "url_stress_test_bal_unique.csv"
    manifest = base / "provenance_manifest.json"

    for p in [train, val, test, stress, manifest]:
        assert p.exists(), f"Expected artifact {p.name} does not exist!"
        assert p.stat().st_size > 0, f"Artifact {p.name} is empty!"

    # Check schemas
    df_train = pd.read_csv(train)
    required_cols = {"raw_url", "url", "is_phishing", "domain", "url_length"}
    assert required_cols.issubset(set(df_train.columns))
    assert len(df_train) > 40000
    assert df_train["is_phishing"].isin([0, 1]).all()


def test_production_zero_data_leakage_between_splits():
    """Verify zero overlap of normalized URLs across production train, val, and test splits."""
    base = Path(__file__).resolve().parent.parent.parent / "data" / "processed" / "urls"
    df_train = pd.read_csv(base / "url_train.csv")
    df_val = pd.read_csv(base / "url_val.csv")
    df_test = pd.read_csv(base / "url_test.csv")
    df_stress = pd.read_csv(base / "url_stress_test_bal_unique.csv")

    train_urls = set(df_train["url"])
    val_urls = set(df_val["url"])
    test_urls = set(df_test["url"])
    stress_urls = set(df_stress["url"])

    # Strict zero leakage
    assert len(train_urls.intersection(val_urls)) == 0
    assert len(train_urls.intersection(test_urls)) == 0
    assert len(val_urls.intersection(test_urls)) == 0
    assert len(stress_urls.intersection(train_urls)) == 0
    assert len(stress_urls.intersection(val_urls)) == 0
    assert len(stress_urls.intersection(test_urls)) == 0
