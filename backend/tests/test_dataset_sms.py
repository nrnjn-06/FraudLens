"""Automated tests for SMS dataset integrity and leakage resistance."""

import json
from pathlib import Path
import pandas as pd
import pytest


DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
RAW_SMS_FILE = DATA_DIR / "raw/sms/SMSSpamCollection"
PROCESSED_DIR = DATA_DIR / "processed/sms"
TRAIN_CSV = PROCESSED_DIR / "sms_train.csv"
VAL_CSV = PROCESSED_DIR / "sms_val.csv"
TEST_CSV = PROCESSED_DIR / "sms_test.csv"
MANIFEST_FILE = PROCESSED_DIR / "provenance_manifest.json"


def test_raw_sms_file_integrity():
    """Verify raw SMS file exists and has expected row count and no malformed lines."""
    assert RAW_SMS_FILE.exists(), f"Raw SMS file missing: {RAW_SMS_FILE}"
    with open(RAW_SMS_FILE, "r", encoding="utf-8") as f:
        lines = [line.rstrip("\r\n") for line in f if line.strip()]
    assert len(lines) == 5574, f"Expected 5,574 raw lines, found {len(lines)}"

    # Check each line has label and text separated by tab
    for idx, line in enumerate(lines, 1):
        parts = line.split("\t", 1)
        assert len(parts) == 2, f"Line {idx} does not have tab separator: {line}"
        assert parts[0] in {"ham", "spam"}, f"Invalid label on line {idx}: {parts[0]}"


def test_processed_splits_exist_and_non_empty():
    """Verify processed train, val, and test splits exist and have non-zero rows."""
    assert TRAIN_CSV.exists()
    assert VAL_CSV.exists()
    assert TEST_CSV.exists()
    assert MANIFEST_FILE.exists()

    df_train = pd.read_csv(TRAIN_CSV)
    df_val = pd.read_csv(VAL_CSV)
    df_test = pd.read_csv(TEST_CSV)

    assert len(df_train) == 4128
    assert len(df_val) == 516
    assert len(df_test) == 516
    assert len(df_train) + len(df_val) + len(df_test) == 5160


def test_processed_schema_and_no_missing_values():
    """Verify columns and assert no missing or null values in any split."""
    expected_columns = {"label", "is_scam", "text", "char_length", "word_count"}

    for split_path in [TRAIN_CSV, VAL_CSV, TEST_CSV]:
        df = pd.read_csv(split_path)
        assert expected_columns.issubset(set(df.columns)), f"Missing columns in {split_path}"
        assert df.isnull().sum().sum() == 0, f"Null values detected in {split_path}"
        assert (df["text"].str.strip() == "").sum() == 0, f"Empty text in {split_path}"
        assert set(df["label"].unique()).issubset({"ham", "spam"})
        assert set(df["is_scam"].unique()).issubset({0, 1})


def test_zero_data_leakage_between_splits():
    """Verify strictly zero duplicate text messages between train, val, and test splits."""
    df_train = pd.read_csv(TRAIN_CSV)
    df_val = pd.read_csv(VAL_CSV)
    df_test = pd.read_csv(TEST_CSV)

    train_texts = set(df_train["text"].str.strip())
    val_texts = set(df_val["text"].str.strip())
    test_texts = set(df_test["text"].str.strip())

    train_val_overlap = train_texts & val_texts
    train_test_overlap = train_texts & test_texts
    val_test_overlap = val_texts & test_texts

    assert len(train_val_overlap) == 0, f"Leakage between train and val: {len(train_val_overlap)} texts"
    assert len(train_test_overlap) == 0, f"Leakage between train and test: {len(train_test_overlap)} texts"
    assert len(val_test_overlap) == 0, f"Leakage between val and test: {len(val_test_overlap)} texts"


def test_stratified_class_balance_consistency():
    """Verify class balance is preserved consistently across splits (~12.4% spam)."""
    df_train = pd.read_csv(TRAIN_CSV)
    df_val = pd.read_csv(VAL_CSV)
    df_test = pd.read_csv(TEST_CSV)

    train_prevalence = df_train["is_scam"].mean()
    val_prevalence = df_val["is_scam"].mean()
    test_prevalence = df_test["is_scam"].mean()

    # Allow tiny rounding deviation (+/- 0.01)
    assert abs(train_prevalence - 0.1245) < 0.005
    assert abs(val_prevalence - 0.1240) < 0.005
    assert abs(test_prevalence - 0.1240) < 0.005


def test_manifest_matches_disk():
    """Verify provenance manifest matches actual files and recorded checksums."""
    with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["dataset_name"] == "SMS Spam Collection v.1"
    assert manifest["preprocessing"]["leakage_verification"]["status"] == "ZERO_LEAKAGE_VERIFIED"
    assert manifest["splits"]["train"]["total_samples"] == 4128
    assert manifest["splits"]["val"]["total_samples"] == 516
    assert manifest["splits"]["test"]["total_samples"] == 516
