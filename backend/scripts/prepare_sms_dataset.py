"""Reproducible SMS Dataset Preprocessing and Stratified Split Pipeline.

Part of FraudLens Dataset Collection, Provenance Verification,
Preprocessing, and Validation.

Dataset: SMS Spam Collection v.1 (UCI Machine Learning Repository / Almeida et al.)
Raw File: data/raw/sms/SMSSpamCollection
Output:
  - data/processed/sms/sms_train.csv
  - data/processed/sms/sms_val.csv
  - data/processed/sms/sms_test.csv
  - data/processed/sms/provenance_manifest.json

Guarantees:
  - Deterministic stratified splitting (80% train, 10% val, 10% test).
  - Deduplication to prevent text leakage across train and test sets.
  - Zero loss of raw text formatting necessary for NLP and entity extraction.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Dict, Tuple

import pandas as pd
from sklearn.model_selection import train_test_split


def compute_sha256(file_path: Path) -> str:
    """Compute hex SHA-256 digest of a file."""
    return hashlib.sha256(file_path.read_bytes()).hexdigest()


def load_raw_sms(raw_path: Path) -> pd.DataFrame:
    """Load raw SMS Spam Collection file."""
    if not raw_path.exists():
        raise FileNotFoundError(f"Raw dataset file not found: {raw_path}")

    rows = []
    with open(raw_path, "r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            line_stripped = line.rstrip("\r\n")
            if not line_stripped:
                continue
            parts = line_stripped.split("\t", 1)
            if len(parts) == 2:
                label, text = parts
                rows.append({
                    "raw_line_num": line_num,
                    "label": label.strip(),
                    "text": text.strip(),
                })
            else:
                raise ValueError(f"Malformed line {line_num} in raw data: {line_stripped}")

    df = pd.DataFrame(rows)
    return df


def preprocess_and_split(
    raw_path: Path,
    output_dir: Path,
    random_state: int = 42,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
) -> Dict:
    """Execute end-to-end dataset preparation and generate provenance manifest."""
    assert abs((train_ratio + val_ratio + test_ratio) - 1.0) < 1e-6, "Split ratios must sum to 1.0"
    output_dir.mkdir(parents=True, exist_ok=True)

    raw_sha256 = compute_sha256(raw_path)
    df_raw = load_raw_sms(raw_path)
    raw_count = len(df_raw)
    raw_label_counts = df_raw["label"].value_counts().to_dict()

    # Deduplicate by text to prevent train/test leakage
    # Exact duplicate texts in SMS datasets cause identical samples to appear in both train and test.
    df_dedup = df_raw.drop_duplicates(subset=["text"]).copy()
    dedup_count = len(df_dedup)
    dropped_duplicates = raw_count - dedup_count

    # Encode binary target
    df_dedup["is_scam"] = (df_dedup["label"] == "spam").astype(int)
    df_dedup["char_length"] = df_dedup["text"].apply(len)
    df_dedup["word_count"] = df_dedup["text"].apply(lambda t: len(t.split()))

    # Stratified Train / (Val + Test) split
    temp_ratio = val_ratio + test_ratio  # 0.2
    df_train, df_temp = train_test_split(
        df_dedup,
        test_size=temp_ratio,
        random_state=random_state,
        stratify=df_dedup["is_scam"],
    )

    # Stratified Val / Test split (each getting 0.1 of total)
    val_relative_ratio = val_ratio / temp_ratio  # 0.5
    df_val, df_test = train_test_split(
        df_temp,
        test_size=val_relative_ratio,
        random_state=random_state,
        stratify=df_temp["is_scam"],
    )

    # Verification: check for data leakage
    train_texts = set(df_train["text"])
    val_texts = set(df_val["text"])
    test_texts = set(df_test["text"])

    train_val_overlap = len(train_texts & val_texts)
    train_test_overlap = len(train_texts & test_texts)
    val_test_overlap = len(val_texts & test_texts)

    if train_val_overlap > 0 or train_test_overlap > 0 or val_test_overlap > 0:
        raise RuntimeError(
            f"DATA LEAKAGE DETECTED! Train-Val: {train_val_overlap}, "
            f"Train-Test: {train_test_overlap}, Val-Test: {val_test_overlap}"
        )

    # Save CSV files
    train_csv = output_dir / "sms_train.csv"
    val_csv = output_dir / "sms_val.csv"
    test_csv = output_dir / "sms_test.csv"

    columns_to_save = ["label", "is_scam", "text", "char_length", "word_count"]
    df_train[columns_to_save].to_csv(train_csv, index=False, encoding="utf-8")
    df_val[columns_to_save].to_csv(val_csv, index=False, encoding="utf-8")
    df_test[columns_to_save].to_csv(test_csv, index=False, encoding="utf-8")

    # Generate manifest
    manifest = {
        "dataset_name": "SMS Spam Collection v.1",
        "provenance": {
            "source": "UCI Machine Learning Repository / Almeida et al. (2011)",
            "raw_filename": raw_path.name,
            "raw_file_sha256": raw_sha256,
            "raw_row_count": raw_count,
            "raw_label_distribution": raw_label_counts,
        },
        "preprocessing": {
            "deduplication": True,
            "dropped_duplicate_rows": dropped_duplicates,
            "retained_unique_rows": dedup_count,
            "random_seed": random_state,
            "split_ratios": {
                "train": train_ratio,
                "val": val_ratio,
                "test": test_ratio,
            },
            "leakage_verification": {
                "train_val_overlap": train_val_overlap,
                "train_test_overlap": train_test_overlap,
                "val_test_overlap": val_test_overlap,
                "status": "ZERO_LEAKAGE_VERIFIED",
            },
        },
        "splits": {
            "train": {
                "file": train_csv.name,
                "sha256": compute_sha256(train_csv),
                "total_samples": len(df_train),
                "ham_count": int((df_train["is_scam"] == 0).sum()),
                "spam_count": int((df_train["is_scam"] == 1).sum()),
                "spam_prevalence": float(df_train["is_scam"].mean()),
            },
            "val": {
                "file": val_csv.name,
                "sha256": compute_sha256(val_csv),
                "total_samples": len(df_val),
                "ham_count": int((df_val["is_scam"] == 0).sum()),
                "spam_count": int((df_val["is_scam"] == 1).sum()),
                "spam_prevalence": float(df_val["is_scam"].mean()),
            },
            "test": {
                "file": test_csv.name,
                "sha256": compute_sha256(test_csv),
                "total_samples": len(df_test),
                "ham_count": int((df_test["is_scam"] == 0).sum()),
                "spam_count": int((df_test["is_scam"] == 1).sum()),
                "spam_prevalence": float(df_test["is_scam"].mean()),
            },
        },
    }

    manifest_path = output_dir / "provenance_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Preprocess and split SMS Spam Collection dataset.")
    parser.add_argument(
        "--raw-path",
        type=Path,
        default=Path("D:/Projects/usability/data/raw/sms/SMSSpamCollection"),
        help="Path to raw SMSSpamCollection file.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("D:/Projects/usability/data/processed/sms"),
        help="Directory to save processed splits and manifest.",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random state seed.")
    args = parser.parse_args()

    manifest = preprocess_and_split(
        raw_path=args.raw_path,
        output_dir=args.output_dir,
        random_state=args.seed,
    )

    print("=== SMS Dataset Preprocessing Complete ===")
    print(f"Total Unique Samples: {manifest['preprocessing']['retained_unique_rows']}")
    print(f"Train samples: {manifest['splits']['train']['total_samples']} (Spam: {manifest['splits']['train']['spam_count']})")
    print(f"Val samples:   {manifest['splits']['val']['total_samples']} (Spam: {manifest['splits']['val']['spam_count']})")
    print(f"Test samples:  {manifest['splits']['test']['total_samples']} (Spam: {manifest['splits']['test']['spam_count']})")
    print(f"Leakage status: {manifest['preprocessing']['leakage_verification']['status']}")
    print(f"Saved manifest to {args.output_dir / 'provenance_manifest.json'}")
