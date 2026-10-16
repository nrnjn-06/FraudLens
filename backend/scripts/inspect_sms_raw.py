"""Raw SMS dataset inspection script for FraudLens.

Analyzes SMSSpamCollection for:
- Checksum & file integrity
- Line count, delimiter parsing
- Label distribution
- Missing values & empty text strings
- Duplicate analysis & label conflict detection
"""

import hashlib
import json
from pathlib import Path
import pandas as pd


def inspect_raw_sms(file_path: Path):
    print(f"=== Inspecting: {file_path} ===")
    content_bytes = file_path.read_bytes()
    sha256 = hashlib.sha256(content_bytes).hexdigest()
    file_size_bytes = len(content_bytes)
    print(f"File Size: {file_size_bytes:,} bytes")
    print(f"SHA-256: {sha256}")

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        raw_lines = f.readlines()
    print(f"Total raw lines in file: {len(raw_lines)}")

    rows = []
    malformed_lines = []
    for line_num, line in enumerate(raw_lines, 1):
        line_clean = line.rstrip("\r\n")
        if not line_clean:
            continue
        parts = line_clean.split("\t", 1)
        if len(parts) == 2:
            label, text = parts
            rows.append({"line_num": line_num, "label": label.strip(), "text": text})
        else:
            malformed_lines.append((line_num, line_clean))

    print(f"Successfully parsed rows: {len(rows)}")
    print(f"Malformed lines: {len(malformed_lines)}")
    if malformed_lines:
        for num, text in malformed_lines[:5]:
            print(f"  Line {num}: {text[:60]}")

    df = pd.DataFrame(rows)

    # Label counts
    label_counts = df["label"].value_counts().to_dict()
    print("\n--- Label Distribution ---")
    for lbl, cnt in label_counts.items():
        pct = (cnt / len(df)) * 100
        print(f"  {lbl}: {cnt} ({pct:.2f}%)")

    # Null / Missing values
    null_labels = df["label"].isnull().sum()
    null_texts = df["text"].isnull().sum()
    empty_texts = (df["text"].str.strip() == "").sum()
    print(f"\n--- Data Quality Checks ---")
    print(f"  Null labels: {null_labels}")
    print(f"  Null text strings: {null_texts}")
    print(f"  Whitespace-only text: {empty_texts}")

    # Duplicates Analysis
    exact_duplicates = df.duplicated(subset=["label", "text"]).sum()
    text_duplicates = df.duplicated(subset=["text"]).sum()
    unique_texts = df["text"].nunique()
    print(f"\n--- Duplicates Analysis ---")
    print(f"  Exact (label + text) duplicates: {exact_duplicates}")
    print(f"  Duplicate text strings: {text_duplicates}")
    print(f"  Unique text strings: {unique_texts}")

    # Label Conflicts (same text marked as both ham and spam)
    conflicts = df.groupby("text")["label"].nunique()
    conflicting_texts = conflicts[conflicts > 1]
    print(f"  Texts with conflicting labels (both ham & spam): {len(conflicting_texts)}")
    if len(conflicting_texts) > 0:
        for conflict_text in conflicting_texts.index[:5]:
            subset = df[df["text"] == conflict_text]
            print(f"    Conflict: {repr(conflict_text[:50])} -> Labels: {subset['label'].tolist()}")

    # Text length stats
    df["char_length"] = df["text"].apply(len)
    df["word_count"] = df["text"].apply(lambda t: len(t.split()))
    print(f"\n--- Text Length Summary (Characters) ---")
    print(df.groupby("label")["char_length"].describe().to_string())

    print(f"\n--- Word Count Summary ---")
    print(df.groupby("label")["word_count"].describe().to_string())

    stats = {
        "file_name": file_path.name,
        "file_size_bytes": file_size_bytes,
        "sha256": sha256,
        "total_lines": len(raw_lines),
        "total_rows": len(df),
        "label_distribution": label_counts,
        "unique_texts": int(unique_texts),
        "exact_duplicates": int(exact_duplicates),
        "text_duplicates": int(text_duplicates),
        "label_conflicts": int(len(conflicting_texts)),
        "null_labels": int(null_labels),
        "empty_texts": int(empty_texts),
    }

    return stats


if __name__ == "__main__":
    raw_path = Path("D:/Projects/usability/data/raw/sms/SMSSpamCollection")
    stats = inspect_raw_sms(raw_path)
    output_meta = Path("D:/Projects/usability/data/raw/sms/raw_stats.json")
    with open(output_meta, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    print(f"\nSaved raw stats to {output_meta}")
