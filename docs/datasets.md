# FraudLens — Comprehensive Dataset Provenance, Preparation & Validation

This document serves as the authoritative record of dataset provenance, preprocessing, deduplication, stratified partitioning, and validation for **FraudLens**.

---

## 1. Executive Summary of Datasets

| Dataset Domain | Source Artifact | Raw Records | Clean Deduplicated | Class Balance | Split Strategy | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SMS Spam / Scam** | `sms+spam+collection(1).zip` | 5,574 | 5,160 | 86.6% Ham / 13.4% Spam | 80/10/10 Stratified (Seed 42) | **Completed** |
| **Phishing URLs (Primary)** | `data_imbal - 55000.xlsx` | 55,000 | 54,869 | 91.11% Legit / 8.89% Phish | 80/10/10 Stratified (Seed 42) | **Completed** |
| **Phishing URLs (Comparison)** | `data_bal - 20000.xlsx` | 20,000 | 19,836 | 50.00% Legit / 50.00% Phish | Leakage-Isolated Stress Test | **Completed** |
| **Tabular Reference** | `phishing(1).csv` | 11,055 | 11,055 | 55.69% Legit / 44.31% Phish | Reference Tabular Only | **Archived / Non-URL** |

---

## 2. SMS Dataset (`sms+spam+collection(1).zip`)

### 2.1 Provenance & Authenticity
- **Origin:** UCI Machine Learning Repository / Almeida et al. (2011).
- **Archive File:** `sms+spam+collection(1).zip`
- **SHA-256 Digest:** `7d039a24a6083ed9ef0f806ebad56bbb976e3aeb8de05669173bfdc4996c239d`
- **Extracted File:** `SMSSpamCollection` (Tab-delimited text, UTF-8).

### 2.2 Raw Characteristics & Cleaning
- **Raw Count:** 5,574 rows (4,827 ham, 747 spam).
- **Missing Values:** 0 missing labels, 0 missing texts.
- **Duplicates Detected:** 414 duplicate messages (whitespace-trimmed).
- **Clean Deduplicated Count:** 5,160 unique messages (4,516 ham, 644 spam).
- **Conflicting Labels:** 0 conflicting labels across duplicates.

### 2.3 Partitions & Leakage Prevention
Split using stratified sampling with fixed random seed `42`:
- **`sms_train.csv`**: 4,128 rows (3,613 ham, 515 spam — 12.48% spam).
- **`sms_val.csv`**: 516 rows (452 ham, 64 spam — 12.40% spam).
- **`sms_test.csv`**: 516 rows (451 ham, 65 spam — 12.60% spam).
- **Cross-Split Text Overlap:** 0 messages overlap between train, validation, or test.

---

## 3. Phishing URL Datasets (Inspection & Validation)

### 3.1 Raw Datasets Inspected & Verified

#### Candidate A (Primary): `data_imbal - 55000.xlsx`
- **File Path:** `~/Downloads/data_imbal - 55000.xlsx`
- **File Size:** 1,789,097 bytes
- **SHA-256 Digest:** `5373af0d644bcb39b1850c2a3e90e28824f1c704c0492df3df95fc8b65ad1c92`
- **Format:** Microsoft Excel OpenXML (.xlsx), single sheet `Sheet1`.
- **Columns:** `URLs` (string), `Labels` (integer).
- **Raw Row Count:** 55,000 rows.
- **Raw Class Distribution:** 50,000 legitimate (`0`), 5,000 phishing (`1`) (9.09% phishing).
- **Missing Values:** 0 null URLs, 0 null labels.
- **Label Values:** Strictly binary `{0, 1}`. No anomalous or negative labels.

#### Candidate B (Comparison): `data_bal - 20000.xlsx`
- **File Path:** `~/Downloads/data_bal - 20000.xlsx`
- **File Size:** 869,780 bytes
- **SHA-256 Digest:** `58e4654e5e10587f297a258d7b7374b609752fabe90668917f511223e8655603`
- **Format:** Microsoft Excel OpenXML (.xlsx), single sheet `Sheet1`.
- **Columns:** `URLs` (string), `Labels` (integer).
- **Raw Row Count:** 20,000 rows.
- **Raw Class Distribution:** 10,000 legitimate (`0`), 10,000 phishing (`1`) (50.00% phishing).
- **Missing Values:** 0 null URLs, 0 null labels.
- **Label Values:** Strictly binary `{0, 1}`.

#### Candidate C (Reference): `phishing(1).csv`
- **File Path:** `~/Downloads/phishing(1).csv`
- **File Size:** 855,304 bytes
- **SHA-256 Digest:** `96d48b5c9e957e2dc06f880b2161476da192f814f74332cfd2e3d61a35309dc3`
- **Format:** Comma-separated values (CSV).
- **Columns:** 31 columns (`Index`, `UsingIP`, `LongURL`, `ShortURL`, `Symbol@`, `Redirecting//`, `PrefixSuffix-`, `SubDomains`, ..., `class`).
- **Raw Row Count:** 11,055 rows.
- **Finding:** Contains pre-extracted categorical integer features `{-1, 0, 1}` from the UCI Phishing Websites dataset. **Contains NO raw URL strings.** Cannot be parsed by the FraudLens lexical URL feature extraction pipeline. Retained for historical reference only.

---

### 3.2 Critical Cross-Dataset Leakage Analysis

A thorough set-intersection analysis of normalized URLs between `data_imbal - 55000.xlsx` and `data_bal - 20000.xlsx` revealed:
- **Total Unique Overlap:** **14,761 URLs** appear in both `data_imbal` and `data_bal`.
- **Percentage Overlap:** **74.4% of `data_bal - 20000.xlsx` is identical to samples in `data_imbal - 55000.xlsx`**.
- **Label Consistency:** 100% agreement on overlapping URLs (0 conflicting labels).

> [!WARNING]
> **Severe Data Leakage Risk Identified:**
> If `data_imbal` were used for training and `data_bal` were used directly as a benchmark or comparison test set, **74.4% of the test set would have already been seen during training**.
> This would cause artificial performance inflation and invalidate model evaluation.

### 3.3 Dataset Selection Justification
1. **Primary Dataset Selected: `data_imbal - 55000.xlsx`**
   - **Real-World Fidelity:** Phishing represents a minority fraction of web traffic. A 10:1 ratio (~8.9% phishing) mirrors realistic production threat distributions far better than an artificial 50/50 balance.
   - **Sample Volume:** 54,869 clean samples provide superior variety for domain, TLD, path, and entropy modeling.
2. **Comparison Dataset Selected: `url_stress_test_bal_unique.csv` (Filtered from `data_bal`)**
    - We isolated the **4,672 clean phishing URLs** that exist solely in `data_bal` and have **zero overlap** with `data_imbal`.
    - This provides an independent, uncontaminated out-of-distribution stress test corpus for URL model evaluation.

---

### 3.4 Data Cleaning & Normalization Pipeline

The cleaning pipeline (`backend/scripts/prepare_url_dataset.py`) enforces deterministic normalization:
1. **Whitespace Trimming:** Strips leading/trailing spaces, tabs, and newlines.
2. **Surrounding Quotes Removal:** Strips accidental wrapping quotation marks (`"`, `'`).
3. **Trailing Slash Normalization:** Removes redundant trailing slashes while preserving root host paths (e.g., `https://example.com/login/` -> `https://example.com/login`).
4. **Duplicate Deduplication:**
   - `data_imbal`: 55,000 raw -> **54,869 clean unique URLs** (131 duplicate variants eliminated).
   - `data_bal`: 20,000 raw -> **19,836 clean unique URLs** (164 duplicate variants eliminated).
5. **Conflict Verification:** Verified that no single normalized URL has both `0` and `1` labels (0 conflicts found).

---

### 3.5 Partition Splits & Specifications

All splits use stratified sampling with random seed `42` on `data_imbal`:

```
data_imbal (54,869 clean rows)
├── Train (80%): 43,895 rows (39,993 Legitimate, 3,902 Phishing — 8.89% Phishing)
├── Validation (10%): 5,487 rows (4,999 Legitimate, 488 Phishing — 8.89% Phishing)
└── Test (10%): 5,487 rows (4,999 Legitimate, 488 Phishing — 8.89% Phishing)
```

#### Stress Test Partition:
- **`url_stress_test_bal_unique.csv`**: 4,672 rows (0 Legitimate, 4,672 Phishing — 100% Phishing).
- **Leakage Invariant:** `len(set(Train) ∩ set(Stress)) == 0`, `len(set(Val) ∩ set(Stress)) == 0`, `len(set(Test) ∩ set(Stress)) == 0`.

---

## 4. Cryptographic Provenance Manifest

Generated at: `data/processed/urls/provenance_manifest.json`

| Output File Path | Rows | Columns | SHA-256 Digest |
| :--- | :--- | :--- | :--- |
| `data/processed/urls/url_train.csv` | 43,895 | `URLs`, `Labels`, `registered_domain` | `fe168fa5045dbb6982cfd715949d10787e2b694b9f298da1c50e2ae2fe1d784a` |
| `data/processed/urls/url_val.csv` | 5,487 | `URLs`, `Labels`, `registered_domain` | `7be1b1f3c3a9e2fc996d934bb88fb037e93ca914a1a0d30fa140228302f33fdf` |
| `data/processed/urls/url_test.csv` | 5,487 | `URLs`, `Labels`, `registered_domain` | `9d7e00da44aaae09ff2529d8924b21650c388656d0d297cb73a8ae3e895c1044` |
| `data/processed/urls/url_stress_test_bal_unique.csv` | 4,672 | `URLs`, `Labels`, `registered_domain` | `adce9ea7412808c104e76a6e033b00fdfb5ebf0cb49065ca77ff53f93ce0d24e` |

---

## 5. Verification & Test Suite

The test suite in [`backend/tests/test_dataset_url.py`](file:///D:/Projects/usability/backend/tests/test_dataset_url.py) provides 12 automated unit and integration tests:
1. `test_url_normalization_preserves_original`: Validates trailing slash trimming and character case retention.
2. `test_extract_registered_domain`: Validates domain extraction ignoring ports and subdomains.
3. `test_duplicate_url_detection`: Validates duplicate removal across trailing slash variations.
4. `test_conflicting_label_detection`: Ensures conflicting binary labels are detected and blocked.
5. `test_missing_url_and_missing_label_handling`: Verifies rejection of empty strings, whitespace, and null labels.
6. `test_label_mapping_and_rejection_of_ambiguous_labels`: Verifies strict `{0, 1}` binary label enforcement.
7. `test_reproducible_splitting_seed_42`: Ensures bit-identical splits across repeated partition runs.
8. `test_prevention_of_url_overlap_across_splits`: Mathematical set-intersection check proving zero train/test leakage.
9. `test_correct_class_distribution_reporting`: Verifies exact preservation of the 8.89% phishing ratio across splits.
10. `test_graceful_errors_missing_files_and_unsupported_formats`: Ensures clear exceptions on invalid file paths.
11. `test_processed_csv_integrity_and_zero_cross_split_leakage`: Tests actual production CSV files on disk for row counts, columns, and 0 intersection.
12. `test_raw_source_file_hashes_immutable`: Cryptographically verifies that raw Excel and CSV downloads remain completely untouched.

All 12 URL dataset tests pass with 100% compliance across the comprehensive test suite.

---

## 6. Phishing URL Model Training, Evaluation & Dataset Limitations

### 6.1 Feature Engineering Schema
The URL model extracts 34 deterministic lexical and structural features strictly without network access:
- **Lengths & Counts:** URL length, hostname length, path length, query length, counts of dots, hyphens, underscores, slashes, question marks, equal signs, `@`, ampersands, exclamation marks, `%` encodings, digits, letters.
- **Ratios & Depth:** Digit ratio in URL and hostname, subdomain depth count.
- **Host & Protocol:** IP address host (IPv4/IPv6), HTTPS vs HTTP, non-standard port indicator.
- **Structural Anomalies:** `@` symbol presence, `//` path separator, query parameter count, sensitive tokens (`login`, `verify`, `account`, `banking`).
- **Complexity & Heuristics:** Shannon entropy of URL and hostname, punycode `xn--`, local brand impersonation score, suspicious TLD flag, consecutive hyphens.

### 6.2 Model Comparison on Validation Split (`url_val.csv`)
Trained on `url_train.csv` (43,895 samples, 8.89% phishing prevalence):

| Configuration | Validation Phishing Precision | Validation Phishing Recall | Validation Phishing F1 | ROC-AUC | PR-AUC | Selection |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`RF_unweighted`** | 91.15% | 78.07% | 84.11% | 0.9771 | 0.9202 | Baseline |
| **`RF_balanced`** | 83.20% | 86.27% | 84.71% | 0.9799 | 0.9177 | Candidate |
| **`RF_balanced_subsample`** | **88.62%** | **81.35%** | **84.83%** | **0.9839** | **0.9183** | **Selected Model** |

### 6.3 Threshold Calibration on Validation Split
- Calibrated optimal decision threshold $t = 0.45$:
  - Phishing Precision: 86.99%, Recall: 83.61%, F1: 85.27%, FPR: 1.22%.
- Defined operational classification bands:
  - `p < 0.25`: `LOW RISK`
  - `0.25 <= p < 0.60`: `MEDIUM RISK`
  - `p >= 0.60`: `HIGH RISK`

### 6.4 Held-Out Test Evaluation (`url_test.csv`, 5,487 rows)
Evaluated once on untouched test split:
- **Accuracy:** 96.87%
- **Macro F1:** 0.9038
- **ROC-AUC:** 0.9807
- **PR-AUC:** 0.9009
- **Phishing Precision:** 81.98% (405 TP / 89 FP)
- **Phishing Recall:** 82.99% (405 TP / 83 FN)
- **Phishing F1:** 0.8248
- **Legitimate Precision:** 98.34% / Recall: 98.22% / F1: 0.9828
- **False Positive Rate (FPR):** 1.78% (89 false alarms out of 4,999 legitimate URLs)
- **False Negative Rate (FNR):** 17.01% (83 misses out of 488 phishing URLs)
- **Confusion Matrix:** `[[4910, 89], [83, 405]]`

### 6.5 Stress Test Split Evaluation (`url_stress_test_bal_unique.csv`, 4,672 rows)
- **Detection Rate:** **86.90%** (4,060 / 4,672 phishing URLs detected).
- **Limitation Note:** This split contains 100% phishing URLs; specificity and false positive rate cannot be measured.

### 6.6 Known Dataset Bias & Generalization Boundaries
1. **Query String Artifact in Primary Dataset:** In `data_imbal - 55000.xlsx`, 0.0% of legitimate URLs contain query strings (`?`), whereas 23.5% of phishing URLs contain query strings. Consequently, tree models split heavily on query presence. The multi-factor risk engine guards against this bias by suppressing false positives for recognized authoritative domains.
2. **Domain-Level Clustering:** Random URL-level splitting allows different paths from the same domain to appear across splits, which may slightly inflate benchmark scores compared to unseen zero-day domain registrations.
3. **Statistical Humility:** These metrics reflect performance on the benchmark corpus and do not guarantee real-world accuracy against novel phishing evasion techniques (e.g. CAPTCHA cloaking, reverse proxies, QR-embedded redirects).

