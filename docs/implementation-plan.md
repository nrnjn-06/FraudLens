# FraudLens — Architectural Design & Engineering Implementation Reference

## 1. Executive Roadmap Overview

This document specifies the modular architecture and implementation specifications across the 8 core engineering modules of **FraudLens**.
All 8 engineering modules are verified, tested, and operational.

```mermaid
flowchart LR
    M1[Module 1: Foundation & Specs] --> M2[Module 2: SMS Dataset & Provenance]
    M2 --> M3[Module 3: Scam Message Module]
    M3 --> M4[Module 4: URL Dataset & Splits]
    M4 --> M5[Module 5: URL Phishing Model]
    M5 --> M6[Module 6: QR & UPI Scanner]
    M6 --> M7[Module 7: Threat Intel & Engine]
    M7 --> M8[Module 8: UI Integration & E2E]

    style M1 fill:#065f46,stroke:#10b981,stroke-width:2px,color:#fff
    style M2 fill:#065f46,stroke:#10b981,stroke-width:2px,color:#fff
    style M3 fill:#065f46,stroke:#10b981,stroke-width:2px,color:#fff
    style M4 fill:#065f46,stroke:#10b981,stroke-width:2px,color:#fff
    style M5 fill:#065f46,stroke:#10b981,stroke-width:2px,color:#fff
    style M6 fill:#065f46,stroke:#10b981,stroke-width:2px,color:#fff
    style M7 fill:#065f46,stroke:#10b981,stroke-width:2px,color:#fff
    style M8 fill:#065f46,stroke:#10b981,stroke-width:2px,color:#fff
```

---

## 2. Detailed Module Breakdown

### Module 1: Foundation, Architecture, and API Specifications
- **Status:** **COMPLETED & VERIFIED**
- **Objectives:**
  - Establish full project directory layout for FastAPI backend and React frontend.
  - Freeze Pydantic API contracts for `/health`, `/analyze-message`, `/analyze-url`, and `/analyze-qr`.
  - Establish the 4 Unified Classifications: `HIGH RISK`, `MEDIUM RISK`, `LOW RISK`, `UNABLE TO VERIFY`.
  - Define reusable `URLAnalysisService` dependency interface.
  - Implement baseline health and contract tests with `pytest` (12 passing tests).
  - Scaffold React + Vite + TypeScript frontend with honest, non-fabricated landing page.
  - Configure `.gitignore` and `.env.example`.
- **Verification Criteria:**
  - `pytest backend/tests` passes 100%.
  - `npm run build` in `frontend` produces production bundle with 0 errors.
  - `GET /health` returns 200 with `FraudLens` and operational metadata.
  - No ML models trained, no datasets altered, no fake results generated.

---

### Module 2: Dataset Collection, Provenance Verification, Preprocessing, and Validation
- **Status:** **SMS CORPUS COMPLETED & VERIFIED**
- **Completed Work (SMS):**
  - Ingested raw archive `sms+spam+collection(1).zip` (UCI ML Repository / Almeida et al., 2011) into `data/raw/sms/`.
  - Preserved raw files untouched; verified SHA-256 hash `7d039a24a6083ed9ef0f806ebad56bbb976e3aeb8de05669173bfdc4996c239d`.
  - Documented class distribution (4,827 ham / 747 spam, 13.4% spam), missing values (0), and duplicates (414 whitespace-trimmed duplicates).
  - Executed reproducible deduplication to prevent train/test leakage, yielding 5,160 unique samples.
  - Generated stratified 80/10/10 train, validation, and test splits with fixed random seed (42).
  - Produced `sms_train.csv` (4,128 rows), `sms_val.csv` (516 rows), `sms_test.csv` (516 rows), and `provenance_manifest.json`.
  - Verified 0 text leakage across splits via automated tests in `test_dataset_sms.py` (6 passing tests).
- **Phishing URL Datasets Status:**
  - Preserved `data_imbal - 55000.xlsx` and `data_bal - 20000.xlsx` intact in download store for URL module execution.

---

### Module 3: Scam Message Detection Model and Supporting Analysis Features
- **Status:** **COMPLETED & VERIFIED (Features 1–5 Complete End-to-End)**
- **Completed Work (Feature 1):**
  - **Feature 1: ML-Based Scam Classification** — Trained and validated `TfidfVectorizer(ngram_range=(1,2), sublinear_tf=True, max_features=10000)` + `LogisticRegression(C=5.0, class_weight='balanced')` strictly on `sms_train.csv`.
  - Serialized model saved to [`backend/models/message_model.joblib`](file:///D:/Projects/usability/backend/models/message_model.joblib) with metadata in [`backend/models/message_model_metadata.json`](file:///D:/Projects/usability/backend/models/message_model_metadata.json).
  - Built secure loading utility [`MessageModelLoader`](file:///D:/Projects/usability/backend/app/services/message_model_loader.py) with lazy-caching, corruption handling, and honest fallback.
  - Integrated into `POST /analyze-message` without modifying external contracts.
  - Achieved 98.06% accuracy, 90.91% spam precision, 93.75% spam recall, 0.9560 macro F1 on held-out test split (`sms_test.csv`).
  - Unit tests in `test_message_model.py` (9 passing tests).
- **Completed Work (Feature 2):**
  - **Feature 2: Social Engineering Detection** — Implemented dedicated heuristic engine [`SocialEngineeringDetector`](file:///D:/Projects/usability/backend/app/services/social_engineering.py) detecting 7 persuasion categories:
    1. Urgency and artificial deadlines
    2. Threats and consequences (account block, disconnection, penalties)
    3. Impersonation indicators (banks, utilities, couriers, government bodies)
    4. OTP and credential requests (inbound solicitation of secret tokens)
    5. Prize and reward bait (fabricated lotteries, cash prizes, gift bait)
    6. Suspicious payment demands (unpaid bill demands, fee extortion)
    7. Link-click pressure (directives urging immediate external link clicks)
  - Implemented defensive security advisory detection to prevent false alarms on legitimate bank notices (e.g. "never share OTP").
  - Implemented negative context guards against benign usage ("urgent meeting", "pay for lunch").
  - Added structured `HeuristicFinding` schema and extended `SocialEngineeringIndicators` with backward compatibility.
  - Integrated into [`MessageAnalysisService`](file:///D:/Projects/usability/backend/app/services/message_service.py) with multi-evidence risk synthesis without arbitrary weighted scores.
  - Comprehensive unit and integration tests in `test_social_engineering.py` (18 passing tests).
- **Completed Work (Feature 3):**
  - **Feature 3: Suspicious-Phrase Highlighting** — Implemented exact character span extraction engine in [`SocialEngineeringDetector.extract_highlighted_phrases`](file:///D:/Projects/usability/backend/app/services/social_engineering.py):
    - Guaranteed indexing invariant: `original_text[start:end] == phrase == text` using Python 0-indexed contiguous slicing `[start:end]`.
    - Handles Unicode code points, emojis, mixed case, punctuation, and repeated phrase instances.
    - Suppresses highlights for legitimate defensive security advisories ("never share OTP") and guarded benign conversational contexts ("urgent meeting with", "pay for lunch").
    - Updated [`HighlightedPhrase`](file:///D:/Projects/usability/backend/app/schemas/message.py) schema with dual support for (`start`, `end`, `text`, `category`, `explanation`) and legacy aliases (`start_idx`, `end_idx`, `phrase`, `reason`).
    - Built safe, reusable React component [`HighlightedMessage`](file:///D:/Projects/usability/frontend/src/components/HighlightedMessage.tsx) with character-slice interval partitioning (zero `dangerouslySetInnerHTML`, zero duplicate/swallowed characters, accessible WCAG indicators, hover interactive tooltips, and legend breakdown).
    - Verified with 11 dedicated unit and API tests in `test_phrase_highlighting.py`.
- **Completed Work (Feature 4):**
  - **Feature 4: Entity Extraction & Embedded URL Scanning** — Implemented [`EntityExtractor`](file:///D:/Projects/usability/backend/app/services/entity_extractor.py):
    - Extracts URLs (with schemes and naked domains) while properly trimming surrounding sentence punctuation (commas, periods, parens, quotes).
    - Extracts phone numbers (domestic Indian 10-digit mobile and international formats) with digit count validation.
    - Extracts UPI handles (`username@bank`) and clearly differentiates them from ordinary email addresses.
    - Preserves exact positional character offsets in `EntitySpan` records: `text[span.start:span.end] == span.raw_text`.
    - Automatically routes embedded URLs through the reusable [`URLAnalysisService`](file:///D:/Projects/usability/backend/app/services/url_service.py) without network egress.
    - Resilient error handling: URL inspection failures never crash message analysis.
    - Unit tests in `test_entity_extraction.py` (10 passing tests).
- **Completed Work (Feature 5):**
  - **Feature 5: Scam Category Identification** — Implemented [`ScamCategoryClassifier`](file:///D:/Projects/usability/backend/app/services/scam_category.py):
    - Categorizes threat typologies into `BANK_KYC`, `DELIVERY`, `JOB`, `PRIZE`, `INVESTMENT`, or `UNKNOWN`.
    - Maps to readable labels (Bank/KYC, Delivery, Job, Prize, Investment, Unknown).
    - Contextual indicators require positive coercion/threat/fee patterns rather than isolated words.
    - Safeguards suppress scam classifications for legitimate bank security advisories, genuine delivery notifications, and conversational contexts.
    - Supports `candidate_categories` for multi-signal messages and deterministic confidence calculation.
    - Unit tests in `test_scam_category.py` (13 passing tests).
- **End-to-End Pipeline Integration & Verification:**
  - Integrated all 5 sub-features into [`MessageAnalysisService.analyze_message`](file:///D:/Projects/usability/backend/app/services/message_service.py).
  - Multi-evidence risk synthesis enforces that no single probability score dictates a verdict without heuristic corroboration.
  - Verified across 10 real-world benchmark scenarios in `test_end_to_end_scam_scenarios.py` (11 passing tests).
  - Complete backend test suite: **90 passed**.
  - Interactive dashboard tester [`MessageAnalyzer`](file:///D:/Projects/usability/frontend/src/components/MessageAnalyzer.tsx) updated with category badges, entity cards, and embedded URL previews.
  - Frontend production build (`tsc -b && vite build`) verified clean (0 errors).

---

### Module 4: Phishing URL Dataset Preparation & Validation
- **Status:** **COMPLETED & VERIFIED**
- **Completed Work:**
  - Ingested and cryptographically verified raw candidate datasets:
    - Primary candidate `data_imbal - 55000.xlsx`: 55,000 raw rows, SHA-256 `5373af0d...` (49,991 legit / 4,878 phishing deduplicated).
    - Comparison candidate `data_bal - 20000.xlsx`: 20,000 raw rows, SHA-256 `58e4654e...` (19,836 clean rows).
    - UCI reference candidate `phishing(1).csv`: 11,055 rows of pre-engineered tabular attributes (retained for reference, no raw URLs).
  - Executed cross-dataset set intersection discovering **14,761 URLs (74.4% of `data_bal`) overlap directly with `data_imbal`**, identifying a critical data leakage hazard.
  - Implemented normalization pipeline trimming whitespace, quotes, and redundant trailing slashes without altering case or query strings.
  - Produced stratified 80/10/10 train/val/test partitions (`url_train.csv`: 43,895 rows, `url_val.csv`: 5,487 rows, `url_test.csv`: 5,487 rows) with fixed seed `42` maintaining exact 8.89% phishing ratio.
  - Produced leakage-isolated stress test split `url_stress_test_bal_unique.csv` (4,672 clean phishing URLs with strictly 0 overlap with `data_imbal`).
  - Recorded cryptographic SHA-256 digests in [`provenance_manifest.json`](file:///D:/Projects/usability/data/processed/urls/provenance_manifest.json) and compiled [`docs/datasets.md`](file:///D:/Projects/usability/docs/datasets.md).
  - Implemented 12 automated unit and integration tests in `test_dataset_url.py` verifying zero cross-split leakage, deterministic seeding, and raw source immutability.

---

### Module 5: Phishing URL Detection Model and Supporting Analysis Features
- **Status:** **COMPLETED & VERIFIED (Features 1–5 Complete End-to-End)**
- **Completed Work:**
  - **Feature 1: ML-Based Phishing Classification** — Engineered 34 deterministic lexical and structural features (lengths, character counts, ratios, subdomain depth, entropy, sensitive tokens, scheme, ports, IP detection). Trained `RandomForestClassifier(n_estimators=150, max_depth=30, min_samples_split=4, class_weight='balanced_subsample', random_state=42)` on `url_train.csv` (43,895 samples). Calibrated optimal decision threshold $t = 0.45$ on validation split (`url_val.csv`).
  - Serialized model saved to [`backend/models/url_model.joblib`](file:///D:/Projects/usability/backend/models/url_model.joblib) with full training metadata in [`backend/models/url_model_metadata.json`](file:///D:/Projects/usability/backend/models/url_model_metadata.json).
  - Built secure loading utility [`URLModelLoader`](file:///D:/Projects/usability/backend/app/services/url_model_loader.py) with lazy caching, singleton pattern, and safe fail-safe fallback.
  - **Feature 2: Typosquatting & Brand Impersonation** — Built deterministic brand lookalike engine checking 24 high-profile brands (PayPal, Apple, Google, Amazon, Microsoft, SBI, etc.) via Levenshtein edit distance, compound domain tokens, and subdomain/path brand spoofing.
  - **Feature 3: Domain & URL Forensics** — Parsed hostname, registered domain, TLD suffix, path, query parameters, and IP address status strictly offline using `tldextract` snapshot cache without network egress.
  - **Feature 4: Explainable Risk Indicators** — Structured transparent indicators categorizing model features, heuristics, and verified evidence.
  - **Feature 5: Threat Intelligence Abstraction** — Integrated with `ThreatIntelService` interface with graceful fallback.
  - **Measured Test Split Results (`url_test.csv`, 5,487 rows, evaluated once):**
    - Accuracy: **96.87%**
    - Macro F1: **0.9038**
    - ROC-AUC: **0.9807**
    - PR-AUC: **0.9009**
    - Phishing Precision: **81.98%** (405 TP / 89 FP)
    - Phishing Recall: **82.99%** (405 TP / 83 FN)
    - Phishing F1: **0.8248**
    - Legitimate Precision: **98.34%** / Recall: **98.22%** / F1: **0.9828**
    - False Positive Rate (FPR): **1.78%** (89 false alarms out of 4,999 legitimate URLs)
    - False Negative Rate (FNR): **17.01%** (83 misses out of 488 phishing URLs)
  - **Stress Test Split Results (`url_stress_test_bal_unique.csv`, 4,672 rows):**
    - Out-of-Distribution Phishing Detection Rate: **86.90%** (4,060 / 4,672 detected).
    - Limitation explicitly documented: contains no legitimate URLs; specificity/FPR cannot be measured on this set.
  - **API & UI Integration:**
    - Updated `POST /analyze-url` endpoint and `URLAnalysisService` with multi-evidence risk synthesis and statistical humility.
    - Created interactive React component [`URLAnalyzer`](file:///D:/Projects/usability/frontend/src/components/URLAnalyzer.tsx) with benchmark presets, model probability bar, typosquatting card, forensics breakdown, and explainable indicators.
  - **Verification:**
    - 25 dedicated unit and API tests in `test_url_features.py`, `test_url_model.py`, and `test_url_api.py`.
    - Total backend test suite: **128 passed**, 0 failed.
    - Frontend production build (`tsc -b && vite build`): **0 errors**.

---

### Module 6: QR Code Safety Scanner & UPI Inspection
- **Status:** **COMPLETED & VERIFIED (Features 1–5 Complete End-to-End)**
- **Completed Work:**
  - **Feature 1: Dual Optical QR Decoding & Strict Payload Classification** — Built dual-engine computer vision decoding service (`cv2.QRCodeDetector` + `pyzbar`) with automatic Otsu contrast thresholding fallback. Classifies payloads into `URL`, `UPI_PAYMENT`, `WIFI_CONFIGURATION`, `PHONE_OR_CONTACT`, `EMAIL_OR_MESSAGE`, `PLAIN_TEXT`, `OTHER_SUPPORTED_SCHEME`, `UNSUPPORTED_OR_UNRECOGNIZED`, and `UNREADABLE`. Enforces strict file validation (PNG, JPEG, WEBP, BMP), dimension caps ($\le 4096\times 4096$), and maximum upload size (5MB).
  - **Feature 2: Safe Hidden Destination Preview** — Safely displays decoded target destination, protocol scheme, and security context without automated browser navigation, remote asset fetching, or code execution.
  - **Feature 3: Integrated Phishing URL Analysis** — Directly passes QR-extracted URLs into `URLAnalysisService` reusing the trained Random Forest model (34 lexical features, calibrated threshold $t=0.45$), Levenshtein typosquatting detector, and domain forensics breakdown.
  - **Feature 4: UPI Payment Safety Inspection** — Safely extracts UPI payment parameters (`pa`, `pn`, `am`, `cu`, `tn`, `mc`, `tr`, `url`). Validates numeric amount formatting and VPA syntax; flags coercive social engineering patterns (KYC freeze threats, penalty fees, lottery claim fees) as `HIGH RISK`; enforces strict disclaimer that syntactic validity does not prove recipient legitimacy.
  - **Feature 5: Multi-QR Detection & Safe Error Handling** — Decodes multiple QR codes present in a single image; synthesizes aggregate classification according to highest-risk invariant (`HIGH RISK` > `MEDIUM RISK` > `UNABLE TO VERIFY` > `LOW RISK`). Corrupt, blank, or unreadable images fail safely to `UNABLE TO VERIFY` with zero crashes.
  - **Frontend Integration:** Built interactive React component [`QRScanner`](file:///D:/Projects/usability/frontend/src/components/QRScanner.tsx) featuring drag-and-drop upload, image preview, 5 one-click benchmark presets ([`qr_presets.json`](file:///D:/Projects/usability/frontend/src/assets/qr_presets.json)), UPI forensics card, URL phishing preview, and multi-symbol breakdown.
  - **Verification:**
    - 20 dedicated unit and integration tests in `test_qr_scanner.py` verifying all payload categories, UPI parsing, multi-QR detection, image constraints, and zero network egress.
    - Total backend test suite: **148 passed**, 0 failed.
    - Frontend production build (`tsc -b && vite build`): **0 errors**.

---

### Module 7: Unified Risk Classification Engine & Threat Intelligence
- **Status:** **COMPLETED & VERIFIED (Features 1–5 Complete End-to-End)**
- **Completed Work:**
  - **Feature 1: Unified Evidence Model Hierarchy** — Created shared, standardized evidence representation distinguishing:
    - `MODEL_PREDICTION`: Statistical ML model probability scores (TF-IDF Logistic Regression, 34-feature Random Forest).
    - `HEURISTIC`: Deterministic local rules (IP hosts, brand lookalikes, sensitive tokens, UPI coercive memos, persuasion tactics).
    - `CONFIRMED_THREAT_INTEL`: Explicit, attributable vendor matches from external intelligence providers.
    - `INFORMATIONAL`: Structural forensics, benign status notices, and educational disclaimers.
    - Each evidence item tracks `source`, `severity` (`HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`), `status` (`CONFIRMED`, `INCONCLUSIVE`, `STALE`, `UNAVAILABLE`), timestamps, provider lookup timestamp, indicator ID, and cache status.
  - **Feature 2: Pluggable Threat Intelligence Provider Integration** — Built provider adapter architecture [`BaseThreatIntelAdapter`](file:///D:/Projects/usability/backend/app/services/threat_intel.py):
    - `VirusTotalAdapter`: VirusTotal API v3 adapter using URL identifier SHA-256 / Base64 lookups, tracking malicious, suspicious, harmless, and undetected engine counts.
    - `URLScanAdapter`: URLScan.io API v1 adapter performing domain-only queries with overall verdict and score parsing.
    - Official HTTP headers, API keys sourced from environment variables (`THREAT_INTEL_VIRUSTOTAL_API_KEY`, `THREAT_INTEL_URLSCAN_API_KEY`), never exposed to frontend.
    - Graceful degradation: Zero crashes on timeouts (5.0s default), 429 rate-limiting, or host unreachability; returns structured telemetry without labeling targets safe.
  - **Feature 3: Strict Privacy & Data Minimization** — Built [`sanitize_url_for_lookup`](file:///D:/Projects/usability/backend/app/services/threat_intel.py):
    - Completely strips embedded credentials (`username:password@`).
    - Filters out sensitive query parameters (`token`, `secret`, `auth`, `pass`, `session`, `otp`, `cred`, `key`, `code`, `pin`).
    - Enforces invariant: Message bodies, UPI payment details, user credentials, and decoded QR strings are NEVER transmitted externally.
  - **Feature 4: Freshness Tracking & Thread-Safe TTL Caching** — Implemented [`ThreatIntelCache`](file:///D:/Projects/usability/backend/app/services/threat_intel.py):
    - Thread-safe memory lock (`threading.Lock`), configurable TTL (default 3,600s), and capacity cap (1,000 entries with LRU eviction).
    - Stale tracking: Entries exceeding TTL are flagged with status `STALE` and elapsed age telemetry instead of silently treated as fresh.
    - Invariant: Transient failures, 429 rate limits, and unconfigured lookups are strictly prohibited from polluting the cache as clean verdicts.
  - **Feature 5: Unified Multi-Factor Risk Synthesis Engine** — Built [`UnifiedRiskEngine`](file:///D:/Projects/usability/backend/app/services/risk_engine.py):
    - Invariant: Confirmed threat intelligence match immediately escalates verdict to `HIGH RISK` regardless of model score.
    - Invariant: Contextual defensive/educational security advisory guards ("never share OTP") suppress false alarms to `LOW RISK`.
    - Invariant: Missing ML model artifacts fail safe to `UNABLE TO VERIFY`.
    - Invariant: Statistical humility — Absence of threat reports is not proof of safety (`(Note: LOW RISK is not an absolute guarantee of safety)`).
    - Multi-QR code aggregation: Preserves highest severity item across multi-barcode images.
    - Wired directly into `URLAnalysisService`, `MessageAnalysisService`, and `QRScannerService` while preserving 100% backward compatibility.
  - **Frontend Integration:**
    - Updated [`frontend/src/types/api.ts`](file:///D:/Projects/usability/frontend/src/types/api.ts) with unified evidence types and enriched threat intel telemetry.
    - Built reusable [`UnifiedEvidenceViewer`](file:///D:/Projects/usability/frontend/src/components/UnifiedEvidenceViewer.tsx) rendering structured category pills, severity badges, cache indicators, and status indicators.
    - Built [`ThreatIntelCard`](file:///D:/Projects/usability/frontend/src/components/ThreatIntelCard.tsx) displaying provider status, vendor breakdowns (Malicious / Suspicious / Harmless), and cache telemetry.
    - Integrated across `URLAnalyzer.tsx`, `MessageAnalyzer.tsx`, `QRScanner.tsx`, and `ArchitectureRoadmap.tsx`.
  - **Verification:**
    - 25 new dedicated unit and integration tests in `test_threat_intel.py` (16 tests) and `test_risk_engine.py` (9 tests).
    - Total backend test suite: **173 passed**, 0 failed across 17 test modules.
    - Frontend production build (`tsc -b && vite build`): **0 errors** (built cleanly in 1.96s).

---

### Module 8: Frontend Dashboard, End-to-End Verification, and System Telemetry
- **Status:** **COMPLETED & VERIFIED (Full Frontend Integration & End-to-End Verification)**
- **Completed Work:**
  - **Feature 1: Real API Gateway Integration & Centralized Config** — Created centralized API configuration [`frontend/src/api.ts`](file:///D:/Projects/usability/frontend/src/api.ts) with `API_BASE_URL` defaulting to `http://127.0.0.1:8000` (configurable via `VITE_API_URL`). Connected all interactive modules (`MessageAnalyzer.tsx`, `URLAnalyzer.tsx`, `QRScanner.tsx`, `App.tsx`, `Header.tsx`) to real backend endpoints.
  - **Feature 2: Standardized User Experience & 4 Canonical Classifications** — Enforced platform-wide four-tier risk taxonomy (`HIGH RISK`, `MEDIUM RISK`, `LOW RISK`, `UNABLE TO VERIFY`) across all views. Preserved raw model confidence as diagnostic telemetry while never rendering numerical scores as the sole primary verdict.
  - **Feature 3: Strict Privacy & Sensitive Token Sanitization** — Sanitized sensitive URL query parameters (tokens, session IDs, passwords, PINs, OTPs, JWTs) in frontend previews (`•••••••• (Redacted)`) and enforced that user inputs, credentials, UPI secrets, and QR payloads are never transmitted to unauthorized external services.
  - **Feature 4: End-to-End Verification Suite** — Created comprehensive 25-test integration suite [`backend/tests/test_e2e_stage8.py`](file:///D:/Projects/usability/backend/tests/test_e2e_stage8.py) validating:
    - Platform health check reporting operational status across all four subsystems.
    - Scam message detection for benign text, compound scams, embedded phishing URLs, educational security advisories, empty/whitespace inputs, and long inputs.
    - Phishing URL detection for authoritative domains, typosquatting brands, raw IP hosts, dangerous schemes (`javascript:`, `data:`), sensitive query parameters, confirmed threat intel matches, and TTL cache hits.
    - QR safety scanner for benign URLs, phishing lookalikes, UPI prepopulated amounts, plain text, Wi-Fi configs, multi-barcode aggregation, blank image fallbacks, corrupt files, and oversized uploads.
    - Unified evidence model and actionable recommendations invariants.
  - **Feature 5: Production Build & Asset Synchronization** — Synchronized UI badges, module roadmaps, telemetry cards, and system status banners. Updated `README.md` and `docs/implementation-plan.md`.
- **Verification Results:**
  - Full backend test suite: **225 passed**, 0 failed (`pytest backend/tests`).
  - Frontend production build (`tsc -b && vite build`): **0 errors**.
  - Live API smoke test: Confirmed 200 responses on `/health`, `/analyze-message`, `/analyze-url`, and `/analyze-qr`.
