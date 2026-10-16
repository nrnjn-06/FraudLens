# FraudLens — Unified ML-Based Fraud Detection Platform

[![Python](https://img.shields.io/badge/Python-3.10%20--%203.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6.svg)](https://www.typescriptlang.org/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC.svg)](https://tailwindcss.com/)
[![scikit--learn](https://img.shields.io/badge/scikit--learn-1.4%2B-F7931E.svg)](https://scikit-learn.org/)
[![Tests](https://img.shields.io/badge/Tests-225%20Passing-success.svg)]()

> **FraudLens** is an integrated machine-learning platform designed to evaluate and explain digital fraud indicators across three modern threat vectors: **Scam Messages**, **Phishing URLs**, and **Deceptive QR Codes**.

---

## 1. Project Overview & Scope

Modern deception exploits cognitive vulnerabilities through multiple digital channels. FraudLens combines natural language processing, structural URL feature engineering, and computer vision payload inspection under a standardized, transparent risk assessment engine.

### The Three Core Modules

#### Module 1: Scam Message Detection (TF-IDF + Logistic Regression)
- **ML Scam Classification:** Classifies SMS, email, and chat messages using statistical n-gram frequencies and model probabilities.
- **Social Engineering Heuristics:** Detects 7 psychological manipulation tactics: artificial urgency, coercive threats, authority impersonation, credential harvesting (OTP/PIN), prize bait, coercive payments, and link pressure.
- **Defensive Advisory Guard:** Recognizes legitimate educational bank notices (*"Never share your OTP"*) and suppresses false alarms.
- **Suspicious Phrase Highlighting:** Extracts exact character offset spans `[start, end]` so the user interface can visually highlight warning signals.
- **Entity Extraction:** Parses monetary figures, phone numbers, and UPI handles; automatically routes embedded URLs to the phishing detector.
- **Scam Typology Identification:** Categorizes threats into Banking/KYC, Delivery, Job Offer, Lottery/Prize, Investment/Crypto, and Government/Tax scams.

#### Module 2: Phishing URL Detection (34-Feature Random Forest)
- **34-Feature Lexical & Structural ML:** Evaluates Shannon entropy, length ratios, digit densities, sensitive path tokens (`login`, `verify`), and subdomain depth.
- **Live Domain Intelligence (RDAP / WHOIS):** Queries open ICANN RDAP registries to determine domain registration age; flags domains created $<30$ days ago.
- **Levenshtein Typosquatting Engine:** Detects lookalike homoglyphs and brand spoofing targeting major institutions (with academic `.ac.in` and government `.gov.in` false-alarm exemptions).
- **Context-Aware Safety Recommendations:** Maps impersonated brands to verified official portals (e.g., pointing victims of fake bank links to the genuine bank website).
- **Threat Intelligence Feed Adapter:** Modular adapters for VirusTotal and URLScan with thread-safe in-memory caching (optional, disabled by default).

#### Module 3: QR Code Safety Scanner (Dual-Engine CV & UPI Forensics)
- **Dual Computer Vision Decoding:** Decodes optical barcodes via PyZbar with automated fallback to OpenCV's `QRCodeDetector` and adaptive threshold preprocessing.
- **Hidden Destination Preview:** Displays decoded links and payloads safely without automatic navigation or browser execution.
- **Integrated URL Handoff:** Decoded web links are automatically fed into the 34-feature Phishing URL analyzer.
- **Deep UPI Payment Forensics:** Parses `upi://pay` URI parameters (`pa`, `pn`, `am`, `tn`) to flag deceptive transaction notes (e.g., notes claiming "Cashback" on outward payment requests).
- **Safe Handling:** Provides honest `UNABLE TO VERIFY` verdicts for non-standard, low-contrast, or corrupted barcode images.

---

## 2. Unified 4-Level Risk Classification System

FraudLens outputs exactly one of four canonical classifications across all detection modules:

| Classification | Meaning | Action Recommended |
| :--- | :--- | :--- |
| **`HIGH RISK`** | Confirmed threat, credential-harvesting trap, severe typosquatting, or high ML scam probability. | Strictly avoid clicking, downloading, or disclosing credentials. |
| **`MEDIUM RISK`** | Anomalous structure, newly registered domain, or moderate coercive urgency warranting caution. | Exercise heightened caution; verify destination independently. |
| **`LOW RISK`** | Standard legitimate web patterns, benign conversational context, or verified educational advisories. | Maintain standard awareness (not an absolute safety guarantee). |
| **`UNABLE TO VERIFY`** | Unreadable barcode symbol, missing input, or offline external service. | Never assume safety; verify via official channels. |

---

## 3. Technology Stack

- **Frontend:** React 19, Vite, TypeScript, Tailwind CSS, Lucide Icons
- **Backend:** Python 3.10 – 3.14, FastAPI, Uvicorn, Pydantic v2
- **Machine Learning:** scikit-learn, pandas, NumPy, Joblib
- **Computer Vision:** OpenCV, PyZbar, Pillow
- **Database:** SQLite (file-based, serverless)
- **Testing:** pytest, pytest-cov, httpx

---

## 4. Repository Structure

```
usability/
├── backend/
│   ├── app/
│   │   ├── main.py                # FastAPI gateway & CORS configuration
│   │   ├── config.py              # Application settings & environment loader
│   │   ├── schemas/               # Pydantic v2 API request & response contracts
│   │   ├── services/              # Core detection, ML loaders, heuristics & risk engine
│   │   └── routers/               # Endpoints: /health, /analyze-message, /analyze-url, /analyze-qr, /auth/*
│   ├── models/                    # Trained production ML model artifacts & metadata
│   │   ├── message_model.joblib   # TF-IDF + Logistic Regression model (~170 KB)
│   │   ├── message_model_metadata.json
│   │   ├── url_model.joblib       # 34-feature Random Forest model (~9.5 MB)
│   │   └── url_model_metadata.json
│   ├── scripts/                   # Model training and dataset inspection reproducibility scripts
│   ├── tests/                     # 21 automated test suites (225 passing tests)
│   └── requirements.txt           # Python dependencies
├── frontend/
│   ├── index.html                 # HTML application entry point
│   ├── package.json               # Node dependencies & build scripts
│   ├── vite.config.ts             # Vite bundler configuration
│   ├── tailwind.config.js         # Tailwind CSS styling configuration
│   └── src/                       # React 19 components, API client, and pages
├── docs/                          # Authoritative technical guides and reports
│   ├── FRAUDLENS_TECHNICAL_GUIDE.md # Comprehensive developer guide & viva walkthrough
│   ├── architecture.md            # System architecture and telemetry specifications
│   ├── datasets.md                # Dataset provenance, sourcing, and preprocessing splits
│   └── implementation-plan.md     # System modules and architectural specifications
├── data/                          # Local runtime data directory (SQLite db ignored by git)
├── .env.example                   # Sanitized configuration template
├── .gitignore                     # Strict exclusions (local db, caches, large data)
└── README.md                      # Primary project overview
```

---

## 5. Quickstart & Installation

### Prerequisites
- **Python:** Version 3.10, 3.11, 3.12, 3.13, or 3.14
- **Node.js:** Version 18.0.0 or higher (with `npm`)

---

### Step 1: Clone and Configure Environment

```bash
# Clone your repository
git clone https://github.com/your-username/fraudlens.git
cd fraudlens

# Copy the sanitized environment template
cp .env.example .env
```

---

### Step 2: Set Up and Run the Backend

```bash
# 1. Install backend dependencies
pip install -r backend/requirements.txt

# 2. Run the automated test suite (225 tests across 21 suites)
pytest backend/tests

# 3. Start the FastAPI development server
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

* **Interactive OpenAPI Swagger Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **System Health Telemetry:** [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

### Step 3: Set Up and Run the Frontend

Open a new terminal window:

```bash
# 1. Navigate to frontend directory
cd frontend

# 2. Install dependencies
npm install

# 3. Verify production build
npm run build

# 4. Start local development server
npm run dev
```

* **Web Application Dashboard:** [http://localhost:5173](http://localhost:5173)

---

## 6. Machine Learning Models & Reproducibility

* **Pre-trained Production Models Included:** The production model artifacts ([`message_model.joblib`](backend/models/message_model.joblib) and [`url_model.joblib`](backend/models/url_model.joblib)) are tracked in the repository. The application is immediately functional after cloning without needing to retrain.
* **Retraining from Scratch (Optional):** If you wish to reproduce or retrain the models:
  ```bash
  python backend/scripts/train_sms_model.py
  python backend/scripts/train_url_model.py
  ```

---

## 7. Authentication & Local Database Architecture

* FraudLens features server-side user authentication (`/auth/signup`, `/auth/login`, `/auth/logout`, `/auth/me`).
* Passwords are encrypted using **PBKDF2-HMAC** with random 32-byte salts across 100,000 iterations.
* User accounts and session tokens are stored locally in a serverless **SQLite** database (`data/fraudlens_auth.db`).
* **Database Auto-Initialization:** On first launch, the application automatically initializes the required tables if the database does not exist.
* **Privacy by Design:** `data/*.db` is excluded in `.gitignore` so that local account details and session tokens are never committed to source control.

---

## 8. Privacy & External Service Disclosure

* **Scam Message Detection:** Runs **100% locally and offline**. No message text, phone numbers, or extracted parameters are sent to external servers.
* **QR Code Scanner:** Runs **100% locally and offline** using OpenCV and PyZbar. No images are transmitted externally.
* **Domain Age & Registration Intelligence:** Queries the open standard **ICANN RDAP** service (`https://rdap.org/domain`) to inspect domain creation dates. This is a public registry lookup (similar to DNS) and does not transmit credentials or message content.
* **Threat Intelligence Feeds (VirusTotal / URLScan):** Optional integrations that are **disabled by default** (`THREAT_INTEL_ENABLED=False`). When enabled, URLs are strictly sanitized by `sanitize_url_for_lookup()` to strip user credentials, session IDs, and query tokens before querying external feeds.

---

## 9. Testing & Quality Assurance

FraudLens includes an extensive automated test suite covering unit tests, contract validation, and end-to-end integration scenarios:

```bash
# Run complete test suite
pytest backend/tests -v
```

**Test Coverage Summary (225 passing tests):**
- `test_auth.py` — Credential validation, salt generation, session lifecycle.
- `test_contracts.py` — Pydantic schema validation and HTTP status codes.
- `test_message_model.py` — TF-IDF model inference, probability calibration, fallback handling.
- `test_social_engineering.py` — 7 coercion categories, advisory guards, phrase extraction.
- `test_url_features.py` — 34 structural and lexical URL feature extractors.
- `test_url_model.py` — Random Forest phishing classifier inference.
- `test_domain_intelligence.py` — RDAP parsing, domain age scoring, TLS verification, cache TTL.
- `test_recommendation_engine.py` — Verified official links, brand matching, context-aware advice.
- `test_qr_scanner.py` — Computer vision decoding, UPI payment URI inspection, invalid image handling.
- `test_risk_engine.py` — Dynamic weight normalization, composite scoring, deterministic hard overrides.
- `test_e2e_pipeline.py` — Multi-vector end-to-end user workflows.

---

## 10. Responsible Use Disclaimer

FraudLens is an educational and assistive cybersecurity tool designed to help users identify potential digital deception. While the platform combines high-accuracy machine learning, real-time domain age verification, and expert heuristic rules, **no automated fraud detection system can guarantee 100% detection of all zero-day threats or sophisticated state-sponsored attacks**. 

Users should always exercise personal vigilance, independently verify unexpected communications, and consult official organizational channels before transferring funds or disclosing sensitive credentials.
