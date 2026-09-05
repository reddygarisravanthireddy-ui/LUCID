# LUCID — Dual-Persona AI Security & Threat Intelligence Platform

> **Clarity in the face of chaos.**

**LUCID** is an enterprise-grade AI security analysis platform designed to transform complex, multi-vector threat signals into clear, actionable intelligence. It inspects untrusted text payloads and visual artifacts (such as phishing emails, smishing SMS, fake authentication portals, deceptive permission prompts, fraudulent popups, and malicious QR codes) using multimodal AI.

Built on a dual-persona architecture, LUCID delivers tailored experiences for both non-technical everyday users and seasoned SecOps analysts:
- **ShieldMe (Everyday Mode):** Plain-English safety verdicts (`Safe`, `Suspicious`, `Dangerous`), actionable remediation steps, and private, session-scoped check history.
- **TIQ (Threat Intelligence Query Mode):** Industry-standard threat taxonomy classification, multi-level severity scoring (`Low`, `Medium`, `High`, `Critical`), MITRE ATT&CK mapping, technical reasoning, attack progression chains, and an incident management dashboard.

---

## Key Features

### 1. Dual-Persona Architecture
- **ShieldMe Mode:**
  - Designed for end-user reassurance and non-technical staff.
  - Translates complex risk indicators into simple color-coded verdicts: **Safe**, **Suspicious**, or **Dangerous**.
  - Delivers actionable, non-jargon guidance (e.g., *"Do not click the link"*, *"Verify sender domain"*).
  - **My Checks Tab:** Automatically tracks session checks using an anonymous, cookie-free `sessionId` stored in local browser state.
- **TIQ (Threat Intelligence Query) Mode:**
  - Built for SOC analysts and incident response teams.
  - Provides standardized threat taxonomy classification, attack vector analysis, severity rationale, and prioritized SOC actions.
  - Unlocks the **SecOps Dashboard** with 7-day incident trends, 30-day automated pattern aggregation, and an interactive Risk Register.

### 2. Multimodal Threat Inspection
- **Dual Payload Analysis:** Evaluates text alerts, uploaded screenshots, or both simultaneously.
- **Visual Evasion Detection:** Identifies visual spoofing tactics including brand impersonation, URL bar mismatches, rogue mobile app permission popups, fake infection warnings, and malicious QR codes.
- **Client & Server Image Pipeline:**
  - *Client-side:* Downscales images (max 1600px edge), converts to WebP, and validates 8MB upload limits.
  - *Server-side:* Uses `sharp` to strip EXIF metadata and re-encode clean WebP buffers before LLM inference.

### 3. Prompt Injection Defense & Privacy Architecture
- **Untrusted Content Sandboxing:** Wraps user input in `<user_submitted_content>` tags with strict system instructions preventing jailbreak attempts or filter evasion.
- **Visual Red-Flag Enforcement:** Instructs model to treat visual filter-evasion text embedded inside images as a severe security red flag.
- **Privacy-Preserving Storage:** Raw user submissions are never persisted to the database. Only metadata (timestamp, mode, severity, verdict, truncated summary) is stored for verified threats.

### 4. Authentication & Multi-Tenancy
- **Google Sign-In:** Gated authentication using Firebase Client Auth SDK.
- **Token Verification:** Express API routes verify Firebase ID tokens via `firebase-admin`.
- **Tenant Scoping (`orgId`):** All incidents, risks, and dashboard queries are partitioned by the authenticated user's UID (`orgId`).

---

## Architecture Overview

```
                  ┌──────────────────────────────┐
                  │    Browser UI (Vanilla JS)   │
                  └──────────────┬───────────────┘
                                 │ HTTP / JSON (Bearer ID Token)
                                 v
                  ┌──────────────────────────────┐
                  │  Express.js API (server.js)  │
                  └──────────────┬───────────────┘
                                 │
                                 v
                  ┌──────────────────────────────┐
                  │ lib/analyzeLucidContent.js   │
                  └──────────────┬───────────────┘
                                 │
                                 v
                  ┌──────────────────────────────┐
                  │ Vertex AI (Gemini 2.5 Flash) │
                  └──────────────────────────────┘
```

> **Shared Analysis Engine**: Both production API endpoints (`server.js`) and automated benchmark runners (`scratch/`) consume the exact same production module ([`lib/analyzeLucidContent.js`](./lib/analyzeLucidContent.js)), guaranteeing 100% parity between evaluated benchmark accuracy and live production behavior.

---

## Security Architecture

- **Firebase ID Token Verification**: Protected backend endpoints require valid `Bearer <token>` headers.
- **Server-Derived `orgId`**: Tenant scope (`orgId`) is derived server-side from `decodedToken.uid`, preventing client-side header spoofing.
- **Firestore Security Rules**: Strict collection-level rules (`firestore.rules`) enforce `resource.data.orgId == request.auth.uid`.
- **Rate Limiting**: `express-rate-limit` caps requests at 100 per 15-minute window per IP.
- **Sanitization & Escaping**: All dynamic DOM outputs in the frontend are sanitized via `escapeHtml()`. CSV exports sanitize formula injection characters (`=`, `+`, `-`, `@`).

---

## Accuracy & Benchmark Performance

LUCID was evaluated across **74 test cases** in 3 independent suites using the shared production analyzer pipeline ([`lib/analyzeLucidContent.js`](./lib/analyzeLucidContent.js)) at `temperature: 0`:

| Benchmark Suite | Case Count | Strict PASS | PARTIAL | FAIL | Strict PASS Rate |
|---|:---:|:---:|:---:|:---:|:---:|
| **Core Regression Suite** | 26 | 23 | 3 | 0 | **88.5%** |
| **Generalization Suite (Unseen)** | 18 | 18 | 0 | 0 | **100.0%** |
| **Adversarial Suite (Unseen)** | 30 | 27 | 3 | 0 | **90.0%** |
| **Combined Benchmark Total** | **74** | **68** | **6** | **0** | **91.9%** |

### Benchmark Highlights:
- **Exceeded Accuracy Target:** Achieved **91.9% combined strict PASS rate** (68/74 cases), exceeding the 80.0% target by **11.9 percentage points**.
- **ShieldMe Verdict Reliability:** Achieved **100% benchmark PASS** (74/74 cases) across all Everyday Mode evaluations.
- **Zero Failures:** 0 FAIL results across all 74 cases.
- **Safety Metrics:** **0 False Positives** and **0 False Negatives** across the Generalization and Adversarial evaluation suites.
- **Evidence-First PARTIAL Behavior:** All 6 PARTIAL cases (3 Core, 3 Adversarial) reflect LUCID's strict evidence-first policy (e.g. requiring confirmed loss for Critical BEC, or confirmed code execution output for Critical RCE), avoiding benchmark overfitting.

---

## Technology Stack

- **Frontend:** Vanilla HTML5, Vanilla JavaScript (ES6+), Vanilla CSS (Custom dark theme).
- **Backend:** Node.js, Express.js.
- **AI Engine:** Google Cloud Vertex AI (`gemini-2.5-flash`).
- **Database:** Google Cloud Firestore (`@google-cloud/firestore`).
- **Authentication:** Firebase Auth (`firebase-admin`).
- **Image Processing:** `sharp` (WebP re-encoding & EXIF metadata stripping).
- **Containerization & Cloud:** Cloud Run, Cloud Build, Docker.

---

## Running Locally

### 1. Prerequisites
- Node.js v18+
- GCP Project with Vertex AI API & Firestore enabled
- Authenticated Application Default Credentials (ADC):
  ```bash
  gcloud auth application-default login
  ```

### 2. Installation & Execution
```bash
# Install dependencies
npm install

# Start development server
npm start
```
App will start at `http://localhost:3000`.

---

## Testing & Static Validation

### Syntax Validation
```bash
node --check lib/analyzeLucidContent.js
node --check server.js
node --check public/script.js
```

### Benchmark Evaluation (Requires GCP Credentials)
```bash
# Core Regression Suite
node scratch/run_accuracy_suite.js && node scratch/evaluate_results.js

# Generalization Suite
node scratch/run_generalization_suite.js && node scratch/evaluate_generalization.js

# Adversarial Suite
node scratch/run_adversarial_suite.js && node scratch/evaluate_adversarial.js
```

---

## Deployment (Cloud Run)

LUCID is containerized for Google Cloud Run deployment:
```bash
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/lucid-app
gcloud run deploy lucid-app --image gcr.io/YOUR_PROJECT_ID/lucid-app --platform managed --region us-central1
```

---

## Documentation Links

- [**Accuracy & Validation Report**](./docs/LUCID_ACCURACY_TEST_REPORT.md)
- [**Test Case Specification**](./docs/LUCID_ACCURACY_TEST_CASES.md)
- [**Operations Runbook**](./RUNBOOK.md)

---

## Limitations & Technical Considerations

1. **Decision Support:** LUCID provides automated threat intelligence to assist, not replace, qualified human security analyst judgment.
2. **Evidence Dependency:** Classification and severity depend strictly on observable evidence in the alert payload.
3. **Multimodal Parity:** Screenshot analysis requires legible visual threat indicators for optimal classification.
4. **Planned SDK Maintenance:** The current Vertex AI SDK will be migrated to `@google/genai` in future releases.
