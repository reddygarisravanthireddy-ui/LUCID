# LUCID — Dual-Mode AI Security & Threat Intelligence Platform

**LUCID** is an AI-powered security analysis platform that inspects suspicious text and screenshots (e.g., phishing emails, smishing SMS, fake login pages, deceptive permission prompts, fraudulent popups, and malicious QR codes). 

Designed with a dual-persona architecture, LUCID serves both everyday users seeking quick reassurance and security analysts managing enterprise threats:
- **ShieldMe (Everyday Mode):** Plain-English safety verdicts (`Safe`, `Suspicious`, `Dangerous`), actionable advice, and a private, session-scoped history ("My Checks").
- **TIQ (Analyst Mode):** In-depth technical classification, severity ratings (`Low`, `Medium`, `High`, `Critical`), MITRE-aligned reasoning, and a full Incident & Risk Management Dashboard.

---

## Key Features

### 1. Dual-Persona Experience
- **ShieldMe Mode:**
  - Designed for non-technical users.
  - Translates complex threat signals into simple color-coded verdicts: **Safe**, **Suspicious**, or **Dangerous**.
  - Provides clear, non-jargon next steps (e.g., *"Do not click the link"*, *"Verify sender address"*).
  - **My Checks Tab:** Automatically tracks past checks for the current browser session using an anonymous, cookie-free `sessionId` stored in `localStorage`.
- **TIQ (Threat Intelligence Query) Mode:**
  - Tailored for SecOps and security analysts.
  - Provides technical taxonomy, attack vectors, severity scoring, and recommended remediation protocols.
  - Grants access to the **SecOps Dashboard**, featuring incident analytics, pattern detection, and a risk register.

### 2. Multimodal Threat Inspection
- **Flexible Input:** Analyze pasted text, uploaded screenshots, or both simultaneously.
- **Visual Attack Analysis:** Detects visually deceptive tactics, including:
  - Spoofed login interfaces and brand impersonation.
  - Mismatched browser address bars / sender domains.
  - Rogue mobile app permission requests.
  - Fake "Device Infected" system warnings.
  - Deceptive QR codes.
- **Client & Server Image Processing Pipeline:**
  - Client-side pre-processing: Downscales images (max 1600px edge), converts to WebP, and validates 8MB upload limits.
  - Server-side sanitization: Utilizes `sharp` to strip EXIF metadata and re-encode to clean WebP buffers before sending to the model.

### 3. Prompt Injection Defense & Privacy Architecture
- **Untrusted Content Sandboxing:** Analyzed payloads are wrapped inside `<user_submitted_content>` tags with strict system-level instructions preventing model manipulation or jailbreaks.
- **Visual Evasion Resistance:** The model is explicitly instructed to treat text embedded inside images designed to bypass filters as severe security red flags.
- **Privacy-First Persistence:** Raw user submissions are **never** persisted to the database. Only high-level metadata (timestamp, mode, severity, verdict, and truncated summary) is stored for verified threats.

### 4. Authentication & Multi-Tenancy
- **Google Sign-In:** Gated entry using Firebase Client Auth SDK.
- **Route Protection Middleware:** All backend routes verify Firebase ID tokens using `firebase-admin`.
- **Tenant Scoping (`orgId`):** All incident records, risks, and dashboard queries are partitioned by the authenticated user's UID (`orgId`).

### 5. SecOps Dashboard (TIQ Mode)
- **Incident Metrics & Trend Analysis:**
  - Top-line stats: Total incidents, Active open issues, High/Critical alerts.
  - 7-Day incident volume trend.
  - 30-Day automated threat pattern aggregation.
- **Incidents Table:**
  - Fast client-side quick filters: **All**, **Open Only**, and **Critical Only**.
  - **Days Open** metric calculating incident duration.
  - Inline status management (`Open`, `In Progress`, `Resolved`).
  - One-click CSV export (`GET /api/incidents/export`).
- **Risk Register:**
  - Track institutional security risks with Category, Priority, and Status.
  - Compact three-dot (`⋮`) action menu with inline Edit Modal and confirmation-guarded deletion.

---

## Operations & Runbook
For full architecture diagrams, sequence flows, input processing lifecycles, and troubleshooting, refer to [`RUNBOOK.md`](./RUNBOOK.md).


---

## Tech Stack

- **Frontend:** Pure Vanilla HTML5, Vanilla JavaScript (ES6+), Vanilla CSS (Custom dark theme, zero UI framework dependencies).
- **Backend:** Node.js, Express.js.
- **AI Model:** Google Cloud Vertex AI (`gemini-2.5-flash`).
- **Database:** Google Cloud Firestore (`@google-cloud/firestore`).
- **Media Processing:** `sharp` (metadata stripping, resizing, WebP re-encoding).
- **Security & Utilities:** `express-rate-limit`, `cors`.

---

## Project Structure

```
.
├── firestore.indexes.json # Firestore composite index definitions
├── firestore.rules        # Security rules for Firestore collections
├── firebase.json          # Firebase deployment configuration
├── package.json           # Node.js project manifest & dependencies
├── server.js              # Express backend, Vertex AI & Firestore integration
├── public/
│   ├── index.html         # Single-page UI (Analyzer, Dashboard, My Checks)
│   ├── script.js          # Client logic, image handling, dashboard state
│   └── style.css          # Dark-theme design system, layout, responsive styling
└── README.md              # Project documentation
```

---

## Prerequisites

1. **Node.js**: Version 18+ installed.
2. **Google Cloud Project**:
   - A GCP Project with **Vertex AI API** and **Cloud Firestore** enabled.
   - Default project configured in `server.js` (`project-c48afffb-501b-4711-a6d` in `us-central1`).
3. **Application Default Credentials (ADC)**:
   Authenticate locally using the Google Cloud CLI:
   ```bash
   gcloud auth application-default login
   ```

---

## Getting Started

### 1. Install Dependencies
```bash
npm install
```

### 2. Start the Application
```bash
npm start
```
The server will start on port `3000` (or `PORT` environment variable if specified):
```
Server listening on port 3000
```

### 3. Access the UI
Open your browser and navigate to:
```
http://localhost:3000
```

---

## API Reference

### Analysis
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Evaluates submitted text/image payload via Vertex AI. Auto-logs incidents if threat thresholds are exceeded. Rate-limited to 100 req/15 min. |

### Incidents
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/incidents` | Retrieves all logged incidents (supports `?status=` and `?severity=` filters). |
| `GET` | `/api/my-checks` | Retrieves session-specific ShieldMe checks for the requesting browser (`?sessionId=...`). |
| `PATCH` | `/api/incidents/:id` | Updates an incident record (e.g. status transition). |
| `DELETE` | `/api/incidents/:id` | Deletes an incident record. |
| `GET` | `/api/incidents/export` | Generates and streams a CSV export of all recorded incidents. |

### Risk Register
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/risks` | Retrieves all risks from the register. |
| `POST` | `/api/risks` | Creates a new risk entry. |
| `PATCH` | `/api/risks/:id` | Updates risk fields (Description, Category, Priority, Status). |
| `DELETE` | `/api/risks/:id` | Deletes a risk entry. |

### Threat Intelligence
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/patterns` | Aggregates the top recurring threat patterns over the past 30 days. |

---

## License

This project is licensed under the ISC License.
