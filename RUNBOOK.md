<p align="center">
  <img src="./public/assets/branding/lucid-icon-256.png" alt="LUCID Logo" width="72" height="72">
</p>

# LUCID

<p align="center">
  <strong>Clarity Through the Chaos.</strong><br>
  <strong>RUNBOOK</strong><br>
  <em>Operations & Deployment</em><br><br>
  <strong>Version 1.0</strong><br>
  September 2026<br><br>
  <strong>LUCID Documentation Suite</strong>
</p>

---

## Document Information

### Purpose

This runbook explains how to operate, deploy, verify, and troubleshoot LUCID. It is intended for developers or maintainers who need to run the application locally, validate the production deployment, understand required Google Cloud and Firebase configuration, and perform safe release checks without changing the frozen security-analysis logic.

### Intended Audience

- Project maintainer
- Developer/operator
- Technical reviewer
- Cloud deployment reviewer

### Related Documents

- [`README.md`](./README.md)
- [`docs/PROJECT_OVERVIEW.md`](./docs/PROJECT_OVERVIEW.md)
- [`docs/USER_GUIDE.md`](./docs/USER_GUIDE.md)
- [`docs/LUCID_Project_Technical_Handbook.pdf`](./docs/LUCID_Project_Technical_Handbook.pdf)
- [`docs/LUCID_ACCURACY_TEST_REPORT.md`](./docs/LUCID_ACCURACY_TEST_REPORT.md)
- [`docs/LUCID_ACCURACY_TEST_CASES.md`](./docs/LUCID_ACCURACY_TEST_CASES.md)

### Table of Contents

1. Operating Principles
2. Production Environment
3. Local Development Setup
4. Google Cloud Configuration
5. Firebase Configuration
6. Application Startup
7. Validation Commands
8. Benchmark and Validation Commands
9. Deployment Workflow
10. Production Verification Checklist
11. Documentation Synchronization
12. Known Operational Behavior
13. Troubleshooting
14. Release Safety Rules
15. Technical Debt
16. Closing Notes

---

## 1. Operating Principles

LUCID is a cloud-native AI cybersecurity assistant with two user-facing modes: ShieldMe for plain-language security guidance and TIQ for analyst-grade threat intelligence. Operational work should preserve the distinction between application behavior, AI/security-analysis logic, validation evidence, and documentation.

The most important operational rule is that the validated analyzer is frozen unless a deliberate regression cycle is started. Documentation, assets, and release packaging may be updated, but security-analysis changes must not be made casually.

### Frozen Analyzer

```text
lib/analyzeLucidContent.js
```

Authoritative SHA-256:

```text
148aa252fd1279fb6591087b860c0322512e846c8d6ef353904058f6e5bb3c25
```

Before a final release, verify the hash:

```bash
shasum -a 256 lib/analyzeLucidContent.js
```

If this hash changes unexpectedly, stop and inspect the change before continuing.

---

## 2. Production Environment

### Canonical Production Application

```text
https://lucid-dmhlvl2qqa-uc.a.run.app
```

### Current Validated Cloud Run Revision

```text
lucid-00013-xwc
```

### Google Cloud Project

```text
project-c48afffb-501b-4711-a6d
```

### Region

```text
us-central1
```

### Runtime Summary

| Layer | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript single-page app |
| Backend | Node.js / Express |
| AI | Vertex AI Gemini 2.5 Flash |
| Authentication | Firebase Authentication with Google Sign-In |
| Database | Firestore |
| Deployment | Cloud Run |
| Build | Cloud Build |
| Container Artifact | Artifact Registry |
| Image/File Processing | Sharp, multer, pdf-parse, mammoth, csv-parse |

---

## 3. Local Development Setup

### Prerequisites

Install or confirm:

- Node.js 18+
- npm
- Google Cloud CLI
- Firebase project configuration
- Application Default Credentials for Google Cloud access

### Install Dependencies

From the project root:

```bash
npm install
```

### Authenticate Google Cloud ADC

Vertex AI access depends on Application Default Credentials.

```bash
gcloud auth application-default login
```

Confirm the active project:

```bash
gcloud config list
```

If the project is not correct:

```bash
gcloud config set project project-c48afffb-501b-4711-a6d
```

---

## 4. Google Cloud Configuration

LUCID uses Google Cloud for AI inference, deployment, artifact storage, and application hosting.

### Required Services

| Service | Purpose |
|---|---|
| Cloud Run | Hosts the Node.js application |
| Vertex AI | Provides Gemini model access |
| Firestore | Stores incidents, risks, and analysis metadata |
| Cloud Build | Builds container images |
| Artifact Registry | Stores built container artifacts |
| IAM / ADC | Provides authenticated server access to Google Cloud APIs |

### Operational Notes

- Vertex AI calls are made in `us-central1`.
- Gemini model used by the application is `gemini-2.5-flash`.
- API keys are not used for Gemini access in this project; Application Default Credentials are required.
- Cloud Run deploys the containerized Express application.

---

## 5. Firebase Configuration

LUCID uses Firebase Authentication for Google Sign-In and Firebase Admin verification on the backend.

### Required Firebase Settings

1. Enable Firebase Authentication.
2. Enable Google Sign-In provider.
3. Add authorized domains for local and production use.
4. Deploy Firestore rules.
5. Ensure authenticated users have isolated Firestore access.

### Production Authorized Domain

The production domain must be allowed in Firebase Authentication settings:

```text
lucid-dmhlvl2qqa-uc.a.run.app
```

If sign-in fails in production with an unauthorized-domain style error, add the domain in Firebase Console:

```text
Firebase Console → Authentication → Settings → Authorized domains
```

No redeploy is required after adding the authorized domain.

### Firestore Rules Deployment

```bash
firebase deploy --only firestore:rules
```

### Firestore Indexes Deployment

```bash
firebase deploy --only firestore:indexes
```

---

## 6. Application Startup

### Start Locally

```bash
npm start
```

The local server normally runs at:

```text
http://localhost:3000
```

### Basic Local Page Check

Open the browser at:

```text
http://localhost:3000
```

Expected result:

- LUCID loads.
- Sign-in button appears if not authenticated.
- ShieldMe and TIQ modes are available after sign-in.

---

## 7. Validation Commands

### Syntax Checks

Run these before any release:

```bash
node --check server.js
node --check public/script.js
node --check lib/analyzeLucidContent.js
node --check lib/analyzeFileContent.js
```

### Analyzer Hash Check

```bash
shasum -a 256 lib/analyzeLucidContent.js
```

Expected hash:

```text
148aa252fd1279fb6591087b860c0322512e846c8d6ef353904058f6e5bb3c25
```

### Whitespace Check

```bash
git diff --check
```

This should produce no output.

### Benchmark ID Leakage Check

Production code must not contain benchmark-specific IDs or answer lookup logic.

```bash
grep -rn "TC-\|GEN-\|ADV-" lib/ server.js
```

Expected result:

- No benchmark ID references in production analyzer or server logic.
- Benchmark cases should remain in test scripts and documentation, not production decision logic.

---

## 8. Benchmark and Validation Commands

These commands require Google Cloud credentials and will call Vertex AI.

### Core Regression Suite

```bash
node scratch/run_accuracy_suite.js
node scratch/evaluate_results.js
```

### Generalization Suite

```bash
node scratch/run_generalization_suite.js
node scratch/evaluate_generalization.js
```

### Adversarial Suite

```bash
node scratch/run_adversarial_suite.js
node scratch/evaluate_adversarial.js
```

### File Pipeline Smoke Test

```bash
node scratch/test_file_pipeline.js
```

### Expected Current Validation Summary

| Validation Area | Current Result |
|---|---:|
| Primary benchmark: Core + Generalization + Adversarial | 68/74 strict PASS = 91.9% |
| ShieldMe primary benchmark | 74/74 successful outcomes |
| File pipeline smoke validation | 19/19 PASS |
| Extended file validation | 17/17 PASS |
| Wireshark screenshot validation | 16/16 PASS |

The file-pipeline, extended-file, and Wireshark validations are separate evidence streams and should not be added to the 74-case primary benchmark as if they were one combined accuracy score.

---

## 9. Deployment Workflow

### Pre-Deployment Checklist

Before deploying:

- Confirm application logic changes are intentional.
- Confirm frozen analyzer hash if no AI/security changes are expected.
- Run syntax checks.
- Run `git diff --check`.
- Review `git status --short`.
- Verify documentation links and production URL references.
- Confirm the production URL is the canonical URL.

### Build and Deploy

Typical Cloud Run deployment flow:

```bash
gcloud builds submit --tag us-central1-docker.pkg.dev/project-c48afffb-501b-4711-a6d/lucid/lucid

gcloud run deploy lucid \
  --image us-central1-docker.pkg.dev/project-c48afffb-501b-4711-a6d/lucid/lucid \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated
```

The exact Artifact Registry repository/image path may vary depending on current Google Cloud configuration. Confirm the active project and Artifact Registry path before running deployment commands.

### Confirm Cloud Run Service

```bash
gcloud run services describe lucid --region us-central1
```

Verify:

- Service name: `lucid`
- Region: `us-central1`
- URL: `https://lucid-dmhlvl2qqa-uc.a.run.app`
- Latest revision matches the intended release

---

## 10. Production Verification Checklist

After deployment, verify the live application instead of assuming deployment success.

### Browser Checks

1. Open the production URL.
2. Confirm the app loads.
3. Sign in with Google.
4. Run a ShieldMe analysis.
5. Run a TIQ analysis with the same evidence.
6. Confirm correlated incident behavior in the TIQ Dashboard.
7. Open the incident details modal.
8. Add analyst notes and change status.
9. Verify file upload analysis.
10. Verify Wireshark screenshot analysis.
11. Open Help and confirm expanded topics are present.

### Expected Production Behaviors

- Sign-in works after Firebase authorized-domain configuration.
- ShieldMe displays plain-language verdict and next steps.
- TIQ displays classification, severity, key indicators, reasoning, MITRE mapping, and SOC actions.
- Same evidence analyzed in ShieldMe and TIQ can correlate into one active incident.
- Resolved incidents are not reused for new analysis.
- File analysis displays the file safety limitation.
- Wireshark scan-only evidence is not over-escalated to confirmed compromise or C2.

---

## 11. Documentation Synchronization

LUCID keeps canonical documentation in `docs/` and deployed-app documentation in `public/docs/`.

### Canonical Documentation

```text
docs/USER_GUIDE.md
docs/LUCID_ACCURACY_TEST_REPORT.md
docs/LUCID_ACCURACY_TEST_CASES.md
```

### Deployed-App Documentation Copies

```text
public/docs/USER_GUIDE.md
public/docs/LUCID_ACCURACY_TEST_REPORT.md
public/docs/LUCID_ACCURACY_TEST_CASES.md
```

Whenever one of these canonical docs changes, copy the same updated content into the matching `public/docs/` file.

### User Guide Image Assets

GitHub/repository docs:

```text
docs/assets/user-guide/
```

Deployed app docs:

```text
public/docs/assets/user-guide/
```

Both should contain the same User Guide figure files.

---

## 12. Known Operational Behavior

### No `/health` Endpoint

LUCID currently does not expose a `/health` route.

This command:

```bash
curl https://lucid-dmhlvl2qqa-uc.a.run.app/health
```

may return:

```text
Cannot GET /health
```

That is expected unless a health endpoint is intentionally added later.

Use the root route and production UI behavior for basic smoke verification.

### Vertex AI SDK Deprecation Warning

The current `@google-cloud/vertexai` SDK path may emit a deprecation warning indicating removal in 2026 and recommending migration to `@google/genai`.

This is tracked as technical debt. Do not migrate during documentation finalization. A future SDK migration should be treated as an application change and followed by full regression testing.

### Prompt Injection Handling

Uploaded or pasted content is untrusted evidence. Prompt-injection text inside uploaded content should be treated as data, not instruction. This is a core design assumption of the analysis pipeline.

### File Analysis Limitation

LUCID safely extracts readable content from supported files, but it does not execute files or perform full dynamic malware analysis.

Required limitation text:

```text
LUCID analyzed the content it could read from this file. This does not guarantee that the entire file is safe.
```

Unsupported, unreadable, or ambiguous files should not be automatically treated as safe.

---

## 13. Troubleshooting

| Issue | Likely Cause | Resolution |
|---|---|---|
| Google Sign-In fails in production | Production domain not authorized in Firebase | Add `lucid-dmhlvl2qqa-uc.a.run.app` to Firebase authorized domains |
| Vertex AI request fails locally | ADC missing or wrong project selected | Run `gcloud auth application-default login` and confirm `gcloud config list` |
| Firestore permission error | Rules/indexes not deployed or user document missing | Deploy rules/indexes and confirm authenticated user context |
| `/health` returns 404 | No health endpoint exists | This is expected; verify the root app URL instead |
| File upload rejected | Unsupported type or size above limit | Use supported file type and keep uploads within size limits |
| PDF extraction fails | PDF is scanned/encrypted/unreadable | Treat as inconclusive or use external verification |
| Wireshark scan classified as C2 | Evidence wording may imply beaconing or compromise | Verify screenshot evidence; scan-only evidence should remain Active Scanning/Medium |
| Dashboard incident not updating | Incident may be Resolved or outside 24-hour correlation window | New analysis should create a new incident |
| Documentation images do not render | Asset path missing in `docs/assets` or `public/docs/assets` | Copy `assets/user-guide` folder into both locations |

---

## 14. Release Safety Rules

Before committing or pushing final work:

1. Do not modify `lib/analyzeLucidContent.js` unless explicitly reopening AI/security logic.
2. Do not restore the frozen analyzer from Git HEAD if the validated hash differs from repository history.
3. Do not use broad delete commands during cleanup.
4. Do not publish private notes or temporary debug artifacts.
5. Do not claim universal security accuracy.
6. Do not combine separate validation suites into an inflated single accuracy number.
7. Do not document roadmap items as current capabilities.
8. Do not replace current production screenshots with old UI screenshots.
9. Do not add competition-specific references inside permanent product documentation.
10. Do not commit until the final repository cleanup pass is complete.

---

## 15. Technical Debt

| Area | Current Status | Future Action |
|---|---|---|
| Vertex AI SDK | Current SDK path emits deprecation/removal warning | Migrate to `@google/genai` and rerun all regression suites |
| File coverage | MVP supports common readable formats | Add XLSX, email formats, archive recursion, macro extraction, native PCAP |
| Dynamic malware behavior | Files are not executed | Add sandbox/dynamic analysis only with strict safety controls |
| Threat intelligence | No live reputation enrichment in MVP | Add IOC, URL reputation, domain age, and external intelligence enrichment |
| Observability | Basic deployment/log checks | Add structured latency, error, model-cost, and request monitoring |
| Enterprise security | Single-user-per-org model | Add RBAC, audit logs, SSO/SAML, enterprise tenant management |
| Fingerprinting | Text fingerprint collapses whitespace | Improve code-sensitive fingerprinting for whitespace-sensitive evidence |

---

## 16. Closing Notes

This runbook is intentionally operational. It does not replace the Technical Handbook, User Guide, Accuracy Report, or Test Cases. Its purpose is to help a maintainer safely run, verify, deploy, troubleshoot, and release LUCID without accidentally changing the validated analyzer or publishing incomplete/private artifacts.

