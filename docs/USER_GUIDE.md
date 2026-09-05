# LUCID End-User & Analyst Guide

> **AI-Powered Threat Analysis & Security Workspace**  
> *Application URL:* [https://lucid-264271786605.us-central1.run.app/](https://lucid-264271786605.us-central1.run.app/)

---

## 1. LUCID Overview

**LUCID** is an AI-assisted security analysis and decision-support platform designed to analyze untrusted text payloads and visual screenshots (such as emails, SMS messages, login portals, security alerts, and application popups). It helps users evaluate potential security threats using multimodal artificial intelligence.

LUCID features a **dual-persona architecture** tailored for two primary user groups:

### ShieldMe (Everyday Mode)
- **Target Audience:** Non-technical staff, general enterprise employees, and everyday web users.
- **Goal:** Provides quick, plain-English security reassurance.
- **Output:** Color-coded security verdicts (**Safe**, **Suspicious**, **Dangerous**), plain-language explanations, and concrete recommended next steps.

### TIQ — Threat Intelligence Query (Analyst Mode)
- **Target Audience:** SOC analysts, security engineers, and incident response teams.
- **Goal:** In-depth threat categorization and technical investigation.
- **Output:** Standardized threat taxonomy classifications, multi-level severity scoring (**Low**, **Medium**, **High**, **Critical**), key observable indicators, technical reasoning, severity rationales, recommended SOC remediation actions, and evidence-supported MITRE ATT&CK mappings.

---

## 2. Getting Started

Follow these steps to perform an analysis:

1. **Access LUCID:** Navigate to [https://lucid-264271786605.us-central1.run.app/](https://lucid-264271786605.us-central1.run.app/).
2. **Sign In:** Click **Sign in with Google** to authenticate securely via Firebase Authentication.
3. **Select Mode:**
   - Keep the toggle set to **ShieldMe** for standard everyday analysis.
   - Switch the toggle to **TIQ Mode** for technical threat intelligence analysis.
4. **Provide Content:**
   - **Text:** Paste security-related text (email body, SMS text, command log, URL payload, alert message).
   - **Image:** Upload a clear screenshot or visual artifact (PNG, JPG, WebP format, up to 8 MB).
   - **Both:** Submit text and an image simultaneously for multimodal evaluation.
5. **Run Analysis:** Click **Analyze Payload**.
6. **Review Results:** Inspect the verdict/classification, technical breakdown, and recommended security actions.

---

## 3. Using ShieldMe (Everyday Mode)

ShieldMe translates security indicators into simple, clear guidance.

### Security Verdicts

| Verdict | Meaning | Suggested Response |
| :--- | :--- | :--- |
| **SAFE** | The submitted content does not display sufficient indicators of a security threat. | Proceed normally. No immediate security action is required. |
| **SUSPICIOUS** | The content contains unusual or concerning indicators that warrant caution and verification. | Do not click links or share credentials. Verify the source via official channels. |
| **DANGEROUS** | Strong indicators of an active attack, malicious lure, or security risk were detected. | Avoid interaction immediately. Contain the payload and alert your IT/Security team. |

> [!NOTE]
> A **SAFE** verdict indicates that no threat indicators were identified in the submitted evidence. It is **not an absolute guarantee** of safety. Always exercise normal security awareness.

### Result Components
- **Security Verdict:** Prominent color-coded badge (`Safe`, `Suspicious`, `Dangerous`).
- **Explanation:** Plain-English summary explaining why the content received its verdict without technical jargon.
- **Recommended Next Steps:** Clear, bulleted action items for the user to follow.

---

## 4. Using TIQ (Threat Intelligence Query Mode)

TIQ Mode provides structured analysis aligned with industry-standard threat taxonomies and the MITRE ATT&CK framework.

### Severity Levels

| Severity | General Meaning | Typical Security Context |
| :--- | :--- | :--- |
| **LOW** | Routine or expected activity with little to no evidence of threat. | Authentic routine notifications, normal SSO sign-in logs. |
| **MEDIUM** | Limited suspicious or reconnaissance activity without confirmed compromise. | User account enumeration, password-reset oracle probing. |
| **HIGH** | Serious active attack patterns requiring prompt containment. | Active credential phishing, MFA push bombing, BEC attempts. |
| **CRITICAL** | Severe attack with demonstrated critical impact or compromise. | Confirmed remote code execution, web shell uploads, ransomware. |

### Result Components
- **Severity Badge:** Multi-level severity indicator (`Low`, `Medium`, `High`, `Critical`).
- **Threat / Attack Classification:** Canonical security taxonomy string (e.g., *Phishing / Credential Harvesting*, *MFA Fatigue / Push Bombing*, *PowerShell Execution / Obfuscated PowerShell*).
- **Key Observable Indicators:** Bulleted list of the strongest factual indicators extracted from the payload.
- **Technical Reasoning:** Concise, evidence-based technical summary of the observed behavior.
- **Severity Rationale:** Specific justification explaining why the assigned severity was selected based on evidence-first rules.
- **Recommended Security Action:** Prioritized remediation steps for SOC analysts and incident responders.
- **MITRE ATT&CK Mapping:** Standardized technique codes (e.g., `T1566.002`, `T1621`, `T1059.001`) attached **only when supported by observable evidence**.

---

## 5. Image & Screenshot Analysis

LUCID evaluates uploaded screenshots and visual artifacts, such as:

- Email and SMS phishing lures
- Authentication prompts and MFA notifications
- Suspicious login portals and brand impersonation pages
- Security alerts, EDR logs, and popups
- Application permission prompts
- Deceptive security warnings

### Image Analysis Guidelines
- **Supported Formats:** PNG, JPEG, WebP (up to 8 MB).
- **Quality Matters:** Use clear, uncropped screenshots where text, sender headers, URLs, or error codes remain legible.
- **Visual Red-Flag Analysis:** System instructions prompt the multimodal model to inspect uploaded images for visual red flags, including address bar mismatches, fake security warnings, deceptive permission prompts, and text embedded inside images designed to evade text filters.

---

## 6. My Checks History

The **My Checks** tab provides a log of ShieldMe analyses for tracking and reference.

### Persistence Behavior
To keep history focused on checks that require user attention or security follow-up:
- **SUSPICIOUS** results are stored and displayed in your history.
- **DANGEROUS** results are stored and displayed in your history.
- **SAFE** analyses are displayed immediately on-screen after execution, but are **not persisted** to your history log.

> **Note:** My Checks provides a threat-focused history of ShieldMe checks that may need your attention. The absence of `Safe` checks in history is intentional design behavior and does not indicate a system error.

---

## 7. Practical Analysis Examples

Here are realistic scenarios illustrating how LUCID evaluates different payloads:

### Example A: Authentic Security Notification
- **Scenario:** A user receives an official notification regarding a routine password update or legitimate sign-in alert with expected sender domains and no credential links.
- **ShieldMe Result:** `SAFE` — Plain-English explanation confirming routine notification context.
- **TIQ Result:** `LOW` — *Benign / Legitimate Security Notification* or *Benign / Normal Authentication Activity*.

### Example B: Credential Phishing Email
- **Scenario:** An email impersonating a financial institution asks the user to "Verify Your Account Immediately" via an external HTTP link.
- **ShieldMe Result:** `DANGEROUS` — Next steps advise against clicking the link or entering credentials.
- **TIQ Result:** `HIGH` — *Financial Phishing / Brand Impersonation* or *Phishing / Credential Harvesting* (`T1566.002`).

### Example C: MFA Fatigue / Push Bombing
- **Scenario:** An alert reporting 15 consecutive unsolicited authenticator push requests within two minutes.
- **ShieldMe Result:** `DANGEROUS` — Advises denying push requests and changing account password immediately.
- **TIQ Result:** `HIGH` — *MFA Fatigue / Push Bombing* (`T1621`).

### Example D: Business Email Compromise (BEC)
- **Scenario:** An email claiming to be from an executive requesting an urgent direct-deposit bank account update from an external domain.
- **ShieldMe Result:** `DANGEROUS` / `SUSPICIOUS` — Identifies social engineering and fraudulent payment requests.
- **TIQ Result:** `HIGH` — *Business Email Compromise* (`T1566`).

---

## 8. AI Disclaimer & Decision Support

### Application Disclaimer
> **AI-generated analysis can make mistakes. Verify important security decisions.**

### Decision Support Context
LUCID is designed as an **AI-assisted security decision-support tool**. It provides automated analysis based on user-supplied content but should not be treated as an absolute security authority. Critical security decisions, incident containment actions, or account recovery steps should be independently verified using trusted organizational sources, original log telemetry, official communication channels, or qualified security professionals.

---

## 9. Best Security Practices

- **Verify Unexpected Communications:** Always verify unexpected password reset notices, sign-in alerts, or payment requests through official out-of-band channels.
- **Check URLs Carefully:** Inspect domain names in links and browser address bars for spoofing or non-standard TLDs before entering credentials.
- **Out-of-Band Payment Verification:** Never alter banking, payroll, or wire details based solely on an email request without phone verification.
- **Validate Threat Findings:** SOC analysts should cross-reference TIQ findings against SIEM logs, EDR telemetry, and network traffic before taking disruptive containment actions.

---

## 10. System Limitations

- **Evidence Dependence:** Analysis accuracy is directly dependent on the completeness and clarity of the submitted text or image.
- **Contextual Ambiguity:** Complex or partial security logs without surrounding context may yield conservative or partial classifications.
- **Image Legibility:** Blurry, heavily cropped, or low-resolution images may prevent effective optical character recognition.
- **No Substitute for IR Procedures:** LUCID provides analytical decision support but does not replace enterprise Incident Response playbooks or perimeter controls.

---

## 11. Privacy & Data Isolation

- **Authentication:** User access is authenticated via Google Sign-In and validated server-side using Firebase ID tokens.
- **Tenant Isolation:** All saved incident records, risk entries, and dashboard metrics are strictly partitioned by the authenticated user's unique identification ID (`orgId`). Users can only read and write their own data.
- **Database Persistence:** When an incident record is saved to Firestore, LUCID writes structured metadata (including timestamp, analysis mode, verdict/severity, classification, explanation/reasoning, and a truncated 100-character text summary). Full-text payloads and raw image files are not written to the application's Firestore database.

---

## 12. Troubleshooting Guide

| Issue | Potential Cause | Recommended Action |
| :--- | :--- | :--- |
| **Analysis Request Fails** | Network timeout or expired auth session. | Refresh the browser page, re-authenticate if prompted, and retry submission. |
| **Image Upload Rejected** | File size exceeds 8 MB or format unsupported. | Ensure image is PNG, JPEG, or WebP under 8 MB. |
| **Unreadable Image Result** | Image text is blurry or heavily cropped. | Re-take a crisp, full-screen screenshot showing relevant headers and text. |
| **Safe Result Not in My Checks** | Expected platform behavior. | `Safe` checks are displayed immediately on screen but intentionally omitted from persistent history. |

---

## 13. Evaluation & Validation Note

LUCID's analysis engine ([`lib/analyzeLucidContent.js`](../lib/analyzeLucidContent.js)) has undergone project validation across 74 cybersecurity test cases spanning Core, Generalization, and Adversarial evaluation suites. Full evaluation methodology, category breakdowns, and performance metrics are documented in the [LUCID Accuracy Validation Report](./LUCID_ACCURACY_TEST_REPORT.md).
