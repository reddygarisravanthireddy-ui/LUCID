<div align="center">
  <img src="../public/assets/branding/lucid-icon-256.png" alt="LUCID Logo" width="86" height="86">

# LUCID

### *Clarity Through the Chaos.*

<br>

# PROJECT OVERVIEW

### Vision & Solution

<br>

**Version 1.0**  
**September 2026**

<br>

**LUCID Documentation Suite**
</div>

---

# Document Information

## Purpose

This document provides a high-level overview of **LUCID**, including the problem it addresses, the solution it provides, the major features of the application, the cloud architecture, the validation approach, the project evolution, and the future roadmap. It is intended to help reviewers, developers, security professionals, and users understand the value of LUCID without needing to inspect the full implementation details first.

## Intended Audience

- Product reviewers and evaluators
- Developers reviewing the repository
- Security professionals assessing the concept
- Everyday users who want to understand the purpose of LUCID
- Future maintainers of the project

## Related Documents

| Document | Purpose |
|---|---|
| `README.md` | Short GitHub landing page and quick introduction |
| `docs/USER_GUIDE.md` | User-focused walkthrough of the application |
| `docs/LUCID_Project_Technical_Handbook.pdf` | Detailed architecture and implementation handbook |
| `docs/LUCID_ACCURACY_TEST_REPORT.md` | Validation methodology and benchmark results |
| `docs/LUCID_ACCURACY_TEST_CASES.md` | Complete test case evidence and expected outcomes |
| `RUNBOOK.md` | Deployment, operations, and troubleshooting guide |

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Negative Impact if the Problem Is Not Solved](#3-negative-impact-if-the-problem-is-not-solved)
4. [Why LUCID Exists](#4-why-lucid-exists)
5. [Solution Overview](#5-solution-overview)
6. [Core User Personas](#6-core-user-personas)
7. [Key Features](#7-key-features)
8. [What Makes LUCID Different](#8-what-makes-lucid-different)
9. [Supported Evidence Types](#9-supported-evidence-types)
10. [Architecture Overview](#10-architecture-overview)
11. [Google Cloud Services Used](#11-google-cloud-services-used)
12. [AI Design](#12-ai-design)
13. [Security and Privacy Approach](#13-security-and-privacy-approach)
14. [Validation Summary](#14-validation-summary)
15. [Project Evolution](#15-project-evolution)
16. [Future Roadmap](#16-future-roadmap)
17. [Conclusion](#17-conclusion)

---

# 1. Executive Summary

Cybersecurity evidence is often difficult to understand. A suspicious email, a login alert, a payment request, a source-code snippet, a document upload, or a Wireshark screenshot may contain signals of real risk, but those signals are not always obvious to the person receiving them. Everyday users may not know whether to ignore the message, report it, or take urgent action. Security analysts, on the other hand, often need a deeper technical view: attack classification, severity, indicators, MITRE ATT&CK context, and response guidance.

**LUCID** was built to reduce that gap.

LUCID is an AI-powered cybersecurity assistant that explains confusing security evidence in a way that matches the needs of different users. It provides two complementary experiences:

- **ShieldMe** helps everyday users understand whether something looks safe, suspicious, dangerous, or inconclusive, using plain language and practical next steps.
- **TIQ** supports technical analysts with structured security analysis, including classification, severity, MITRE ATT&CK mappings, key indicators, reasoning, unknowns, and response actions.

The key idea behind LUCID is not simply to “ask AI about security.” LUCID combines a dual-persona interface, controlled output schemas, deterministic safeguards, file extraction controls, incident correlation, risk tracking, and a cloud-native deployment model. The same evidence can be interpreted for an ordinary user and also converted into analyst-ready intelligence.

LUCID supports multiple evidence types, including text, suspicious messages, screenshots, security alerts, PDFs, DOCX files, CSV files, logs, source code, and Wireshark screenshots. Uploaded files are treated as data and are not executed. When the application cannot safely read or confidently assess a file, it avoids falsely labeling the evidence as safe.

The current production release is deployed on Google Cloud Run and uses Vertex AI Gemini, Firebase Authentication, Firestore, and a Node.js backend. Validation has been performed across core, generalization, adversarial, file-analysis, and Wireshark-specific test suites. The final primary benchmark reached **68/74 strict PASS = 91.9%**, with **6 PARTIAL** and **0 FAIL**, while separate file and Wireshark validation suites confirmed the new evidence-handling workflows.

LUCID’s purpose is simple: **turn confusing cybersecurity evidence into clear, useful, and action-oriented security understanding.**

---

# 2. Problem Statement

Cybersecurity threats increasingly target both individuals and organizations. Phishing messages, fake login alerts, business email compromise attempts, suspicious attachments, malicious links, exposed credentials, vulnerable code, and unusual network traffic can all appear in daily workflows. However, recognizing and responding to these threats requires context that many users do not have.

A major problem is that security evidence is often presented in one of two extremes:

1. **Too technical for everyday users.**  
   Alerts may include IP addresses, authentication failures, HTTP requests, MITRE technique IDs, command-line artifacts, or file indicators without explaining what they mean in plain language.

2. **Too simplified for analysts.**  
   Some tools provide a generic risk label but do not include enough classification, severity reasoning, indicators, or investigation context for a security analyst to take action.

This creates a usability gap. Everyday users need clear explanations and safe next steps. Analysts need structured intelligence and evidence. A single explanation style does not work for both groups.

There is also an operational problem. Security evidence often arrives in fragmented forms: screenshots, messages, logs, code snippets, documents, and network captures. Without a unified workflow, users may need separate tools for every evidence type. Analysts may also waste time reinvestigating duplicate evidence if related findings are not correlated.

LUCID addresses this problem by giving users a single platform that can safely process different evidence types and produce audience-specific cybersecurity analysis.

---

# 3. Negative Impact if the Problem Is Not Solved

If users cannot understand cybersecurity evidence clearly, the consequences can be serious.

Everyday users may ignore a real phishing attempt because it looks routine. They may click a malicious link, approve a fraudulent payment request, share credentials, or fail to report a suspicious message. They may also panic over harmless alerts because they do not know how to evaluate the situation.

Security analysts face a different but related problem. They may spend valuable time manually interpreting repetitive alerts, reviewing duplicate evidence, or translating raw data into investigation notes. If severity is overestimated, teams waste time on low-priority activity. If severity is underestimated, real threats may remain unresolved.

The broader impact includes:

- Higher risk of fraud, account compromise, and data exposure.
- Delayed response to genuine security incidents.
- Increased alert fatigue and investigation workload.
- Inconsistent triage decisions across users and analysts.
- Reduced trust in security tools because findings are difficult to interpret.
- Missed opportunities to educate users at the moment they encounter a threat.

LUCID helps reduce these risks by making security analysis easier to understand, more structured, and more actionable.

---

# 4. Why LUCID Exists

LUCID was created around one principle: **cybersecurity should be understandable without losing technical accuracy.**

Many security tools are built primarily for experts. They may be powerful, but they often assume that the user already understands security terminology, attack patterns, and response workflows. LUCID takes a different approach by supporting two levels of interpretation from the same evidence.

For everyday users, LUCID aims to answer questions such as:

- Is this message safe or dangerous?
- What signs make it suspicious?
- What should I do next?
- Should I click, reply, download, pay, or report?

For analysts, LUCID aims to answer deeper questions such as:

- What type of attack is this?
- How severe is it?
- What indicators support the classification?
- Which MITRE ATT&CK techniques are relevant?
- What actions should a SOC analyst take?
- What is known, unknown, and uncertain?

This dual-persona design is the foundation of LUCID. It allows the same platform to serve both non-technical users and technical teams without forcing one audience to use the other audience’s language.

---

# 5. Solution Overview

LUCID is a web-based cybersecurity assistant that accepts security evidence and returns structured analysis. The application is designed as a cloud-native system with a browser-based frontend, Node.js backend, Vertex AI Gemini model integration, Firebase Authentication, and Firestore persistence.

The solution has four major layers:

1. **User Interface Layer**  
   Users interact with LUCID through ShieldMe or TIQ. ShieldMe focuses on plain-language safety guidance. TIQ focuses on analyst-grade investigation output.

2. **Evidence Processing Layer**  
   LUCID accepts text, screenshots, documents, logs, source code, and Wireshark screenshots. Uploaded files are validated, safely extracted, and treated as data.

3. **AI Reasoning Layer**  
   Vertex AI Gemini is used to analyze submitted evidence and produce structured JSON outputs. The backend applies schema expectations, normalization, and guardrails to keep results consistent.

4. **Investigation Workflow Layer**  
   Firestore stores analysis records, incidents, risks, and workflow state. Incident correlation connects matching evidence within defined boundaries so analysts do not repeatedly investigate the same event.

At a high level, LUCID works like this:

```text
User submits evidence
        ↓
Frontend sends evidence to backend
        ↓
Backend validates and preprocesses input
        ↓
AI + deterministic safeguards analyze the evidence
        ↓
ShieldMe or TIQ result is generated
        ↓
Analysis is stored and correlated into incidents
        ↓
Users review history, dashboard, risks, and resolution workflow
```

This design makes LUCID more than a one-time chatbot response. It becomes a structured security workflow.

---

# 6. Core User Personas

## 6.1 ShieldMe — Everyday User Mode

ShieldMe is designed for people who are not cybersecurity specialists. Its goal is to explain suspicious evidence in plain language and provide safe next steps.

ShieldMe is useful when a user receives:

- A suspicious email or text message.
- A fake login alert.
- A payment or gift-card request.
- A screenshot of a warning or pop-up.
- A document or file that may be unsafe.
- A message that feels suspicious but is difficult to judge.

ShieldMe avoids unnecessary jargon. Instead of focusing on technical labels first, it explains what is suspicious, why the user should care, and what action to take.

Typical ShieldMe outputs include:

- Verdict: Safe, Suspicious, Dangerous, or Inconclusive.
- Plain-language explanation.
- Practical next steps.
- A reminder that important cases should still be verified through trusted channels.

## 6.2 TIQ — Technical Analyst Mode

TIQ is designed for users who need deeper security context. It is intended for analysts, security students, developers, and technical reviewers.

TIQ provides:

- Threat classification.
- Severity assessment.
- MITRE ATT&CK mappings.
- Key indicators.
- Technical reasoning.
- Attack-chain context.
- Recommended SOC actions.
- Confidence and unknowns.

TIQ is useful for investigating:

- Authentication attacks.
- Phishing and business email compromise.
- PowerShell or command-line activity.
- SQL injection indicators.
- Suspicious network traffic.
- Malicious or vulnerable code.
- Security alert screenshots.
- Uploaded logs and documents.

Together, ShieldMe and TIQ allow LUCID to support both accessibility and technical depth.

---

# 7. Key Features

## 7.1 Dual-Mode Analysis

LUCID’s most important feature is its dual-mode design. The same evidence can be analyzed in ShieldMe for plain-language guidance or in TIQ for analyst-level output.

**Why it matters:** A non-technical user and a SOC analyst should not receive the same explanation. ShieldMe reduces confusion. TIQ preserves technical depth.

## 7.2 Multimodal Evidence Analysis

LUCID can analyze multiple forms of evidence, including text, screenshots, documents, logs, source code, and Wireshark screenshots.

**Why it matters:** Security evidence does not arrive in one format. A practical security assistant must handle different forms of input without forcing the user to manually convert everything first.

## 7.3 File Analysis Pipeline

LUCID supports safe analysis of common file types such as PDFs, DOCX files, CSV files, TXT/log files, Markdown files, and source-code files.

Uploaded files are treated as data and are not executed. LUCID extracts readable content where possible, performs static checks, sends relevant evidence to the AI analysis pipeline, and clearly communicates limitations.

**Why it matters:** Many real attacks arrive as attachments or documents. A file-aware assistant is more useful than a text-only assistant.

## 7.4 Wireshark Screenshot Analysis

LUCID can analyze Wireshark screenshots as visual evidence. It can identify patterns such as scanning, suspicious traffic, failed lookups, or possible command-and-control behavior when the visual evidence supports those conclusions.

**Why it matters:** Network evidence is commonly shared as screenshots in learning, triage, and incident-review contexts. LUCID helps users interpret that evidence without requiring them to be packet-analysis experts.

## 7.5 Incident Correlation

When the same evidence is analyzed in both ShieldMe and TIQ, LUCID correlates the result into a single incident instead of creating unnecessary duplicates, as long as the evidence matches the active correlation conditions.

**Why it matters:** Analysts often waste time reviewing repeated reports of the same event. Correlation makes the workflow cleaner and more realistic.

## 7.6 TIQ Dashboard

The TIQ Dashboard gives analysts a centralized view of incidents, risks, and patterns. It supports incident review, status tracking, severity visibility, and investigation workflow.

**Why it matters:** A security assistant becomes more valuable when findings are organized into an investigation workspace rather than disappearing after one response.

## 7.7 My Checks

My Checks gives ShieldMe users a history of their recent analyses. It helps everyday users revisit previous results without needing to resubmit the same evidence.

**Why it matters:** Security decisions often require follow-up. A user may want to return to an earlier result before taking action.

## 7.8 Risk Register

The Risk Register allows analysts to track identified risks, including description, category, priority, and status. It supports editing and deletion.

**Why it matters:** Security findings should not only be analyzed; they should be tracked until they are understood or resolved.

## 7.9 Pattern Detection

Pattern Detection helps identify recurring activity or related findings across analyses.

**Why it matters:** Individual events can appear minor in isolation. Patterns help analysts understand whether activity may represent a broader campaign or repeated behavior.

## 7.10 Multi-Tenant Security Model

LUCID uses authenticated user identity to isolate each user’s data. Firestore access is scoped so one user cannot read or modify another user’s records.

**Why it matters:** A security application must protect the evidence and results it processes. Isolation is essential even in an MVP.

---

# 8. What Makes LUCID Different

LUCID is different because it is not limited to a single AI response style or a single evidence type.

| Traditional Security Workflow | LUCID Approach |
|---|---|
| Security alerts are difficult for non-experts to understand | ShieldMe translates evidence into plain language |
| Analysts must manually convert evidence into structured investigation notes | TIQ returns classification, severity, indicators, MITRE mappings, and response actions |
| Different evidence types require separate tools | LUCID supports text, screenshots, documents, logs, code, and Wireshark screenshots |
| Duplicate investigations waste time | Incident Correlation links matching active evidence |
| Results often disappear after analysis | Dashboard, My Checks, and Risk Register preserve workflow context |
| AI output may overclaim without enough evidence | LUCID uses evidence-first reasoning and communicates uncertainty |

The most important difference is the combination of **accessibility, technical depth, and workflow continuity**. LUCID is designed to help users understand evidence, act on it, and track it.

---

# 9. Supported Evidence Types

LUCID supports the following evidence categories in the current MVP:

| Evidence Type | Example Use |
|---|---|
| Plain text | Suspicious messages, alerts, commands, logs |
| Emails and message content | Phishing, BEC, credential theft attempts |
| URLs and domains | Suspicious links or login pages |
| Screenshots | Security alerts, pop-ups, phishing messages |
| Wireshark screenshots | Network scanning, suspicious traffic, possible C2 patterns |
| PDF documents | Suspicious documents or reports |
| DOCX files | Office-style document inspection |
| CSV files | Structured logs or exported security data |
| TXT / Markdown / logs | Raw indicators, authentication logs, application logs |
| Source code | Vulnerable or suspicious code snippets |

LUCID’s file analysis has deliberate safety boundaries. It reads supported content where possible, but it does not execute uploaded files. Unsupported or unreadable content should not be treated as automatically safe.

---

# 10. Architecture Overview

LUCID follows a modular cloud-native architecture.

```text
Browser Frontend
  ├── ShieldMe mode
  ├── TIQ mode
  ├── File/image upload UI
  ├── My Checks
  └── TIQ Dashboard
        ↓
Node.js Backend API
  ├── Input validation
  ├── File extraction pipeline
  ├── Image preprocessing
  ├── AI request orchestration
  ├── Output normalization
  └── Incident correlation
        ↓
Vertex AI Gemini
  ├── Plain-language ShieldMe analysis
  └── Technical TIQ analysis
        ↓
Firestore
  ├── Analysis records
  ├── Incidents
  ├── Risks
  └── User-scoped data
        ↓
Google Cloud Run
  └── Production deployment
```

The architecture separates user experience, evidence processing, AI reasoning, persistence, and deployment. This makes the system easier to maintain and easier to extend.

The production application is deployed at:

```text
https://lucid-dmhlvl2qqa-uc.a.run.app
```

---

# 11. Google Cloud Services Used

LUCID uses Google Cloud and Firebase services to support deployment, AI inference, authentication, and data persistence.

| Service | Role in LUCID | Why It Was Chosen |
|---|---|---|
| Google Cloud Run | Hosts the Node.js web application | Supports containerized deployment with scalable managed infrastructure |
| Vertex AI Gemini | Provides AI analysis and reasoning | Enables multimodal, language-based security interpretation |
| Firebase Authentication | Handles Google Sign-In | Simplifies secure user authentication |
| Firestore | Stores analyses, incidents, risks, and user-scoped data | Provides flexible document storage for investigation workflows |
| Cloud Build | Builds and deploys container revisions | Supports repeatable production deployment |
| Artifact Registry | Stores container images | Provides managed image storage for Cloud Run deployment |

Google Cloud was selected because LUCID benefits from managed infrastructure, AI model access, authentication integration, and scalable deployment without needing to maintain custom servers.

---

# 12. AI Design

LUCID uses AI as an interpretation layer, not as an uncontrolled replacement for human judgment.

The AI design follows several principles:

## 12.1 Audience-Specific Output

ShieldMe and TIQ use different output expectations. ShieldMe focuses on clarity, verdict, explanation, and next steps. TIQ focuses on classification, severity, MITRE mapping, indicators, reasoning, response actions, confidence, and unknowns.

## 12.2 Evidence-First Reasoning

LUCID is designed to avoid overclaiming. For example, an exploit attempt should not automatically be treated as confirmed compromise unless the submitted evidence supports that conclusion.

## 12.3 Structured Responses

The backend expects structured outputs so the frontend can render results consistently. This improves reliability compared with free-form AI responses.

## 12.4 Uncertainty Handling

When evidence is incomplete, unsupported, or unreadable, LUCID should communicate uncertainty rather than provide a false sense of safety.

## 12.5 Prompt-Injection Awareness

Uploaded content is treated as evidence, not as instructions. This is especially important when analyzing suspicious documents, messages, or logs that may contain malicious or manipulative language.

---

# 13. Security and Privacy Approach

LUCID processes sensitive security evidence, so the application includes several protective design choices.

## Authentication

Firebase Authentication is used to require sign-in and associate data with an authenticated user.

## Tenant Isolation

The backend derives organization/user scope from authenticated identity. Firestore rules and server-side checks prevent cross-user access to incidents and risks.

## Safe File Handling

Uploaded files are validated and processed through a safe extraction pipeline. They are not executed.

## Rate Limiting

The backend includes rate limiting to reduce abuse and accidental overuse.

## Evidence Handling

Evidence is used to produce security analysis and incident workflow records. The documentation advises users not to upload unnecessary secrets, passwords, or sensitive personal data.

## Responsible AI Use

LUCID is an assistant. It does not replace human judgment, professional incident response, or formal forensic review. Important decisions should be verified through trusted channels and appropriate security processes.

---

# 14. Validation Summary

LUCID was validated using multiple evaluation sets to test accuracy, generalization, adversarial robustness, file handling, and network screenshot interpretation.

| Evaluation Area | Result | Purpose |
|---|---:|---|
| Primary benchmark | **68/74 strict PASS = 91.9%** | Measures final core, generalization, and adversarial analysis performance |
| Core regression suite | **24/26 PASS = 92.3%** | Confirms expected behavior on known representative cases |
| Generalization suite | **18/18 PASS = 100%** | Tests unseen cases and transfer beyond the original benchmark |
| Adversarial suite | **26/30 PASS = 86.7%** | Tests ambiguous, evasive, and difficult scenarios |
| File smoke validation | **19/19 PASS** | Confirms supported file pipeline behavior |
| Extended file validation | **17/17 PASS** | Confirms additional file edge cases |
| Wireshark validation | **16/16 PASS** | Confirms network screenshot handling |

The primary benchmark result should be interpreted as a controlled project evaluation, not as a universal cybersecurity accuracy claim. File and Wireshark validation results are reported separately and are not combined into the primary 74-case AI benchmark.

The detailed methodology and results are documented in:

- `docs/LUCID_ACCURACY_TEST_REPORT.md`
- `docs/LUCID_ACCURACY_TEST_CASES.md`

---

# 15. Project Evolution

LUCID improved through multiple engineering stages. The project did not begin as a complete incident-management platform; it evolved through testing, feedback, and feature expansion.

| Stage | What Changed | Why It Mattered |
|---|---|---|
| Initial prototype | Basic AI-assisted security analysis | Proved that AI could explain suspicious security evidence |
| Dual-persona design | Added ShieldMe and TIQ modes | Allowed the same evidence to support both everyday users and analysts |
| Benchmark correction | Established a corrected baseline of 42.3% strict PASS on the original core suite | Created an honest starting point for improvement |
| First major optimization | Improved core performance to 69.2% strict PASS | Addressed classification, severity, and reasoning weaknesses |
| Generalization expansion | Added unseen test cases | Tested whether improvements transferred beyond the original cases |
| Adversarial hardening | Added ambiguous and difficult scenarios | Reduced overclaiming and improved robustness |
| File analysis pipeline | Added safe extraction for supported documents, logs, CSVs, code, and PDFs | Expanded LUCID beyond text-only evidence |
| Wireshark screenshot handling | Added network screenshot analysis behavior | Improved multimodal security evidence support |
| Firestore persistence | Stored analyses, incidents, and risks | Turned one-time analysis into ongoing workflow |
| Incident correlation | Linked matching evidence into active incidents | Reduced duplicate investigation work |
| Dashboard and Risk Register | Added analyst workflow features | Supported triage, tracking, and resolution |
| Production deployment | Deployed final application to Cloud Run | Made the system accessible as a live cloud application |

A key design principle throughout this evolution was to improve reasoning without hardcoding individual benchmark answers. Some PARTIAL results were accepted where the evidence did not justify a stronger claim. This helped preserve defensible security reasoning rather than optimizing only for a score.

---

# 16. Future Roadmap

LUCID is designed as a foundation for AI-assisted cybersecurity analysis. Planned future enhancements include:

- **Threat intelligence enrichment** using reputation sources, IOC enrichment, domain intelligence, and URL analysis.
- **Expanded file support** for email files, ZIP archives, Office macros, XLSX files, and additional forensic artifacts.
- **Enterprise SIEM/SOAR integrations** with platforms such as Google SecOps, Splunk, Microsoft Sentinel, and QRadar.
- **Enhanced AI reasoning** with improved explainability, confidence calibration, and multimodal analysis quality.
- **Cross-platform support** through mobile, browser, email, and collaboration-tool integrations.
- **Continuous benchmarking** using larger and more diverse real-world datasets to improve robustness and generalization.

The roadmap is intentionally focused and realistic. It builds on the current modular architecture rather than replacing the system.

---

# 17. Conclusion

LUCID was built to make cybersecurity evidence easier to understand and easier to act on. It addresses a real gap between ordinary users who need clear guidance and analysts who need structured technical intelligence.

By combining ShieldMe, TIQ, multimodal evidence handling, safe file analysis, incident correlation, a dashboard workflow, risk tracking, and cloud-native deployment, LUCID demonstrates how AI can support practical cybersecurity interpretation without removing the need for human verification.

The project’s evolution shows measurable improvement from an early baseline to a stronger validated release. Its final primary benchmark reached **91.9% strict PASS** in controlled testing, while additional file and Wireshark validations confirmed expanded evidence-handling capabilities.

LUCID’s long-term vision is to become a trusted assistant for interpreting suspicious evidence, reducing confusion, supporting analysts, and helping users respond to security risks with clarity.

---

## Documentation Analysis — Final Validation

LUCID now detects software and project documentation as benign content using
content-only signals (Markdown headings, section keywords, and structural
markers). No filename is used in detection.

Markdown, HTML snippets, architecture text, deployment instructions, and
security terminology found inside documentation files are not treated as
malicious unless direct malicious behaviour is present in the content itself.
Raw phishing and malware evidence detection is fully preserved.

**Documentation/threat regression test: 19/19 PASS, 0 FAIL.**

Final analyzer SHA-256:
`009ad4427809bce6b8eaf9f932714587d7bb9e4f425a2d08684c06a18c2b5208`

---

<div align="center">

**LUCID — Clarity Through the Chaos.**

</div>
