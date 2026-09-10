<p align="center">
  <img src="./assets/branding/lucid-icon-256.png" alt="LUCID Logo" width="72" height="72">
</p>

# LUCID Documentation Index

> **Clarity Through the Chaos.**  
> Documentation suite for the LUCID AI-powered security analysis platform.

**Version 1.0**  
**September 2026**

---

## Purpose

This folder contains the main reviewer-facing documentation for **LUCID**. It explains what the project is, why it matters, how it works, how users interact with it, how it was validated, and what limitations remain.

LUCID is designed to help two different audiences interpret confusing cybersecurity evidence:

- **ShieldMe** gives everyday users simple verdicts, plain-language explanations, and next steps.
- **TIQ** gives analysts deeper classification, severity, indicators, MITRE ATT&CK mapping, and incident workflow support.

---

## Recommended Reading Order

| Order | Document | Best For | What It Covers |
|---:|---|---|---|
| 1 | [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md) | Reviewers, evaluators, first-time readers | Problem, solution, uniqueness, impact, architecture summary, validation summary |
| 2 | [`USER_GUIDE.md`](./USER_GUIDE.md) | End users, demo viewers, reviewers | How to use ShieldMe, TIQ, uploads, My Checks, Dashboard, Risk Register, Help, and limitations |
| 3 | [`LUCID_Project_Technical_Handbook.pdf`](./LUCID_Project_Technical_Handbook.pdf) | Technical reviewers | Architecture, implementation, security controls, AI pipeline, validation, operations, limitations |
| 4 | [`LUCID_ACCURACY_TEST_REPORT.md`](./LUCID_ACCURACY_TEST_REPORT.md) | Accuracy reviewers | Benchmark methodology, final results, false-positive/false-negative controls, validation interpretation |
| 5 | [`LUCID_ACCURACY_TEST_CASES.md`](./LUCID_ACCURACY_TEST_CASES.md) | Deep technical reviewers | Case-level benchmark details for Core, Generalization, Adversarial, File, and Wireshark validation |
| 6 | [`../RUNBOOK.md`](../RUNBOOK.md) | Maintainers/operators | Local setup, deployment, production checks, troubleshooting, release safety, cleanup checklist |

---

## Main Public Documents

### Project Overview

[`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md)

Use this first when someone needs to understand the project quickly. It explains the problem LUCID solves, why the solution is useful, what makes the idea unique, and how the platform is structured.

Key topics:

- Purpose of LUCID
- Problem and negative impact if unsolved
- Dual-mode approach: ShieldMe and TIQ
- Supported evidence types
- Architecture summary
- Google Cloud usage
- Validation summary
- Short future roadmap

---

### User Guide

[`USER_GUIDE.md`](./USER_GUIDE.md)

Use this for walkthroughs, demos, and reviewer testing. It explains how a user interacts with the deployed application.

Key topics:

- Signing in
- Switching between ShieldMe and TIQ
- Text analysis
- Screenshot/image analysis
- File and document analysis
- Wireshark/network screenshot analysis
- My Checks
- TIQ Dashboard
- Incident correlation
- Analyst notes and resolution workflow
- Risk Register
- Pattern Detection
- Help system
- Safety limitations and responsible-use guidance

Screenshots used by the User Guide are stored here:

```text
docs/assets/user-guide/
```

The deployed app copy uses the matching folder:

```text
public/docs/assets/user-guide/
```

---

### Technical Handbook

[`LUCID_Project_Technical_Handbook.pdf`](./LUCID_Project_Technical_Handbook.pdf)

Use this for the full technical explanation of LUCID. It is the primary long-form reviewer document.

Key topics:

- System architecture
- Frontend/backend structure
- Vertex AI Gemini analysis path
- File processing pipeline
- Multimodal image analysis
- Prompt-injection handling
- Evidence-first reasoning
- Incident correlation
- Dashboard workflow
- Multi-tenancy and Firestore isolation
- Validation methodology
- Known limitations and technical debt
- Reviewer walkthrough

---

### Accuracy Report

[`LUCID_ACCURACY_TEST_REPORT.md`](./LUCID_ACCURACY_TEST_REPORT.md)

Use this when evaluating the reliability of the application.

Current validation summary:

| Validation Area | Result |
|---|---:|
| Primary benchmark: Core + Generalization + Adversarial | **68/74 strict PASS = 91.9%** |
| Primary benchmark PARTIAL | **6/74** |
| Primary benchmark FAIL | **0/74** |
| ShieldMe primary benchmark | **74/74 successful outcomes** |
| File pipeline smoke validation | **19/19 PASS** |
| Extended file validation | **17/17 PASS** |
| Wireshark screenshot validation | **16/16 PASS** |

Important interpretation:

The primary benchmark, file validation, extended file validation, and Wireshark validation are reported separately. They should not be added together into one inflated accuracy score.

---

### Test Cases

[`LUCID_ACCURACY_TEST_CASES.md`](./LUCID_ACCURACY_TEST_CASES.md)

Use this for detailed case-level review.

It documents:

- **26 Core Regression cases**
- **18 Generalization cases**
- **30 Adversarial cases**
- **19 File Pipeline smoke checks**
- **17 Extended File validation checks**
- **16 Wireshark screenshot validation checks**

It also explains the evidence-first PARTIAL policy and why some strict evaluator expectations were intentionally not forced when the submitted evidence did not prove confirmed impact.

---

## Supporting Runtime Documentation

### Operations Runbook

[`../RUNBOOK.md`](../RUNBOOK.md)

The Runbook sits at the repository root because it is an operator-facing project document.

It covers:

- Local setup
- Google Cloud configuration
- Firebase configuration
- Deployment workflow
- Production verification
- Documentation synchronization
- Known operational behavior
- Troubleshooting
- Release safety rules
- Technical debt
- Final cleanup checklist

---

## Documentation Synchronization Rule

Some documentation exists in two locations because the project supports both GitHub/repository browsing and deployed in-app documentation.

Canonical repository docs:

```text
docs/USER_GUIDE.md
docs/LUCID_ACCURACY_TEST_REPORT.md
docs/LUCID_ACCURACY_TEST_CASES.md
```

Deployed app docs:

```text
public/docs/USER_GUIDE.md
public/docs/LUCID_ACCURACY_TEST_REPORT.md
public/docs/LUCID_ACCURACY_TEST_CASES.md
```

When one of the canonical files changes, copy the same updated version to the matching `public/docs/` location.

---

## What Should Not Be Public Documentation

The following are useful during development but should not be treated as final public documentation unless intentionally reviewed and cleaned:

```text
raw benchmark JSON files
temporary updater scripts
backup folders
old handbook drafts
debug screenshots
*.bak files
*.before_* files
private learning notes
```

Raw evidence can be preserved privately, but the public documentation should remain clean and reviewer-friendly.

---

## Current Production Reference

```text
Production URL: https://lucid-dmhlvl2qqa-uc.a.run.app
Cloud Run service: lucid
Region: us-central1
Validated revision: lucid-00013-xwc
Google Cloud project: project-c48afffb-501b-4711-a6d
```

---

## Final Reviewer Path

A reviewer can understand the project in this order:

1. Read [`PROJECT_OVERVIEW.md`](./PROJECT_OVERVIEW.md).
2. Open the live application.
3. Follow [`USER_GUIDE.md`](./USER_GUIDE.md) for a practical walkthrough.
4. Use [`LUCID_Project_Technical_Handbook.pdf`](./LUCID_Project_Technical_Handbook.pdf) for implementation details.
5. Use the Accuracy Report and Test Cases documents to verify evaluation depth.

---

## Closing Note

This documentation suite is designed to make LUCID understandable without a live verbal explanation. It explains the purpose, user value, technical implementation, validation evidence, operating procedures, and limitations of the project in a clean reviewer-facing structure.
