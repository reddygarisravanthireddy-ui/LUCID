<div align="center">

<img src="/public/assets/branding/lucid-icon-256.png" alt="LUCID Logo" width="84" height="84">

# LUCID

**Clarity Through the Chaos.**

# ACCURACY TEST CASES

**Version 1.0**  
**September 2026**

**LUCID Documentation Suite**

</div>

---

## Document Information

**Purpose:** This document records the formal LUCID evaluation cases used to validate the shared production analysis pipeline. It is the case-level companion to the Accuracy & Reliability Validation Report.

**Audience:** Developers, evaluators, security reviewers, and anyone who wants to inspect exactly what LUCID was tested against.

**Related Documents:** `README.md`, `docs/PROJECT_OVERVIEW.md`, `docs/USER_GUIDE.md`, `docs/LUCID_ACCURACY_TEST_REPORT.md`, `docs/LUCID_Project_Technical_Handbook.pdf`, and `RUNBOOK.md`.

---

## Table of Contents

1. Evaluation Scope  
2. Scoring Model  
3. Primary Benchmark Summary  
4. Core Regression Suite — 26 Cases  
5. Generalization Suite — 18 Cases  
6. Adversarial Suite — 30 Cases  
7. File Pipeline Smoke Validation — 19 Cases  
8. Extended File Validation — 17 Cases  
9. Wireshark Screenshot Validation — 16 Cases  
10. Improvement History and Rationale  
11. Safety and Overfitting Controls  
12. Interpretation Limits  

---

## 1. Evaluation Scope

LUCID was evaluated through a controlled benchmark and additional targeted validation suites. The primary benchmark consists of **74 formal cases** across three independent suites:

| Suite | Cases | Purpose |
|---|---:|---|
| Core Regression Suite | 26 | Stable regression coverage across major threat categories and benign activity. |
| Generalization Suite | 18 | Unseen variants used to verify that improvements transfer beyond original examples. |
| Adversarial Suite | 30 | Ambiguous, evasive, and boundary cases used to stress severity and taxonomy calibration. |
| **Primary Benchmark Total** | **74** | **Formal controlled benchmark.** |

Additional validation suites are documented separately in this file:

| Validation Area | Cases | Purpose |
|---|---:|---|
| File Pipeline Smoke Validation | 19 | Confirms safe extraction, static checks, AI aggregation, and file-result behavior. |
| Extended File Validation | 17 | Confirms edge behavior across document/code/parsing limitations. |
| Wireshark Screenshot Validation | 16 | Confirms evidence-first handling of scan and C2 screenshot scenarios. |

The file and Wireshark suites are **not added** to the 74-case primary benchmark percentage. They provide separate confidence in the file/multimodal pipeline.

---

## 2. Scoring Model

| Score | Meaning |
|---|---|
| **PASS** | The evaluated behavior matched the expected verdict, classification, severity, and supporting reasoning closely enough for strict acceptance. |
| **PARTIAL** | LUCID substantially understood the evidence, but one strict dimension such as exact severity or expected impact level differed. PARTIAL is not counted as PASS. |
| **FAIL** | A material miss occurred, such as an unsafe verdict, major classification error, missing required fields, or incorrect handling of benign/malicious evidence. |

LUCID intentionally uses an **evidence-first** policy. It does not force Critical severity for an attempted exploit, BEC request, or suspicious scan unless the submitted evidence supports confirmed impact, execution, compromise, loss, or command-and-control behavior.

---

## 3. Primary Benchmark Summary

| Suite | Total | PASS | PARTIAL | FAIL | Strict PASS Rate | ShieldMe Result |
|---|---:|---:|---:|---:|---:|---|
| Core Regression | 26 | 24 | 2 | 0 | 92.3% | 26/26 |
| Generalization | 18 | 18 | 0 | 0 | 100.0% | 18/18 |
| Adversarial | 30 | 26 | 4 | 0 | 86.7% | 30/30 |
| **Combined Primary Benchmark** | **74** | **68** | **6** | **0** | **91.9%** | **74/74** |

Key release interpretation:

- LUCID exceeded the 80% controlled benchmark target.
- No primary benchmark case ended as FAIL.
- ShieldMe achieved successful outcomes across all 74 primary benchmark cases.
- No malicious primary benchmark case was classified as Safe.
- Remaining PARTIAL results reflect strict evidence-first calibration rather than complete misses.

---

## 4. Core Regression Suite — 26 Cases

| Test ID | Category | Case Name | Expected ShieldMe | Expected TIQ / Severity | Final Status | Notes |
|---|---|---|---|---|---|---|

| **TC-001** | Phishing / Social Engineering | Credential Phishing (Microsoft 365 spoofed link) | Dangerous | Phishing / Credential Harvesting / High | **PASS** | Detected credential-harvesting lure and spoofed domain. |
| **TC-002** | Phishing / Social Engineering | Smishing (SMS banking scam) | Dangerous | Phishing / Credential Harvesting / High | **PASS** | Detected SMS-based credential theft and urgent financial lure. |
| **TC-003** | Phishing / Social Engineering | Spear Phishing (targeted vendor invoice) | Dangerous | Spear Phishing / Social Engineering / High | **PASS** | Detected targeted fraud/social-engineering indicators. |
| **TC-004** | Phishing / Social Engineering | OAuth Consent Phishing (malicious app) | Dangerous | OAuth Consent Phishing / High | **PASS** | Detected suspicious consent grant and risky permissions. |
| **TC-005** | Phishing / Social Engineering | Business Email Compromise (CEO wire request) | Dangerous | Business Email Compromise / Critical expected / High observed | **PARTIAL** | Correct BEC detection; kept High because loss/transfer completion was not confirmed. |
| **TC-006** | Authentication Attack | SSH Brute-Force Attack | Dangerous | Brute Force / Password Guessing / High | **PASS** | Detected high-volume repeated login attempts. |
| **TC-007** | Authentication Attack | Dictionary Attack (FTP wordlist profile) | Dangerous | Password Guessing / Dictionary Attack / Medium/High | **PASS** | Detected wordlist-based authentication attack; final behavior accepted as evidence-supported. |
| **TC-008** | Authentication Attack | Password Spraying Attack (Azure AD proxy) | Dangerous | Password Spraying / High | **PASS** | Detected horizontal low-and-slow authentication attack. |
| **TC-009** | Authentication Attack | Credential Stuffing Attack | Dangerous | Credential Stuffing / High | **PASS** | Detected leaked-credential reuse across accounts. |
| **TC-010** | Authentication Attack | MFA Push Fatigue / Bombing | Dangerous | MFA Fatigue / Push Bombing / High | **PASS** | Detected repeated unsolicited push approvals. |
| **TC-011** | Endpoint Execution | Obfuscated PowerShell Execution | Dangerous | PowerShell Execution / Obfuscated PowerShell / Critical | **PASS** | Detected obfuscated execution and dangerous command behavior. |
| **TC-012** | Endpoint Execution | Scheduled Task Persistence (malware dropper) | Dangerous | Persistence / Scheduled Task / High | **PASS** | Detected persistence behavior and suspicious dropper activity. |
| **TC-013** | Endpoint Execution | Ransomware Execution (shadow copy deletion) | Dangerous | Ransomware Activity / Critical | **PASS** | Detected ransomware indicators and recovery inhibition. |
| **TC-014** | Endpoint Execution | Process Injection / Memory Tampering | Dangerous | Process Injection / Memory Tampering / High | **PASS** | Detected memory-tampering behavior only when supported by evidence. |
| **TC-015** | Privilege Escalation | Sudoer Privilege Escalation | Dangerous | Privilege Escalation / Critical | **PASS** | Detected unauthorized elevation path. |
| **TC-016** | Privilege Escalation | Unauthorized Domain Admin Creation | Dangerous | Account Manipulation / Domain Admin Creation / Critical | **PASS** | Detected high-impact identity compromise behavior. |
| **TC-017** | Privilege Escalation | UAC Bypass via Event Viewer Registry Hijack | Dangerous | Privilege Escalation / UAC Bypass / High | **PASS** | Detected Windows privilege bypass pattern. |
| **TC-018** | Application Security | SQL Injection (blind / data extraction) | Dangerous | SQL Injection / High | **PASS** | Detected injection and data-access indicators. |
| **TC-019** | Application Security | Cross-Site Scripting (reflected XSS) | Dangerous | Cross-Site Scripting / High | **PASS** | Detected reflected script injection risk. |
| **TC-020** | Application Security | Vulnerability Exploitation (Log4Shell payload) | Dangerous | Vulnerability Exploitation / Critical expected / High observed | **PARTIAL** | Correct exploit classification; kept High because command execution/output was not confirmed. |
| **TC-021** | Network / C2 | DNS Tunneling Data Exfiltration | Dangerous | Data Exfiltration / DNS Tunneling / High | **PASS** | Detected suspicious DNS tunneling/exfiltration pattern. |
| **TC-022** | Network / C2 | Command and Control (HTTPS beaconing) | Dangerous | Command and Control / High | **PASS** | Detected periodic beaconing behavior. |
| **TC-023** | Network / Lateral Movement | Lateral Movement (WMI / PsExec) | Dangerous | Lateral Movement / High | **PASS** | Detected remote execution/lateral movement evidence. |
| **TC-024** | Network / Multi-Stage | Multi-Stage Intrusion (phishing to DC compromise) | Dangerous | Multi-Stage Enterprise Intrusion / Critical | **PASS** | Detected full attack chain with high-impact progression. |
| **TC-025** | Benign | Legitimate Security Notification (Google alert) | Safe | Benign / Legitimate Security Notification / Low | **PASS** | Avoided false positive on authentic notification. |
| **TC-026** | Benign | Normal Authentication Activity (SSO & Duo MFA) | Safe | Benign / Normal Authentication Activity / Low | **PASS** | Avoided false positive on normal SSO/MFA activity. |


**Core suite result:** **24/26 PASS**, **2 PARTIAL**, **0 FAIL**. The two PARTIAL cases are evidence-boundary cases where LUCID correctly detected the threat but avoided unsupported Critical escalation.

---

## 5. Generalization Suite — 18 Cases

The Generalization suite verifies that LUCID handles unseen variations rather than only memorizing original Core patterns.

| Test ID | Case Name | Final Status | Notes |
|---|---|---|---|

| **GEN-001** | Brute Force Attack (Generic) | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-002** | Dictionary Attack (Wordlist Profile) | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-003** | Password Spraying (Horizontal) | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-004** | Credential Stuffing (Combo List) | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-005** | Account Enumeration (Password Reset Oracle) | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-006** | MFA Fatigue (Authenticator Push Bombing) | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-007** | Suspicious Obfuscated PowerShell | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-008** | Benign PowerShell Administration | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-009** | SQL Injection (Boolean-based Blind) | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-010** | Vulnerability Exploitation (Spring4Shell RCE) | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-011** | Command and Control (HTTPS Beaconing) | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-012** | Data Exfiltration (Sensitive Database Archive) | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-013** | Local Privilege Escalation (Sudoer Abuse) | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-014** | Lateral Movement (WMI Execution to DC) | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-015** | Multi-Stage Enterprise Intrusion | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-016** | Normal SAML Single Sign-On | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-017** | Suspicious Executive Impersonation Email | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |
| **GEN-018** | Legitimate Password Expiration Warning | **PASS** | Correct unseen-case behavior without benchmark-specific logic. |


**Generalization suite result:** **18/18 PASS**, **0 PARTIAL**, **0 FAIL**. This suite is important because it demonstrates transfer beyond the original regression examples.

---

## 6. Adversarial Suite — 30 Cases

The Adversarial suite tests evasive, ambiguous, and boundary conditions. It is intentionally harder than the Core suite because several cases are designed to expose overclassification, false escalation, and weak taxonomy boundaries.

| Test ID | Case Name | Final Status | Notes |
|---|---|---|---|

| **ADV-001** | Benign IT Maintenance Script with Bypass Flag | **PASS** | Correct adversarial/boundary handling. |
| **ADV-002** | Obfuscated PowerShell Downloader without Standard Keywords | **PASS** | Correct adversarial/boundary handling. |
| **ADV-003** | Authentic IT Password Expiration Warning | **PASS** | Correct adversarial/boundary handling. |
| **ADV-004** | Subtle Credential Phishing without Urgency Keywords | **PASS** | Correct adversarial/boundary handling. |
| **ADV-005** | API User Account Enumeration | **PASS** | Correct adversarial/boundary handling. |
| **ADV-006** | Horizontal Password Spraying | **PASS** | Correct adversarial/boundary handling. |
| **ADV-007** | Credential Stuffing with Leaked Combo List | **PASS** | Correct adversarial/boundary handling. |
| **ADV-008** | Targeted Dictionary Attack on Admin Account | **PASS** | Correct adversarial/boundary handling. |
| **ADV-009** | MFA Fatigue Push Bombing | **PASS** | Correct adversarial/boundary handling. |
| **ADV-010** | Office Macro Spawning Hidden Encoded PowerShell | **PASS** | Correct adversarial/boundary handling. |
| **ADV-011** | SQL Injection Union Select Table Extraction | **PASS** | Correct adversarial/boundary handling. |
| **ADV-012** | Spring4Shell Remote Code Execution | **PARTIAL** | Unconfirmed exploitation evidence rated High rather than Critical. |
| **ADV-013** | Log4Shell JNDI Exploit Attempt | **PARTIAL** | Unconfirmed JNDI/execution evidence rated High rather than Critical. |
| **ADV-014** | DNS Tunneling Command & Control | **PASS** | Correct adversarial/boundary handling. |
| **ADV-015** | Massive Database Exfiltration via Rclone | **PARTIAL** | Strict boundary remained PARTIAL in final adversarial aggregate. |
| **ADV-016** | Local Privilege Escalation via Dirty Pipe | **PASS** | Correct adversarial/boundary handling. |
| **ADV-017** | WMI Remote Execution to Domain Controller | **PASS** | Correct adversarial/boundary handling. |
| **ADV-018** | Unauthorized Domain Admin Account Creation | **PASS** | Correct adversarial/boundary handling. |
| **ADV-019** | Ransomware Deleting Shadow Copies | **PASS** | Correct adversarial/boundary handling. |
| **ADV-020** | Normal Corporate SAML SSO Login | **PASS** | Correct adversarial/boundary handling. |
| **ADV-021** | Official Google Account Security Alert | **PASS** | Correct adversarial/boundary handling. |
| **ADV-022** | Security Administrator Internal Port Scan | **PASS** | Correct adversarial/boundary handling. |
| **ADV-023** | Routine PowerShell Backup Script Execution | **PASS** | Correct adversarial/boundary handling. |
| **ADV-024** | Executive Impersonation Wire Transfer Fraud (BEC) | **PARTIAL** | Unconfirmed BEC wire request rated High rather than Critical. |
| **ADV-025** | Illicit OAuth Consent Grant Application | **PASS** | Correct adversarial/boundary handling. |
| **ADV-026** | Impossible Travel Anomaly | **PASS** | Correct adversarial/boundary handling. |
| **ADV-027** | Insider Threat Mass Data Download | **PASS** | Correct adversarial/boundary handling. |
| **ADV-028** | Command Injection in Web Diagnostic Tool | **PASS** | Correct adversarial/boundary handling. |
| **ADV-029** | DLL Dropper with Scheduled Task Persistence | **PASS** | Correct adversarial/boundary handling. |
| **ADV-030** | Full Multi-Stage Enterprise Intrusion Chain | **PASS** | Correct adversarial/boundary handling. |


**Adversarial suite result:** **26/30 PASS**, **4 PARTIAL**, **0 FAIL**. The PARTIAL cases remained conservative where the submitted evidence did not fully prove the highest-impact interpretation.

---

## 7. File Pipeline Smoke Validation — 19 Cases

The file pipeline validation confirms that uploaded files are handled safely and that readable content is extracted and analyzed without executing uploaded content.

| Test ID | Case Name | Purpose | Final Status |
|---|---|---|---|

| **FILE-001** | TXT suspicious message | Readable text extraction and phishing/social-engineering analysis. | **PASS** |
| **FILE-002** | Markdown security note | Markdown text extraction and indicator handling. | **PASS** |
| **FILE-003** | Log file authentication attack | Repeated login indicators from logs. | **PASS** |
| **FILE-004** | CSV with suspicious entries | CSV parsing and field-level evidence extraction. | **PASS** |
| **FILE-005** | PDF phishing content | PDF text extraction and security analysis. | **PASS** |
| **FILE-006** | Multi-page PDF | Page-aware extraction and aggregation. | **PASS** |
| **FILE-007** | DOCX suspicious document | DOCX text extraction via Mammoth. | **PASS** |
| **FILE-008** | JavaScript vulnerable code | Static code review without executing uploaded code. | **PASS** |
| **FILE-009** | Parameterized SQL safe code | Avoid false positive on parameterized query. | **PASS** |
| **FILE-010** | Hardcoded secret style code sample | Static indicator recognition. | **PASS** |
| **FILE-011** | Benign text file | Safe/low-risk text handling. | **PASS** |
| **FILE-012** | Unsupported binary-like file | Unsupported/unreadable content not automatically Safe. | **PASS** |
| **FILE-013** | Oversized/limit behavior | Upload validation and safe rejection path. | **PASS** |
| **FILE-014** | CSV formula-like content | CSV formula-injection awareness. | **PASS** |
| **FILE-015** | Prompt injection inside document | Treat document instructions as untrusted data. | **PASS** |
| **FILE-016** | Malicious-code document | Detected malicious indicators without executing file. | **PASS** |
| **FILE-017** | File with weak/partial evidence | Conservative Suspicious/Inconclusive behavior. | **PASS** |
| **FILE-018** | Image/document evidence pairing | Aggregate file evidence with AI analysis. | **PASS** |
| **FILE-019** | Whole-file limitation messaging | Required limitation shown for readable-file analysis. | **PASS** |


**File smoke validation result:** **19/19 PASS**.

Important validated behaviors:

- Uploaded files are treated as data.
- Uploaded files are not executed.
- Unsupported or unreadable files are not automatically marked Safe.
- File analysis may return `SAFE`, `SUSPICIOUS`, `DANGEROUS`, or `INCONCLUSIVE`.
- `malicious_content` may be `detected`, `not_detected`, or `inconclusive`.
- LUCID displays the limitation: “LUCID analyzed the content it could read from this file. This does not guarantee that the entire file is safe.”

---

## 8. Extended File Validation — 17 Cases

| Test ID | Case Name | Final Status |
|---|---|---|

| **EXTFILE-001** | PDF v2 parsing compatibility | **PASS** |
| **EXTFILE-002** | Multipage PDF location mapping | **PASS** |
| **EXTFILE-003** | DOCX paragraph extraction | **PASS** |
| **EXTFILE-004** | CSV column extraction | **PASS** |
| **EXTFILE-005** | TXT/log newline preservation | **PASS** |
| **EXTFILE-006** | Source-code static scan | **PASS** |
| **EXTFILE-007** | Vulnerable JavaScript SQLi recognition | **PASS** |
| **EXTFILE-008** | Parameterized SQL false-positive control | **PASS** |
| **EXTFILE-009** | Prompt-injection-as-data handling | **PASS** |
| **EXTFILE-010** | Unsupported extension handling | **PASS** |
| **EXTFILE-011** | Unreadable extraction fallback | **PASS** |
| **EXTFILE-012** | Dangerous file verdict aggregation | **PASS** |
| **EXTFILE-013** | Suspicious file verdict aggregation | **PASS** |
| **EXTFILE-014** | Inconclusive file verdict behavior | **PASS** |
| **EXTFILE-015** | malicious_content detected mapping | **PASS** |
| **EXTFILE-016** | malicious_content not_detected mapping | **PASS** |
| **EXTFILE-017** | limitation/disclaimer consistency | **PASS** |


**Extended file validation result:** **17/17 PASS**. These cases strengthen confidence in parsing, unsupported-file handling, prompt-injection treatment, and result aggregation.

---

## 9. Wireshark Screenshot Validation — 16 Cases

The Wireshark validation suite confirms that LUCID interprets network screenshot evidence conservatively. Scan-only traffic should be treated as reconnaissance/active scanning, not as confirmed compromise or command-and-control. Confirmed periodic beaconing should still be escalated appropriately.

| Test ID | Case Name | Final Status |
|---|---|---|

| **WIRE-001** | Mixed scan + failed DNS: TIQ Active Scanning | **PASS** |
| **WIRE-002** | Mixed scan + failed DNS: TIQ Medium severity | **PASS** |
| **WIRE-003** | Mixed scan + failed DNS: MITRE T1595.002 | **PASS** |
| **WIRE-004** | Mixed scan + failed DNS: not classified as C2 | **PASS** |
| **WIRE-005** | Mixed scan + failed DNS: ShieldMe Suspicious | **PASS** |
| **WIRE-006** | Pure SYN port scan: TIQ Active Scanning | **PASS** |
| **WIRE-007** | Pure SYN port scan: TIQ Medium severity | **PASS** |
| **WIRE-008** | Pure SYN port scan: MITRE T1595.002 | **PASS** |
| **WIRE-009** | Pure SYN port scan: not classified as C2 | **PASS** |
| **WIRE-010** | Pure SYN port scan: ShieldMe Suspicious | **PASS** |
| **WIRE-011** | Confirmed C2 beacon: TIQ Command and Control | **PASS** |
| **WIRE-012** | Confirmed C2 beacon: High/Critical severity preserved | **PASS** |
| **WIRE-013** | Confirmed C2 beacon: not downgraded to scanning | **PASS** |
| **WIRE-014** | Confirmed C2 beacon: ShieldMe Dangerous | **PASS** |
| **WIRE-015** | Wireshark guard: scan does not imply exploitation | **PASS** |
| **WIRE-016** | Wireshark guard: C2 evidence still escalates correctly | **PASS** |


**Wireshark validation result:** **16/16 PASS**.

Validated behavior includes:

- Mixed scan + failed DNS: TIQ identifies Active Scanning, Medium severity, MITRE `T1595.002`; ShieldMe returns Suspicious.
- Pure SYN port scan: TIQ identifies Active Scanning, Medium severity, MITRE `T1595.002`; ShieldMe returns Suspicious.
- Confirmed C2 beacon: TIQ identifies Command and Control with High severity; ShieldMe returns Dangerous.
- Reconnaissance-only traffic does not become unsupported exploitation/C2.

---

## 10. Improvement History and Rationale

LUCID's benchmark performance improved through structured engineering rather than test-case memorization.

| Stage | Result | Why It Mattered |
|---|---:|---|
| Corrected early Core baseline | 11/26 PASS = 42.3% | Revealed classification, severity, and MITRE weaknesses in the initial evaluation. |
| First major Core optimization | 18/26 PASS = 69.2% | Improved contextual reasoning and reduced broad misclassification. |
| Combined Core + Generalization checkpoint | 32/44 PASS = 72.7% | Confirmed that improvements began transferring to unseen cases. |
| Final primary benchmark | 68/74 PASS = 91.9% | Demonstrated mature evidence-first behavior across Core, Generalization, and Adversarial suites. |

Why the system improved:

- The analyzer was centralized so production and test runners used the same shared module.
- Prompt and taxonomy guidance became more precise for phishing, authentication attacks, PowerShell, SQL injection, BEC, C2, data exfiltration, and benign notifications.
- Severity was calibrated around observable impact rather than keywords alone.
- The evaluator and documentation separated strict PASS, PARTIAL, and FAIL instead of hiding borderline cases.
- Generalization and adversarial suites reduced the risk of overfitting to known examples.
- File and Wireshark validation added coverage beyond plain text prompts.

---

## 11. Safety and Overfitting Controls

LUCID's evaluation process included controls intended to make the result trustworthy:

- Production and benchmark execution use the same shared analyzer path.
- The project does not rely on benchmark IDs such as `TC-`, `GEN-`, or `ADV-` inside production analysis logic.
- Deterministic safeguards are general security rules, not case-specific answer lookups.
- PARTIAL cases are preserved when forcing a PASS would require unsupported escalation.
- Controlled metrics are reported separately from file and Wireshark validation to avoid inflated accuracy claims.

---

## 12. Interpretation Limits

The results in this document are project validation results, not a universal guarantee that LUCID will correctly classify every possible real-world threat. Accuracy depends on the quality, completeness, and readability of the submitted evidence.

LUCID is a decision-support tool. Important security decisions should be verified using authoritative telemetry, security tools, organizational procedures, or qualified human analysts.

---

## Final Test Case Coverage Summary

| Area | Cases | Result |
|---|---:|---|
| Primary benchmark | 74 | 68 PASS, 6 PARTIAL, 0 FAIL |
| File pipeline smoke validation | 19 | 19 PASS |
| Extended file validation | 17 | 17 PASS |
| Wireshark screenshot validation | 16 | 16 PASS |

This document preserves the complete testing structure needed for reviewers to understand both the final score and the engineering reasoning behind it.

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
