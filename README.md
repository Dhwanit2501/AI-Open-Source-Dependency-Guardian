# AI Open-Source Dependency Guardian

> Built a **Software Composition Analysis (SCA) scanner** to detect vulnerable and outdated dependencies by parsing `requirements.txt` and `package.json`, leveraging **NVD, OSV.dev, and CVSS-based risk scoring** to prioritize remediation - with AI-powered business impact explanations via Google Gemini.

## Problem Statement

Open-source projects rely on hundreds of dependencies. Outdated or vulnerable packages are a top cause of security breaches and technical debt. **According to the 2025 OSSRA report, 86% of codebases contain vulnerable open source and 90% are more than four years out-of-date.** Most small teams and individual developers lack automated tools to check and fix these issues.

## Solution

AI Open-Source Dependency Guardian automates dependency risk assessment by scanning common project files and cross-referencing trusted vulnerability databases — with zero hallucination.

- **Real CVE data** — queries OSV.dev directly for verified vulnerabilities. No AI guessing.
- **Accurate CVSS scoring** — parses CVSS vector strings using the `cvss` library to compute real numeric base scores (e.g. 9.8, 7.5) instead of estimates.
- **Most secure fix version** — queries OSV without a version filter to find the highest fixed version across all known CVEs for a package — the version that fixes everything.
- **Zero hallucination** — Gemini's only role is explaining vulnerabilities in plain English and mapping them to business impact. It never decides CVE IDs, CVSS scores, or fix versions.
- **Loop-free rescanning** — version comparison logic detects when a package is already at or beyond the clean version, marking it secure and stopping infinite upgrade loops.
- **Patched file generation** — auto-creates a patched `requirements.txt` or `package.json` preserving all original fields, with only vulnerable packages upgraded.
- **Risk tracking over time** — stores previous scans and highlights risk score improvements or regressions between scans.
- **Clickable CVE references** — each CVE links directly to NVD for independent verification.

### YouTube Demo
[![Watch the Demo](https://img.youtube.com/vi/4YxTJUh-PK4/hqdefault.jpg)](https://youtu.be/4YxTJUh-PK4)

### Live Project
[Try the Live App](https://ai-open-source-dependency-guardian.streamlit.app/)

---

## Architecture

![Architecture Diagram](src/media/AI%20Open-Source%20Guardian-Arch.png)

---

## How It Works

```
Upload requirements.txt / package.json
            ↓
    Parse dependencies (parser.py)
            ↓
    OSV.dev API — query current version
    → Get real CVEs + CVSS scores
            ↓
    OSV.dev API — query without version
    → Find highest fixed version (most secure)
            ↓
    Version check: current >= clean?
    → Yes: mark secure, skip Gemini
    → No:  pass real CVE data to Gemini
            ↓
    Gemini — explain risk in plain English
    + calculate overall risk score (0-100)
            ↓
    Generate patched dependency file
    Store scan result in memory
            ↓
    Display: Risk Score, CVEs, Fix, Comparison
```

---

## Components

### User Interface (`streamlit_ui.py`)
- File upload for `requirements.txt` and `package.json`
- Circular risk score gauge (0–100) with severity color coding
- Per-dependency cards showing CVSS score, severity, CVE badges (linked to NVD), plain English explanation, and suggested fix
- Side-by-side original vs patched file comparison
- One-click patched file download
- Scan-over-scan improvement tracking

### Agent Core

**Planner (`planner.py`)**
- Parses dependency files
- Generates per-package analysis tasks
- Passes last scan context for improvement comparison

**Executor (`executor.py`)**
- Fetches real CVEs from OSV.dev for each dependency
- Calculates actual CVSS numeric scores from vector strings
- Finds the most secure available version via OSV full-package query
- Detects already-secure packages via version comparison
- Calls Gemini only for plain English explanation and risk scoring
- Overrides Gemini's suggested versions with OSV data post-response
- Generates patched dependency file preserving all original fields

**Memory (`memory.py`)**
- Stores scan results in `data_db.json`
- Tracks risk scores, fixes, and scan timestamps
- Calculates improvement/regression between scans
- Maintains last 10 entries (FIFO cleanup)

### Tools / APIs

| Tool | Role |
|------|------|
| **OSV.dev API** | Source of truth for CVEs, CVSS scores, and fix versions |
| **Google Gemini API** | Plain English risk explanation + business impact only |
| **NVD (nvd.nist.gov)** | CVE reference links for user verification |
| **cvss library** | Parses CVSS vector strings to real numeric scores |
| **packaging library** | Semantic version comparison for clean version detection |

---

## Setup & Installation

1. Clone the repo:
   ```bash
   git clone https://github.com/bhingle/Gen-Warriors.git
   cd Gen-Warriors
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Add your Gemini API key to a `.env` file:
   ```
   GEMINI_API_KEY=your-gemini-api-key-here
   ```

4. Run the app:
   ```bash
   streamlit run src/streamlit_ui.py
   ```

---

## Usage

1. Upload a `requirements.txt` (Python) or `package.json` (Node.js) file
2. Wait for OSV + Gemini analysis (~10–30 seconds)
3. Review the risk score, CVE details, and business impact explanations
4. Download the patched dependency file
5. Re-upload the patched file to verify risk score drops to 0

---

## Supported File Types

| File | Ecosystem |
|------|-----------|
| `requirements.txt` | Python / PyPI |
| `package.json` | Node.js / npm |

---

## Key Design Decisions

**Why OSV.dev instead of relying on Gemini for CVEs?**
LLMs hallucinate CVE data — assigning wrong CVE IDs, incorrect CVSS scores, and suggesting arbitrary fix versions. OSV.dev is an authoritative, machine-readable vulnerability database maintained by Google. Using it as the source of truth eliminates hallucination entirely.

**Why minimum safe version instead of latest?**
Industry-standard SCA tools (Snyk, Dependabot, OWASP Dependency Check) suggest the minimum version that fixes known CVEs — not the absolute latest. Major version bumps introduce breaking changes. The minimum safe version is a targeted, verified fix. Users can upgrade further as part of scheduled dependency reviews.

**Why does Gemini only explain?**
Gemini is excellent at translating technical CVE summaries into plain English with business context. It is not a reliable vulnerability database. Separating these responsibilities gives accurate data + clear communication.

---

## Observability

- OSV query results logged per package (CVE count, CVSS, clean version)
- Raw and cleaned Gemini responses logged for debugging
- User-friendly error messages for rate limits and API failures
- Retry logic with exponential backoff for Gemini 429 errors

---

## Future Improvements

- **Interactive Chatbot Mode** — conversational follow-up questions about specific vulnerabilities
- **Automated PR Generation** — create pull requests with patched files directly in CI/CD pipelines
- **File Versioning** — track dependency changes and risk evolution over time
- **Multi-file scanning** — scan entire repositories at once
- **SBOM Export** — generate Software Bill of Materials in CycloneDX or SPDX format

---

## Contributors

Built collaboratively by [@Dhwanit2501](https://github.com/Dhwanit2501) and [@bhingle](https://github.com/bhingle)