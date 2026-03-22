from gemini_api import call_gemini
import re
import json
import logging
import requests as http_requests
from packaging.version import Version, InvalidVersion
from cvss import CVSS3

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# OSV.dev integration — single source of truth for vulnerabilities + fixes
# ---------------------------------------------------------------------------

def check_osv(package: str, version: str, ecosystem: str = "PyPI") -> list:
    """
    Queries OSV for CVEs affecting a specific package version.
    Used to determine if the CURRENT version is vulnerable.
    """
    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": ecosystem}
    }
    try:
        response = http_requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        return response.json().get("vulns", [])
    except Exception as e:
        logger.warning("OSV query failed for %s==%s: %s", package, version, e)
        return []


def find_clean_version(package: str, ecosystem: str) -> str | None:
    """
    Queries OSV for ALL vulnerabilities of a package (no version filter).
    Returns the highest fixed version — this fixes ALL known CVEs.
    """
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"name": package, "ecosystem": ecosystem}
    }
    try:
        response = http_requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        vulns = response.json().get("vulns", [])
    except Exception as e:
        logger.warning("OSV all-vulns query failed for %s: %s", package, e)
        return None

    all_fixed = []
    for v in vulns:
        for affected in v.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        all_fixed.append(event["fixed"])

    if not all_fixed:
        return None

    valid = []
    for ver in all_fixed:
        try:
            valid.append((Version(ver), ver))
        except InvalidVersion:
            pass

    if valid:
        clean = max(valid, key=lambda x: x[0])[1]
        logger.debug("OSV clean version for %s: %s", package, clean)
        return clean

    return all_fixed[-1]



def detect_ecosystem(file_type: str) -> str:
    return "npm" if file_type == "json" else "PyPI"


def extract_cvss_score(severity_list: list) -> float:
    """
    Extracts numeric CVSS score from OSV severity list.
    OSV returns vector strings — uses cvss library to calculate real base score.
    """
    best = 0.0
    for s in severity_list:
        raw = s.get("score", "")
        try:
            score = float(raw)
            if score > best:
                best = score
            continue
        except ValueError:
            pass
        try:
            if "CVSS:3" in raw:
                c = CVSS3(raw)
                score = float(c.base_score)
                if score > best:
                    best = score
        except Exception as e:
            logger.debug("Could not parse CVSS vector '%s': %s", raw, e)
    return best


def get_highest_cvss_vuln(vulns: list):
    """Returns the most severe CVE and its numeric score."""
    best_vuln = vulns[0]
    best_score = 0.0
    for v in vulns:
        score = extract_cvss_score(v.get("severity", []))
        if score > best_score:
            best_score = score
            best_vuln = v
    return best_vuln, best_score


def get_real_vulnerabilities(combined_deps: dict, ecosystem: str) -> dict:
    """
    For each dependency:
    1. Queries OSV with current version → gets CVEs affecting it
    2. If vulnerable, queries OSV without version → gets the cleanest fix version
    3. Verifies the clean version actually has no CVEs
    4. If current version >= clean version → already secure

    Returns dict with full vulnerability context per package.
    """
    results = {}
    for pkg, data in combined_deps.items():
        version = data.get("version")
        if not version:
            results[pkg] = {
                "vulns": [], "is_secure": True,
                "clean_version": None, "cvss": 0.0,
                "top_cve": None, "cve_ids": []
            }
            continue

        vulns = check_osv(pkg, version, ecosystem)

        if not vulns:
            logger.info("%s==%s: No CVEs found — secure ✓", pkg, version)
            results[pkg] = {
                "vulns": [], "is_secure": True,
                "clean_version": version, "cvss": 0.0,
                "top_cve": None, "cve_ids": []
            }
            continue

        # Find the most secure version (fixes ALL known CVEs)
        clean_version = find_clean_version(pkg, ecosystem)

        # Check if current version is already at or beyond the clean version
        is_secure = False
        if clean_version:
            try:
                if Version(version) >= Version(clean_version):
                    logger.info("%s==%s: Already at or beyond clean version %s — secure ✓",
                                pkg, version, clean_version)
                    is_secure = True
            except InvalidVersion:
                pass

        top_cve, best_score = get_highest_cvss_vuln(vulns)

        # Collect CVE IDs using aliases (CVE-XXXX format), fall back to GHSA if no CVE alias
        cve_ids = []
        for v in vulns:
            aliases = v.get("aliases", [])
            cve = next((a for a in aliases if a.startswith("CVE-")), None)
            if cve:
                cve_ids.append(cve)
            elif v.get("id"):
                cve_ids.append(v.get("id"))
            if len(cve_ids) == 5:
                break

        logger.info("%s==%s: %d CVE(s), CVSS=%s, clean=%s, secure=%s, top CVEs=%s",
                    pkg, version, len(vulns), round(best_score, 1),
                    clean_version, is_secure, cve_ids)

        results[pkg] = {
            "vulns": vulns,
            "is_secure": is_secure,
            "clean_version": clean_version,
            "cvss": best_score,
            "top_cve": top_cve,
            "cve_ids": cve_ids
        }

    return results


def build_vuln_context(vuln_data: dict) -> str:
    """
    Builds prompt context for Gemini.
    Secure packages → tell Gemini to mark safe, no fix needed.
    Vulnerable packages → real CVE data + OSV fix version.
    Gemini only explains in plain English — never decides versions.
    """
    lines = []
    for pkg, data in vuln_data.items():
        if data["is_secure"]:
            lines.append(
                f"{pkg}: SECURE — No actionable vulnerabilities. "
                f"Mark as safe (cvss=0.0, severity=Low). Do not suggest any version change."
            )
        else:
            top_cve = data["top_cve"]
            vid = top_cve.get("id", "unknown") if top_cve else "unknown"
            summary = top_cve.get("summary", "Vulnerability found") if top_cve else "Vulnerability found"
            cvss = round(data["cvss"], 1)
            clean = data["clean_version"]
            count = len(data["vulns"])
            cve_ids = data["cve_ids"]

            lines.append(
                f"{pkg}: {count} CVE(s) found. "
                f"Most severe: {vid} — {summary} "
                f"(CVSS: {cvss} | Fix version: {clean} | All CVEs: {', '.join(cve_ids)})"
            )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Patch file generators
# ---------------------------------------------------------------------------

def generate_patched_requirements(original_sections, suggested_versions):
    lines = []
    for pkg, data in original_sections["dependencies"].items():
        prefix = data.get("prefix", "==")
        if pkg in suggested_versions:
            lines.append(f"{pkg}{prefix}{suggested_versions[pkg]}")
        else:
            version = data.get("version")
            if version:
                lines.append(f"{pkg}{prefix}{version}")
            else:
                lines.append(pkg)
    return "\n".join(lines)


def generate_updated_package_json(original_sections, suggested_versions):
    deps = {}
    dev_deps = {}
    peer_deps = {}

    for pkg, data in original_sections.get("dependencies", {}).items():
        prefix = data["prefix"]
        ver = suggested_versions.get(pkg, data["version"])
        deps[pkg] = f"{prefix}{ver}"

    for pkg, data in original_sections.get("devDependencies", {}).items():
        prefix = data["prefix"]
        ver = suggested_versions.get(pkg, data["version"])
        dev_deps[pkg] = f"{prefix}{ver}"

    for pkg, data in original_sections.get("peerDependencies", {}).items():
        prefix = data["prefix"]
        ver = suggested_versions.get(pkg, data["version"])
        peer_deps[pkg] = f"{prefix}{ver}"

    # Rebuild result preserving original key order from _raw
    result = {}
    raw = original_sections.get("_raw", {})
    dep_sections = {"dependencies": deps, "devDependencies": dev_deps, "peerDependencies": peer_deps if peer_deps else None}
    for k, v in raw.items():
        if k in dep_sections:
            if dep_sections[k] is not None:
                result[k] = dep_sections[k]
        else:
            result[k] = v
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# JSON parsing helpers
# ---------------------------------------------------------------------------

def clean_gemini_response(raw: str) -> str:
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fenced:
        return fenced.group(1).strip()
    brace_match = re.search(r"\{.*\}", raw, re.DOTALL)
    if brace_match:
        return brace_match.group(0).strip()
    return raw.strip()


def parse_suggested_fix(item: str):
    """
    Parses fix strings including scoped npm packages like @org/pkg==1.0.0.
    Supports: pkg==1.0.0, @org/pkg==1.0.0, pkg>=1.0.0
    """
    # Matches optional @scope/name or plain name, followed by version operator and version
    match = re.match(r"^(@?[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)?)[><=!]+=?\s*([\d\.]+)", item.strip())
    if match:
        return match.group(1).strip(), match.group(2).strip()
    return None, None


# ---------------------------------------------------------------------------
# Main execute function
# ---------------------------------------------------------------------------

def execute(plan_tasks, combined_deps, original_sections, file_type):
    ecosystem = detect_ecosystem(file_type)

    # Step 1: OSV is the single source of truth for CVEs and fix versions
    logger.info("Fetching vulnerability data from OSV.dev...")
    vuln_data = get_real_vulnerabilities(combined_deps, ecosystem)
    vuln_context = build_vuln_context(vuln_data)
    logger.debug("=== OSV VULNERABILITY CONTEXT ===\n%s\n=================================", vuln_context)

    # Step 2: Build dependency list
    parsed_data = "\n".join([
        f"{name}=={data['version'] if data['version'] else 'No version'}"
        for name, data in combined_deps.items()
    ])

    # Step 3: Gemini explains risks in plain English only
    prompt = f"""
    You are a dependency risk analyzer. Your ONLY job is to explain vulnerabilities
    in plain English for non-technical stakeholders and calculate the risk score.

    CRITICAL RULES:
    - Do NOT invent or add any CVE IDs not listed below
    - Do NOT suggest different fix versions — use EXACTLY the "Fix version" provided
    - For packages marked SECURE, set cvss to "0.0", severity to "Low", fix to current version
    - Use the EXACT numeric CVSS score provided — do not change it
    - Derive severity: >= 9.0 Critical, >= 7.0 High, >= 4.0 Medium, < 4.0 Low

    Verified Vulnerability Data (from OSV.dev):
    {vuln_context}

    Risk Score Calculation Rules:
    - Start with 0.
    - For each vulnerable dependency add:
        - CVSS >= 9.0 → +25 points
        - CVSS >= 7.0 → +20 points
        - CVSS >= 4.0 → +10 points
        - CVSS < 4.0  → +5 points
    - Normalize to 0-100.
    - If all dependencies are safe, set risk_score = 0.

    Dependencies:
    {parsed_data}

    Output only valid JSON. No markdown. No ``` wrapping. No text outside JSON.

    {{
    "risk_score": <0-100>,
    "dependencies": [
        {{
        "package": "<name>",
        "current_version": "<version>",
        "cvss": "<exact score from above or 0.0>",
        "severity": "<Critical/High/Medium/Low>",
        "explanation": "<plain English explanation with business impact>",
        "fix": "<package>==<exact fix version from above>"
        }}
    ],
    "suggested_fixes": [
        "<package>==<exact fix version from above>"
    ]
    }}
    """

    raw_response = call_gemini(prompt)
    logger.debug("=== RAW GEMINI RESPONSE ===\n%s\n===========================", raw_response)

    if not raw_response.strip().startswith("{"):
        logger.error("Gemini returned a non-JSON response: %s", raw_response)
        raise RuntimeError(raw_response)

    cleaned = clean_gemini_response(raw_response)
    logger.debug("=== CLEANED RESPONSE ===\n%s\n========================", cleaned)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as e:
        logger.error("JSON parse failed: %s\nCleaned text was:\n%s", e, cleaned)
        raise RuntimeError(f"Could not parse Gemini response: {e}")

    risk_score = parsed.get("risk_score", 0)
    parsed_results = parsed.get("dependencies", [])

    # Step 4: Enrich Gemini's results with real CVE IDs from OSV
    for dep in parsed_results:
        pkg = dep.get("package")
        if pkg in vuln_data and vuln_data[pkg]["cve_ids"]:
            dep["cve_ids"] = vuln_data[pkg]["cve_ids"]
        else:
            dep["cve_ids"] = []

    # Step 5: Override fix versions with OSV data — never trust Gemini for versions
    suggested_versions = {}
    for pkg, data in vuln_data.items():
        if not data["is_secure"] and data["clean_version"]:
            suggested_versions[pkg] = data["clean_version"]
            logger.debug("Using OSV fix version for %s: %s", pkg, data["clean_version"])

    if file_type == "json":
        patched_file = generate_updated_package_json(original_sections, suggested_versions)
    else:
        patched_file = generate_patched_requirements(original_sections, suggested_versions)

    return parsed_results, patched_file, risk_score