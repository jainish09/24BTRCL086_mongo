"""
Deterministic CPE 2.3 Version Matcher & Program Inventory Lookup.
Decided purely in code (never by LLM) to eliminate hallucinations.
"""

import re
from typing import Dict, Any, List, Optional, Tuple


def parse_version_tuple(v_str: str) -> Tuple[int, ...]:
    """Extracts numeric version components for deterministic comparisons."""
    if not v_str:
        return (0,)
    # Extract all digit clusters
    nums = re.findall(r"\d+", str(v_str))
    if not nums:
        return (0,)
    return tuple(int(n) for n in nums)


def is_version_in_range(version: str, cpe_range: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Checks if a concrete software version falls within an NVD CPE vulnerable range.
    Returns (is_vulnerable: bool, reason: str).
    """
    v_parts = parse_version_tuple(version)

    start_inc = cpe_range.get("versionStartIncluding")
    start_exc = cpe_range.get("versionStartExcluding")
    end_inc = cpe_range.get("versionEndIncluding")
    end_exc = cpe_range.get("versionEndExcluding")

    # Check lower bounds
    if start_inc:
        if v_parts < parse_version_tuple(start_inc):
            return False, f"Version {version} is older than startIncluding {start_inc}"
    if start_exc:
        if v_parts <= parse_version_tuple(start_exc):
            return False, f"Version {version} is older/equal to startExcluding {start_exc}"

    # Check upper bounds
    if end_inc:
        if v_parts > parse_version_tuple(end_inc):
            return False, f"Version {version} is newer than endIncluding {end_inc} (Patched)"
    if end_exc:
        if v_parts >= parse_version_tuple(end_exc):
            return False, f"Version {version} is newer/equal to endExcluding {end_exc} (Patched)"

    # Within range
    fixed_ver = end_exc or end_inc or "latest security update"
    return True, f"Version {version} falls inside vulnerable range. Fixed in {fixed_ver}"


def evaluate_cve_against_host(cve: Dict[str, Any], host_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compares a CVE's NVD CPE ranges against host OS build and installed software.
    Returns deterministic verdict: AFFECTED, PATCHED, NOT AFFECTED, or UNKNOWN.
    """
    cve_id = cve.get("cveId", "")
    ranges = cve.get("nvdVersionRanges", [])
    platforms = [p.lower() for p in cve.get("platforms", [])]
    product = cve.get("product", "").lower()

    os_build = str(host_data.get("osBuild", ""))
    installed_programs = host_data.get("installedPrograms", [])
    store_apps = host_data.get("storeApps", [])
    all_programs = installed_programs + store_apps

    # Check OS level CVE (e.g. Windows TCP/IP, Wi-Fi driver)
    if "windows" in platforms and ("windows" in product or "tcp/ip" in product or "wi-fi" in product or "kernel" in product or "applocker" in product):
        if not os_build:
            return {
                "cveId": cve_id,
                "product": cve.get("product"),
                "verdict": "UNKNOWN",
                "scannedVersion": "None reported",
                "fixedVersion": "Latest Cumulative Update",
                "details": "Host OS build was not reported in scan."
            }

        for r in ranges:
            crit = r.get("criteria", "").lower()
            if "microsoft:windows" in crit:
                vuln, detail = is_version_in_range(os_build, r)
                fixed_v = r.get("versionEndExcluding") or r.get("versionEndIncluding") or "latest cumulative update"
                if vuln:
                    return {
                        "cveId": cve_id,
                        "product": cve.get("product"),
                        "verdict": "AFFECTED",
                        "scannedVersion": os_build,
                        "fixedVersion": fixed_v,
                        "details": f"Host OS build {os_build} is vulnerable. {detail}"
                    }
                else:
                    return {
                        "cveId": cve_id,
                        "product": cve.get("product"),
                        "verdict": "PATCHED",
                        "scannedVersion": os_build,
                        "fixedVersion": fixed_v,
                        "details": f"Host OS build {os_build} has patched this vulnerability ({detail})."
                    }

    # Check Application level CVE (e.g. Chrome, Edge, Office, Outlook)
    matched_app = None
    target_names = [p.strip() for p in product.replace("/", ",").split(",")]
    if "chrome" in product:
        target_names.extend(["google chrome", "chrome"])
    if "edge" in product:
        target_names.extend(["microsoft edge", "edge"])
    if "outlook" in product or "office" in product:
        target_names.extend(["microsoft outlook", "microsoft office", "office 365", "microsoft 365"])

    for prog in all_programs:
        prog_name = prog.get("name", "").lower()
        if any(t in prog_name for t in target_names if len(t) > 3):
            matched_app = prog
            break

    if not matched_app:
        return {
            "cveId": cve_id,
            "product": cve.get("product"),
            "verdict": "NOT AFFECTED",
            "scannedVersion": "Not Installed",
            "fixedVersion": "N/A",
            "details": f"Software '{cve.get('product')}' was not detected in host inventory."
        }

    app_ver = matched_app.get("version", "")
    if not app_ver:
        return {
            "cveId": cve_id,
            "product": matched_app.get("name"),
            "verdict": "UNKNOWN",
            "scannedVersion": "Installed without version string",
            "fixedVersion": "Check vendor advisory",
            "details": f"Detected {matched_app.get('name')} but version could not be parsed."
        }

    # Match against CPE ranges
    for r in ranges:
        vuln, detail = is_version_in_range(app_ver, r)
        fixed_v = r.get("versionEndExcluding") or r.get("versionEndIncluding") or "latest update"
        if vuln:
            return {
                "cveId": cve_id,
                "product": matched_app.get("name"),
                "verdict": "AFFECTED",
                "scannedVersion": app_ver,
                "fixedVersion": fixed_v,
                "details": f"{matched_app.get('name')} version {app_ver} is vulnerable ({detail})."
            }
        else:
            return {
                "cveId": cve_id,
                "product": matched_app.get("name"),
                "verdict": "PATCHED",
                "scannedVersion": app_ver,
                "fixedVersion": fixed_v,
                "details": f"{matched_app.get('name')} version {app_ver} is patched."
            }

    return {
        "cveId": cve_id,
        "product": matched_app.get("name"),
        "verdict": "NOT AFFECTED",
        "scannedVersion": app_ver,
        "fixedVersion": "N/A",
        "details": f"Application version {app_ver} is not listed in vulnerable CPE criteria."
    }


def lookup_installed_program(query: str, host_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalized token match against host program inventory.
    Returns deterministic status: installed / not exactly (closest matches) / not found among N.
    """
    programs = host_data.get("installedPrograms", []) + host_data.get("storeApps", []) + host_data.get("steamGames", [])
    total_count = len(programs)

    if total_count == 0:
        return {
            "status": "SCAN_PENDING",
            "matches": [],
            "totalScanned": 0,
            "message": "⚠️ No PC scanner data was found in MongoDB. Run the 1-line Sentinel scanner command in PowerShell to audit this machine."
        }

    is_folder_mention = bool(re.search(r"\b(folder|file|directory|path)\b", query, flags=re.I))
    clean_q = re.sub(r"\b(is|are|do|i|have|has|got|check|installed|install|on|in|inside|my|the|pc|laptop|computer|app|program|software|folder|file|directory|\?)\b", "", query, flags=re.I).strip().lower()
    if not clean_q:
        return {
            "status": "NOT_FOUND",
            "matches": [],
            "totalScanned": total_count,
            "targetName": clean_q,
            "isFolderQuery": is_folder_mention,
            "message": f"Please specify a software or package name to check among {total_count} installed programs."
        }

    exact_matches = []
    close_matches = []

    q_tokens = set(clean_q.split())

    for p in programs:
        p_name = p.get("name", "").strip()
        p_lower = p_name.lower()

        if clean_q == p_lower or clean_q in p_lower:
            exact_matches.append(p)
        else:
            p_tokens = set(re.findall(r"\w+", p_lower))
            if q_tokens.intersection(p_tokens):
                close_matches.append(p)

    if exact_matches:
        return {
            "status": "INSTALLED",
            "matches": exact_matches[:5],
            "totalScanned": total_count,
            "targetName": clean_q,
            "isFolderQuery": is_folder_mention,
            "message": f"Found {len(exact_matches)} matching installation(s) on your device."
        }
    elif close_matches:
        return {
            "status": "CLOSE_MATCH",
            "matches": close_matches[:5],
            "totalScanned": total_count,
            "targetName": clean_q,
            "isFolderQuery": is_folder_mention,
            "message": f"Not exactly found, but found {len(close_matches)} related package(s)."
        }
    else:
        return {
            "status": "NOT_FOUND",
            "matches": [],
            "totalScanned": total_count,
            "targetName": clean_q,
            "isFolderQuery": is_folder_mention,
            "message": f"'{clean_q}' is not found among {total_count} installed applications on this PC."
        }
