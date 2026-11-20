#!/usr/bin/env python3
"""
Comprehensive Chapter 12 Automated Verification Runner.
Executes the full test pipeline in sequence:
  1. TLS Verification (test_tls.py)
  2. RBAC Initialization (init_rbac.py)
  3. RBAC & Permissions Verification (test_rbac.py)
  4. Field-Level Redaction Demonstration (field_redaction.py)
"""

import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def run_script(script_name):
    script_path = BASE_DIR / script_name
    print("\n" + "#" * 85)
    print(f"## RUNNING: {script_name}")
    print("#" * 85)
    res = subprocess.run([sys.executable, str(script_path)], cwd=BASE_DIR)
    if res.returncode != 0:
        print(f"\n[-] ERROR: {script_name} failed with exit code {res.returncode}")
        return False
    return True


def main():
    print("=" * 85)
    print("MONGODB CHAPTER 12 — COMPREHENSIVE SECURITY TEST PIPELINE")
    print("=" * 85)

    suite = [
        "test_tls.py",
        "init_rbac.py",
        "test_rbac.py",
        "field_redaction.py"
    ]

    failed = []
    for script in suite:
        success = run_script(script)
        if not success:
            failed.append(script)
            print(f"\n[!] Pipeline stopped due to failure in {script}")
            break

    print("\n" + "=" * 85)
    print("CHAPTER 12 AUTOMATED PIPELINE SUMMARY")
    print("=" * 85)
    if not failed:
        print("[+] ALL CHAPTER 12 SECURITY TESTS PASSED WITH 100% SUCCESS!")
        print("    - Non-TLS connections rejected")
        print("    - TLS Handshake & SAN Hostname verified")
        print("    - CA & Client Certificate Validation verified")
        print("    - Admin Authentication verified")
        print("    - Custom RBAC Roles & Scopes verified")
        print("    - Read-Only & Read-Write Application User restrictions verified")
        print("    - View-Level Redaction (Salary exclusion & SSN masking) verified")
        print("    - Underlying sensitive collection bypass prevention verified")
        sys.exit(0)
    else:
        print(f"[-] PIPELINE FAILED. Failed scripts: {', '.join(failed)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
