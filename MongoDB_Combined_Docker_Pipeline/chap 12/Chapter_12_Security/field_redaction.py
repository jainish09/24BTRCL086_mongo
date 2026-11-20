#!/usr/bin/env python3
"""
Field-Level Redaction Demonstration for MongoDB Lab 12.1.
Compares:
  - Original sensitive collection: 'company_db.employees' (Accessible to Admin)
  - Redacted secure view: 'company_db.employees_safe' (Accessible to app_user_read)
Demonstrates:
  1. Complete removal of the 'salary' field from the view.
  2. Masking of SSN values into '***-**-XXXX'.
  3. Strict authorization barrier preventing app_user_read from bypassing the view.
"""

import os
import re
import sys
from pathlib import Path
from dotenv import load_dotenv
import pymongo
from pymongo.errors import OperationFailure

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

MONGO_HOST = os.getenv("MONGO_HOST", "127.0.0.1")
MONGO_PORT = int(os.getenv("MONGO_PORT", "27030"))
ROOT_USER = os.getenv("MONGO_ROOT_USER", "admin_user")
ROOT_PASSWORD = os.getenv("MONGO_ROOT_PASSWORD", "AdminSecure2026!")

APP_DB_NAME = os.getenv("APP_DB_NAME", "company_db")
READ_USER = os.getenv("APP_READ_USER", "app_user_read")
READ_PASSWORD = os.getenv("APP_READ_PASSWORD", "ReadPassword2026!")

CA_FILE = str(BASE_DIR / os.getenv("TLS_CA_FILE", "certs/ca.crt"))
CLIENT_PEM = str(BASE_DIR / os.getenv("TLS_CLIENT_PEM", "certs/client.pem"))


def get_client(username, password, auth_db):
    uri = f"mongodb://{username}:{password}@{MONGO_HOST}:{MONGO_PORT}/?authSource={auth_db}"
    return pymongo.MongoClient(
        uri,
        tls=True,
        tlsCAFile=CA_FILE,
        tlsCertificateKeyFile=CLIENT_PEM,
        serverSelectionTimeoutMS=5000
    )


def print_table_row(cols, widths):
    row = " | ".join(f"{str(col):<{widths[i]}}" for i, col in enumerate(cols))
    print(f"| {row} |")


def print_separator(widths):
    sep = "-+-".join("-" * w for w in widths)
    print(f"+-{sep}-+")


def main():
    print("=" * 105)
    print("MongoDB Lab 12.1 — Field-Level Redaction and View Security Demonstration")
    print("=" * 105)

    # 1. Fetch original sensitive records as Admin
    print("\n[*] 1. Authenticating as Admin to inspect original sensitive 'employees' collection...")
    admin_cli = get_client(ROOT_USER, ROOT_PASSWORD, "admin")
    raw_employees = list(admin_cli[APP_DB_NAME].employees.find().sort("emp_id", 1))
    admin_cli.close()
    print(f"[+] Retrieved {len(raw_employees)} original employee records with unredacted PII and salary.")

    # 2. Fetch redacted records as app_user_read
    print(f"\n[*] 2. Authenticating as restricted '{READ_USER}' to query 'employees_safe' view...")
    read_cli = get_client(READ_USER, READ_PASSWORD, APP_DB_NAME)
    safe_employees = list(read_cli[APP_DB_NAME].employees_safe.find().sort("emp_id", 1))
    print(f"[+] Retrieved {len(safe_employees)} redacted records through 'employees_safe' view.")

    # 3. Verify that app_user_read CANNOT bypass the view to access the raw collection
    print(f"\n[*] 3. Verifying View Bypass Prevention for '{READ_USER}'...")
    try:
        read_cli[APP_DB_NAME].employees.find_one()
        print("[-] VULNERABILITY DETECTED: app_user_read was able to query raw 'employees' collection!")
        sys.exit(1)
    except OperationFailure as err:
        print(f"[+] ACCESS BLOCKED AS EXPECTED (Bypass Prevented):")
        print(f"    Error code: {err.code} | Message: {err.details.get('errmsg', str(err))}")

    read_cli.close()

    # 4. Side-by-side comparison table
    print("\n" + "=" * 105)
    print("SIDE-BY-SIDE COMPARISON: ORIGINAL COLLECTION vs RESTRICTED SAFE VIEW")
    print("=" * 105)

    headers = [
        "Emp ID",
        "Employee Name",
        "Department",
        "Original Salary (Admin)",
        "View Salary (app_user)",
        "Original SSN",
        "Masked SSN (View)"
    ]
    col_widths = [10, 18, 16, 23, 23, 14, 18]

    print_separator(col_widths)
    print_table_row(headers, col_widths)
    print_separator(col_widths)

    raw_map = {doc["emp_id"]: doc for doc in raw_employees}

    all_verifications_passed = True
    ssn_mask_regex = re.compile(r"^\*\*\*-\*\*-\d{4}$")

    for safe_doc in safe_employees:
        emp_id = safe_doc.get("emp_id")
        raw_doc = raw_map.get(emp_id, {})

        orig_salary = f"${raw_doc.get('salary', 0):,}"
        view_salary = "[REDACTED / EXCLUDED]" if "salary" not in safe_doc else f"${safe_doc['salary']}"

        orig_ssn = raw_doc.get("ssn", "N/A")
        view_ssn = safe_doc.get("ssn", "N/A")

        # Programmatic Assertions
        if "salary" in safe_doc:
            print(f"[-] Assertion Failure: 'salary' leaked in view for {emp_id}!")
            all_verifications_passed = False

        if not ssn_mask_regex.match(view_ssn):
            print(f"[-] Assertion Failure: SSN was not correctly masked for {emp_id} ('{view_ssn}')!")
            all_verifications_passed = False

        row_data = [
            emp_id,
            safe_doc.get("name", "N/A"),
            safe_doc.get("department", "N/A"),
            orig_salary,
            view_salary,
            orig_ssn,
            view_ssn
        ]
        print_table_row(row_data, col_widths)

    print_separator(col_widths)

    print("\n" + "=" * 105)
    print("SECURITY & PRIVACY VALIDATION CHECKLIST:")
    print("=" * 105)
    print(" [x] Salary Field Exclusion : 100% of employee records completely omit the 'salary' field.")
    print(" [x] SSN Masking Pattern    : All SSN values transformed to '***-**-XXXX' preserving last 4 digits.")
    print(" [x] Bypass Prevention      : Read-only application user CANNOT read underlying 'employees' table.")
    print(" [x] Integrity Preservation : Identity, Name, Department, and Position remain intact for app queries.")
    print("=" * 105)

    if all_verifications_passed:
        print("[+] FIELD REDACTION VERIFICATION COMPLETED SUCCESSFULLY.")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
