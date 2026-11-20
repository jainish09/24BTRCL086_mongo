#!/usr/bin/env python3
"""
Permission and RBAC Verification Suite for MongoDB Lab 12.1.
Verifies:
  1. Admin authentication and unrestricted access.
  2. app_user_read:
     - Permitted: find on employees_safe view, find on departments
     - Blocked: find on raw employees (Bypass prevention), insert on departments, find on audit_logs
  3. app_user_write:
     - Permitted: find, insert, update, delete on audit_logs
     - Blocked: find on employees, find on employees_safe, drop collection
"""

import os
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
WRITE_USER = os.getenv("APP_WRITE_USER", "app_user_write")
WRITE_PASSWORD = os.getenv("APP_WRITE_PASSWORD", "WritePassword2026!")

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


def run_test(test_name, action_fn, should_succeed=True):
    try:
        result = action_fn()
        if should_succeed:
            print(f"  [PASS] {test_name} - Operation Succeeded as expected.")
            return True, result
        else:
            print(f"  [FAIL] {test_name} - Expected failure, but operation succeeded!")
            return False, result
    except OperationFailure as err:
        if not should_succeed:
            print(f"  [PASS] {test_name} - Authorization Denied as expected: {err.details.get('errmsg', str(err))}")
            return True, err
        else:
            print(f"  [FAIL] {test_name} - Unexpected Authorization Failure: {err}")
            return False, err
    except Exception as err:
        print(f"  [FAIL] {test_name} - Unexpected Exception: {type(err).__name__}: {err}")
        return False, err


def main():
    print("=" * 80)
    print("MongoDB Lab 12.1 — Authentication and RBAC Verification Suite")
    print("=" * 80)

    test_results = []

    # ==========================================================================
    # 1. Admin Verification
    # ==========================================================================
    print("\n[SECTION 1] Administrative User Verification (admin_user):")
    admin_cli = get_client(ROOT_USER, ROOT_PASSWORD, "admin")

    p, _ = run_test(
        "Admin Auth & Ping",
        lambda: admin_cli.admin.command("ping"),
        should_succeed=True
    )
    test_results.append(("Admin Authentication", p))

    p, docs = run_test(
        "Admin Read Raw Sensitive 'employees' Collection",
        lambda: list(admin_cli[APP_DB_NAME].employees.find({"emp_id": "EMP-1001"}, {"_id": 0})),
        should_succeed=True
    )
    test_results.append(("Admin Read Raw Employees", p))
    if p and docs:
        print(f"         Raw Employee Record: {docs[0]}")

    admin_cli.close()

    # ==========================================================================
    # 2. app_user_read Verification
    # ==========================================================================
    print(f"\n[SECTION 2] Read-Only User Verification ({READ_USER}):")
    read_cli = get_client(READ_USER, READ_PASSWORD, APP_DB_NAME)
    company_db_read = read_cli[APP_DB_NAME]

    # Permitted 1: Read employees_safe view
    p, safe_docs = run_test(
        f"{READ_USER} query view 'employees_safe'",
        lambda: list(company_db_read.employees_safe.find({}, {"_id": 0}).limit(2)),
        should_succeed=True
    )
    test_results.append((f"{READ_USER} - Read Safe View", p))
    if p and safe_docs:
        print(f"         Sample Safe View Document: {safe_docs[0]}")

    # Permitted 2: Read departments collection
    p, depts = run_test(
        f"{READ_USER} query collection 'departments'",
        lambda: list(company_db_read.departments.find({}, {"_id": 0}).limit(1)),
        should_succeed=True
    )
    test_results.append((f"{READ_USER} - Read Departments", p))

    # Unauthorized 1: Attempt to read raw sensitive 'employees' collection directly (View Bypass Prevention)
    p, _ = run_test(
        f"{READ_USER} BYPASS ATTEMPT: query raw 'employees' directly",
        lambda: list(company_db_read.employees.find({})),
        should_succeed=False
    )
    test_results.append((f"{READ_USER} - Blocked Raw Employees Access", p))

    # Unauthorized 2: Attempt to write into departments
    p, _ = run_test(
        f"{READ_USER} unauthorized write to 'departments'",
        lambda: company_db_read.departments.insert_one({"dept_id": "HACK", "name": "Unauthorized"}),
        should_succeed=False
    )
    test_results.append((f"{READ_USER} - Blocked Write to Departments", p))

    # Unauthorized 3: Attempt to read audit_logs
    p, _ = run_test(
        f"{READ_USER} unauthorized read from 'audit_logs'",
        lambda: list(company_db_read.audit_logs.find({})),
        should_succeed=False
    )
    test_results.append((f"{READ_USER} - Blocked Read from Audit Logs", p))

    read_cli.close()

    # ==========================================================================
    # 3. app_user_write Verification
    # ==========================================================================
    print(f"\n[SECTION 3] Read-Write User Verification ({WRITE_USER}):")
    write_cli = get_client(WRITE_USER, WRITE_PASSWORD, APP_DB_NAME)
    company_db_write = write_cli[APP_DB_NAME]

    test_log_id = "LOG-RBAC-TEST-999"

    # Permitted 1: Insert into audit_logs
    p, ins_res = run_test(
        f"{WRITE_USER} insert into 'audit_logs'",
        lambda: company_db_write.audit_logs.insert_one({
            "log_id": test_log_id,
            "event": "PERMISSION_VERIFY_EXEC",
            "performed_by": WRITE_USER,
            "status": "IN_PROGRESS"
        }).inserted_id,
        should_succeed=True
    )
    test_results.append((f"{WRITE_USER} - Insert Audit Log", p))

    # Permitted 2: Read (find) from audit_logs
    p, found_log = run_test(
        f"{WRITE_USER} find in 'audit_logs'",
        lambda: company_db_write.audit_logs.find_one({"log_id": test_log_id}, {"_id": 0}),
        should_succeed=True
    )
    test_results.append((f"{WRITE_USER} - Find Audit Log", p))

    # Permitted 3: Update in audit_logs
    p, upd_res = run_test(
        f"{WRITE_USER} update record in 'audit_logs'",
        lambda: company_db_write.audit_logs.update_one(
            {"log_id": test_log_id},
            {"$set": {"status": "COMPLETED"}}
        ).modified_count,
        should_succeed=True
    )
    test_results.append((f"{WRITE_USER} - Update Audit Log", p))

    # Permitted 4: Delete (remove) from audit_logs
    p, del_res = run_test(
        f"{WRITE_USER} delete record from 'audit_logs'",
        lambda: company_db_write.audit_logs.delete_one({"log_id": test_log_id}).deleted_count,
        should_succeed=True
    )
    test_results.append((f"{WRITE_USER} - Delete Audit Log", p))

    # Unauthorized 1: Attempt to read raw employees
    p, _ = run_test(
        f"{WRITE_USER} unauthorized read from 'employees'",
        lambda: list(company_db_write.employees.find({})),
        should_succeed=False
    )
    test_results.append((f"{WRITE_USER} - Blocked Read Employees", p))

    # Unauthorized 2: Attempt to read employees_safe view
    p, _ = run_test(
        f"{WRITE_USER} unauthorized read from 'employees_safe'",
        lambda: list(company_db_write.employees_safe.find({})),
        should_succeed=False
    )
    test_results.append((f"{WRITE_USER} - Blocked Read Safe View", p))

    # Unauthorized 3: Attempt to drop audit_logs collection
    p, _ = run_test(
        f"{WRITE_USER} unauthorized drop collection 'audit_logs'",
        lambda: company_db_write.audit_logs.drop(),
        should_succeed=False
    )
    test_results.append((f"{WRITE_USER} - Blocked Drop Collection", p))

    write_cli.close()

    # ==========================================================================
    # Summary Table
    # ==========================================================================
    print("\n" + "=" * 80)
    print("RBAC TEST RESULTS SUMMARY")
    print("=" * 80)
    all_passed = True
    for name, passed in test_results:
        status_str = "[PASS]" if passed else "[FAIL]"
        if not passed:
            all_passed = False
        print(f" {status_str} | {name}")
    print("=" * 80)

    if all_passed:
        print("[+] ALL RBAC & PERMISSION TESTS PASSED PERFECTLY.")
        sys.exit(0)
    else:
        print("[-] SOME TESTS FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
