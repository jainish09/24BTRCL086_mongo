#!/usr/bin/env python3
"""
Python RBAC & Security Initializer for MongoDB Lab 12.1.
Connects as Admin over TLS to create collections, sample data, custom roles,
the redacted view (employees_safe), and application users.
"""

import os
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


def get_admin_client():
    uri = f"mongodb://{ROOT_USER}:{ROOT_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/?authSource=admin"
    client = pymongo.MongoClient(
        uri,
        tls=True,
        tlsCAFile=CA_FILE,
        tlsCertificateKeyFile=CLIENT_PEM,
        serverSelectionTimeoutMS=5000
    )
    return client


def initialize_security():
    print("=" * 70)
    print(f"[*] Initializing MongoDB RBAC & Security on {MONGO_HOST}:{MONGO_PORT}...")
    print("=" * 70)

    client = get_admin_client()
    # Test admin connectivity
    client.admin.command("ping")
    print("[+] Successfully authenticated as Admin via TLS.")

    company_db = client[APP_DB_NAME]

    # 1. Base collections
    print("\n[1/5] Populating base collections...")
    company_db.employees.drop()
    sample_employees = [
        {
            "emp_id": "EMP-1001",
            "name": "Alice Johnson",
            "department": "Engineering",
            "position": "Senior Security Architect",
            "salary": 145000,
            "ssn": "111-22-3333",
            "email": "alice.j@corp.local"
        },
        {
            "emp_id": "EMP-1002",
            "name": "Bob Smith",
            "department": "Finance",
            "position": "Financial Analyst",
            "salary": 98000,
            "ssn": "222-33-4444",
            "email": "bob.s@corp.local"
        },
        {
            "emp_id": "EMP-1003",
            "name": "Carol White",
            "department": "Human Resources",
            "position": "HR Director",
            "salary": 120000,
            "ssn": "333-44-5555",
            "email": "carol.w@corp.local"
        },
        {
            "emp_id": "EMP-1004",
            "name": "David Brown",
            "department": "Engineering",
            "position": "DevOps Engineer",
            "salary": 115000,
            "ssn": "444-55-6666",
            "email": "david.b@corp.local"
        },
        {
            "emp_id": "EMP-1005",
            "name": "Eva Martinez",
            "department": "Product",
            "position": "Product Manager",
            "salary": 130000,
            "ssn": "555-66-7777",
            "email": "eva.m@corp.local"
        }
    ]
    company_db.employees.insert_many(sample_employees)
    print(f"    [+] Inserted {len(sample_employees)} records into '{APP_DB_NAME}.employees'.")

    company_db.departments.drop()
    sample_depts = [
        {"dept_id": "D-01", "name": "Engineering", "floor": 4, "head": "Alice Johnson"},
        {"dept_id": "D-02", "name": "Finance", "floor": 2, "head": "Bob Smith"},
        {"dept_id": "D-03", "name": "Human Resources", "floor": 3, "head": "Carol White"},
        {"dept_id": "D-04", "name": "Product", "floor": 4, "head": "Eva Martinez"}
    ]
    company_db.departments.insert_many(sample_depts)

    company_db.audit_logs.drop()
    company_db.audit_logs.insert_one({
        "log_id": "LOG-INIT-001",
        "event": "BOOTSTRAP_COMPLETE",
        "performed_by": "admin_user",
        "status": "INITIALIZED"
    })
    print("    [+] Populated 'departments' and 'audit_logs' collections.")

    # 2. View: employees_safe (Field-Level Redaction)
    print("\n[2/5] Creating field-level redaction view 'employees_safe'...")
    try:
        company_db.command("drop", "employees_safe")
    except OperationFailure:
        pass

    redaction_pipeline = [
        {
            "$project": {
                "_id": 1,
                "emp_id": 1,
                "name": 1,
                "department": 1,
                "position": 1,
                "email": 1,
                # 'salary' is omitted completely
                "ssn": {
                    "$concat": [
                        "***-**-",
                        {"$substrCP": ["$ssn", 7, 4]}
                    ]
                }
            }
        }
    ]
    company_db.command({
        "create": "employees_safe",
        "viewOn": "employees",
        "pipeline": redaction_pipeline
    })
    print("    [+] View 'employees_safe' created (Salary excluded, SSN masked).")

    # 3. Custom MongoDB Roles
    print("\n[3/5] Creating custom MongoDB roles in database 'company_db'...")
    try:
        company_db.command("dropRole", "custom_read_safe_role")
    except OperationFailure:
        pass
    try:
        company_db.command("dropRole", "custom_write_audit_role")
    except OperationFailure:
        pass

    # Role 1: Read-only on specifically authorized collections (employees_safe, departments)
    company_db.command({
        "createRole": "custom_read_safe_role",
        "privileges": [
            {
                "resource": {"db": APP_DB_NAME, "collection": "employees_safe"},
                "actions": ["find"]
            },
            {
                "resource": {"db": APP_DB_NAME, "collection": "departments"},
                "actions": ["find"]
            }
        ],
        "roles": []
    })
    print("    [+] Custom Role 'custom_read_safe_role' created.")

    # Role 2: Read, Insert, Update, Delete on specifically authorized collection (audit_logs)
    company_db.command({
        "createRole": "custom_write_audit_role",
        "privileges": [
            {
                "resource": {"db": APP_DB_NAME, "collection": "audit_logs"},
                "actions": ["find", "insert", "update", "remove"]
            }
        ],
        "roles": []
    })
    print("    [+] Custom Role 'custom_write_audit_role' created.")

    # 4. Create Application Users
    print("\n[4/5] Creating application users...")
    try:
        company_db.command("dropUser", READ_USER)
    except OperationFailure:
        pass
    try:
        company_db.command("dropUser", WRITE_USER)
    except OperationFailure:
        pass

    company_db.command({
        "createUser": READ_USER,
        "pwd": READ_PASSWORD,
        "roles": [
            {"role": "custom_read_safe_role", "db": APP_DB_NAME}
        ]
    })
    print(f"    [+] User '{READ_USER}' created with role 'custom_read_safe_role'.")

    company_db.command({
        "createUser": WRITE_USER,
        "pwd": WRITE_PASSWORD,
        "roles": [
            {"role": "custom_write_audit_role", "db": APP_DB_NAME}
        ]
    })
    print(f"    [+] User '{WRITE_USER}' created with role 'custom_write_audit_role'.")

    print("\n[5/5] RBAC Initialization Finished Successfully.")
    print("=" * 70)
    client.close()


if __name__ == "__main__":
    initialize_security()
