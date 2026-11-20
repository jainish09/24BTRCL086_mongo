#!/usr/bin/env python3
"""
TLS & In-Transit Encryption Test Suite for MongoDB Lab 12.2.
Validates:
  1. Plaintext connection rejection (Non-TLS connection is rejected).
  2. TLS connection with PyMongo using valid CA and client certificate.
  3. Strict hostname verification (validating SAN for localhost / 127.0.0.1 without bypasses).
  4. Untrusted CA rejection (connection rejected when client uses an untrusted CA).
  5. Mutual TLS rejection with rogue client certificate.
  6. Command-line mongosh TLS connection verification via docker exec.
"""

import os
import subprocess
import sys
from pathlib import Path
from dotenv import load_dotenv
import pymongo
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

MONGO_HOST = os.getenv("MONGO_HOST", "127.0.0.1")
MONGO_PORT = int(os.getenv("MONGO_PORT", "27030"))
ROOT_USER = os.getenv("MONGO_ROOT_USER", "admin_user")
ROOT_PASSWORD = os.getenv("MONGO_ROOT_PASSWORD", "AdminSecure2026!")

CA_FILE = str(BASE_DIR / os.getenv("TLS_CA_FILE", "certs/ca.crt"))
CLIENT_PEM = str(BASE_DIR / os.getenv("TLS_CLIENT_PEM", "certs/client.pem"))
ROGUE_CA = str(BASE_DIR / "certs/rogue_ca.crt")
ROGUE_CLIENT_PEM = str(BASE_DIR / "certs/rogue_client.pem")


def print_header(title):
    print("\n" + "=" * 80)
    print(f"[*] {title}")
    print("=" * 80)


def test_plaintext_rejected():
    print("[TEST 1] Plaintext (Non-TLS) Connection Rejection:")
    uri = f"mongodb://{MONGO_HOST}:{MONGO_PORT}/?serverSelectionTimeoutMS=2000"
    print(f"         Attempting unencrypted connection to: {uri} (tls=False)...")
    try:
        client = pymongo.MongoClient(uri, tls=False, serverSelectionTimeoutMS=2000)
        client.admin.command("ping")
        client.close()
        print("  [FAIL] Security Vulnerability: Plaintext connection succeeded! Server is not enforcing requireTLS.")
        return False
    except (ServerSelectionTimeoutError, ConnectionFailure) as err:
        print("  [PASS] Plaintext Connection REJECTED as expected by MongoDB (--tlsMode requireTLS).")
        print(f"         Caught Expected Error: {type(err).__name__}")
        return True
    except Exception as err:
        print(f"  [PASS] Connection terminated: {type(err).__name__}: {err}")
        return True


def test_valid_tls_pymongo():
    print("[TEST 2] Secure TLS Connection with PyMongo (CA + Client Certificate):")
    uri = f"mongodb://{ROOT_USER}:{ROOT_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/?authSource=admin"
    print(f"         Connecting with TLS, CA: {CA_FILE}, Client PEM: {CLIENT_PEM}...")
    try:
        client = pymongo.MongoClient(
            uri,
            tls=True,
            tlsCAFile=CA_FILE,
            tlsCertificateKeyFile=CLIENT_PEM,
            serverSelectionTimeoutMS=5000
        )
        res = client.admin.command("ping")
        client.close()
        print(f"  [PASS] TLS Handshake & Authentication Succeeded: {res}")
        return True
    except Exception as err:
        print(f"  [FAIL] TLS Connection Failed: {type(err).__name__}: {err}")
        return False


def test_hostname_verification():
    print("[TEST 3] Strict Hostname & SAN Validation (No tlsAllowInvalidHostnames):")
    # Connecting to '127.0.0.1' and 'localhost' which are explicit SANs in server.crt
    print("         Verifying server certificate against Subject Alternative Names...")
    try:
        # Explicitly ensure tlsAllowInvalidHostnames is False (the default)
        client = pymongo.MongoClient(
            f"mongodb://{ROOT_USER}:{ROOT_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/?authSource=admin",
            tls=True,
            tlsCAFile=CA_FILE,
            tlsCertificateKeyFile=CLIENT_PEM,
            tlsAllowInvalidHostnames=False,
            serverSelectionTimeoutMS=5000
        )
        res = client.admin.command("ping")
        client.close()
        print("  [PASS] Strict Hostname Verification Passed without workarounds.")
        return True
    except Exception as err:
        print(f"  [FAIL] Hostname verification failed: {err}")
        return False


def test_untrusted_ca_rejected():
    print("[TEST 4] Untrusted Root CA Rejection:")
    print(f"         Attempting connection with rogue untrusted CA: {ROGUE_CA}...")
    try:
        client = pymongo.MongoClient(
            f"mongodb://{MONGO_HOST}:{MONGO_PORT}/?serverSelectionTimeoutMS=2000",
            tls=True,
            tlsCAFile=ROGUE_CA,
            tlsCertificateKeyFile=CLIENT_PEM,
            serverSelectionTimeoutMS=2000
        )
        client.admin.command("ping")
        client.close()
        print("  [FAIL] Untrusted CA was accepted! Security failure.")
        return False
    except (ServerSelectionTimeoutError, ConnectionFailure) as err:
        print("  [PASS] Connection REJECTED as expected when CA is untrusted.")
        print(f"         Caught Expected Error: {type(err).__name__}")
        return True
    except Exception as err:
        print(f"  [PASS] Handshake failed as expected: {type(err).__name__}: {err}")
        return True


def test_rogue_client_cert_mtls():
    print("[TEST 5] Mutual TLS Validation with Rogue Client Certificate:")
    print(f"         Attempting connection presenting untrusted client cert: {ROGUE_CLIENT_PEM}...")
    try:
        client = pymongo.MongoClient(
            f"mongodb://{MONGO_HOST}:{MONGO_PORT}/?serverSelectionTimeoutMS=2000",
            tls=True,
            tlsCAFile=CA_FILE,
            tlsCertificateKeyFile=ROGUE_CLIENT_PEM,
            serverSelectionTimeoutMS=2000
        )
        client.admin.command("ping")
        client.close()
        print("  [FAIL] Rogue client certificate was accepted by server!")
        return False
    except (ServerSelectionTimeoutError, ConnectionFailure) as err:
        print("  [PASS] Rogue Client Certificate REJECTED by MongoDB server during mTLS handshake.")
        print(f"         Caught Expected Error: {type(err).__name__}")
        return True
    except Exception as err:
        print(f"  [PASS] Connection terminated during handshake: {type(err).__name__}: {err}")
        return True


def test_mongosh_tls():
    print("[TEST 6] Command-Line 'mongosh' Connection with TLS & Certificates:")
    cmd = [
        "docker", "exec", "chapter12-mongo-security",
        "mongosh",
        "--tls",
        "--tlsCAFile", "/etc/ssl/mongo/ca.crt",
        "--tlsCertificateKeyFile", "/etc/ssl/mongo/client.pem",
        "-u", ROOT_USER,
        "-p", ROOT_PASSWORD,
        "--authenticationDatabase", "admin",
        "--eval", "db.adminCommand('ping')"
    ]
    print(f"         Executing in container: {' '.join(cmd[:6])} ...")
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0 and "{ ok: 1 }" in res.stdout:
            print("  [PASS] mongosh connected successfully over TLS and verified admin ping.")
            print(f"         Output: {res.stdout.strip()}")
            return True
        else:
            print(f"  [FAIL] mongosh failed (Exit code {res.returncode}):\n{res.stderr}\n{res.stdout}")
            return False
    except Exception as err:
        print(f"  [FAIL] Failed to execute docker exec mongosh: {err}")
        return False


def main():
    print_header("MongoDB Lab 12.2 — TLS and Encryption in Transit Verification")

    results = []
    results.append(("Plaintext Non-TLS Connection Rejected", test_plaintext_rejected()))
    results.append(("Valid TLS Connection (PyMongo + Client Cert)", test_valid_tls_pymongo()))
    results.append(("Strict Hostname & SAN Validation", test_hostname_verification()))
    results.append(("Untrusted CA Rejection", test_untrusted_ca_rejected()))
    results.append(("Rogue Client Certificate mTLS Rejection", test_rogue_client_cert_mtls()))
    results.append(("mongosh TLS CLI Verification", test_mongosh_tls()))

    print("\n" + "=" * 80)
    print("TLS TEST RESULTS SUMMARY")
    print("=" * 80)
    all_ok = True
    for name, ok in results:
        status_str = "[PASS]" if ok else "[FAIL]"
        if not ok:
            all_ok = False
        print(f" {status_str} | {name}")
    print("=" * 80)

    if all_ok:
        print("[+] ALL TLS & ENCRYPTION IN TRANSIT TESTS PASSED PERFECTLY.")
        sys.exit(0)
    else:
        print("[-] SOME TLS TESTS FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
