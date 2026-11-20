#!/usr/bin/env python3
"""
Certificate Generator for MongoDB Lab 12.2 (TLS / In-Transit Encryption).
Supports OpenSSL (via system PATH or Git distribution) or Python cryptography library.
Generates:
  1. ca.key, ca.crt (Self-signed Root CA)
  2. server.key, server.crt, server.pem (with SAN: localhost, chapter12-mongo-security, mongo-sec, 127.0.0.1)
  3. client.key, client.crt, client.pem (Client auth for PyMongo / mongosh)
  4. rogue_ca.key, rogue_ca.crt, rogue_client.pem (Untrusted cert for rejection testing)
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path


def find_openssl():
    cmd = shutil.which("openssl")
    if cmd:
        return cmd
    common_paths = [
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files\Git\bin\openssl.exe",
        r"C:\OpenSSL-Win64\bin\openssl.exe",
        r"C:\Program Files\OpenSSL\bin\openssl.exe",
    ]
    for p in common_paths:
        if os.path.exists(p):
            return p
    return None


def run_cmd(cmd, cwd):
    res = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Command failed ({' '.join(cmd)}):\n{res.stderr}")
    return res.stdout


def generate_with_openssl(openssl_bin, certs_dir: Path):
    print(f"[*] Using OpenSSL binary: {openssl_bin}")

    ca_key = certs_dir / "ca.key"
    ca_crt = certs_dir / "ca.crt"

    server_key = certs_dir / "server.key"
    server_csr = certs_dir / "server.csr"
    server_cnf = certs_dir / "server_ext.cnf"
    server_crt = certs_dir / "server.crt"
    server_pem = certs_dir / "server.pem"

    client_key = certs_dir / "client.key"
    client_csr = certs_dir / "client.csr"
    client_cnf = certs_dir / "client_ext.cnf"
    client_crt = certs_dir / "client.crt"
    client_pem = certs_dir / "client.pem"

    # 1. Root CA
    print("[1/4] Generating Root CA...")
    run_cmd([openssl_bin, "genrsa", "-out", str(ca_key), "4096"], certs_dir)
    run_cmd([
        openssl_bin, "req", "-x509", "-new", "-nodes",
        "-key", str(ca_key), "-sha256", "-days", "3650",
        "-subj", "/C=US/ST=SecurityState/L=DatabaseLab/O=MongoDB-Security/OU=RootCA/CN=MongoSecurityRootCA",
        "-out", str(ca_crt)
    ], certs_dir)

    # 2. Server Certificate with SAN
    print("[2/4] Generating Server Key and SAN-enabled Certificate...")
    run_cmd([openssl_bin, "genrsa", "-out", str(server_key), "2048"], certs_dir)
    run_cmd([
        openssl_bin, "req", "-new", "-key", str(server_key), "-out", str(server_csr),
        "-subj", "/C=US/ST=SecurityState/L=DatabaseLab/O=MongoDB-Security/OU=Server/CN=localhost"
    ], certs_dir)

    server_cnf.write_text(
        "authorityKeyIdentifier=keyid,issuer\n"
        "basicConstraints=CA:FALSE\n"
        "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        "subjectAltName = @alt_names\n\n"
        "[alt_names]\n"
        "DNS.1 = localhost\n"
        "DNS.2 = chapter12-mongo-security\n"
        "DNS.3 = mongo-sec\n"
        "IP.1 = 127.0.0.1\n",
        encoding="utf-8"
    )

    run_cmd([
        openssl_bin, "x509", "-req", "-in", str(server_csr),
        "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(server_crt), "-days", "825", "-sha256",
        "-extfile", str(server_cnf)
    ], certs_dir)

    # Combine server cert + key into server.pem for mongod
    with open(server_pem, "wb") as outfile:
        outfile.write(server_crt.read_bytes())
        outfile.write(b"\n")
        outfile.write(server_key.read_bytes())

    # 3. Client Certificate
    print("[3/4] Generating Authorized Client Certificate...")
    run_cmd([openssl_bin, "genrsa", "-out", str(client_key), "2048"], certs_dir)
    run_cmd([
        openssl_bin, "req", "-new", "-key", str(client_key), "-out", str(client_csr),
        "-subj", "/C=US/ST=SecurityState/L=DatabaseLab/O=MongoDB-Security/OU=Client/CN=app_client"
    ], certs_dir)

    client_cnf.write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage = digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = clientAuth\n",
        encoding="utf-8"
    )

    run_cmd([
        openssl_bin, "x509", "-req", "-in", str(client_csr),
        "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(client_crt), "-days", "825", "-sha256",
        "-extfile", str(client_cnf)
    ], certs_dir)

    with open(client_pem, "wb") as outfile:
        outfile.write(client_crt.read_bytes())
        outfile.write(b"\n")
        outfile.write(client_key.read_bytes())

    # 4. Rogue Untrusted Certificate for Negative Testing
    print("[4/4] Generating Rogue Untrusted Certificate (for negative tests)...")
    rogue_ca_key = certs_dir / "rogue_ca.key"
    rogue_ca_crt = certs_dir / "rogue_ca.crt"
    rogue_client_key = certs_dir / "rogue_client.key"
    rogue_client_csr = certs_dir / "rogue_client.csr"
    rogue_client_crt = certs_dir / "rogue_client.crt"
    rogue_client_pem = certs_dir / "rogue_client.pem"

    run_cmd([openssl_bin, "genrsa", "-out", str(rogue_ca_key), "2048"], certs_dir)
    run_cmd([
        openssl_bin, "req", "-x509", "-new", "-nodes",
        "-key", str(rogue_ca_key), "-sha256", "-days", "365",
        "-subj", "/CN=UntrustedRogueCA", "-out", str(rogue_ca_crt)
    ], certs_dir)
    run_cmd([openssl_bin, "genrsa", "-out", str(rogue_client_key), "2048"], certs_dir)
    run_cmd([
        openssl_bin, "req", "-new", "-key", str(rogue_client_key), "-out", str(rogue_client_csr),
        "-subj", "/CN=unauthorized_client"
    ], certs_dir)
    run_cmd([
        openssl_bin, "x509", "-req", "-in", str(rogue_client_csr),
        "-CA", str(rogue_ca_crt), "-CAkey", str(rogue_ca_key), "-CAcreateserial",
        "-out", str(rogue_client_crt), "-days", "365", "-sha256"
    ], certs_dir)

    with open(rogue_client_pem, "wb") as outfile:
        outfile.write(rogue_client_crt.read_bytes())
        outfile.write(b"\n")
        outfile.write(rogue_client_key.read_bytes())

    # Clean up intermediate files
    for temp_f in [server_csr, client_csr, rogue_client_csr, server_cnf, client_cnf]:
        if temp_f.exists():
            temp_f.unlink()

    print(f"[+] All certificates generated successfully in {certs_dir}")


def main():
    base_dir = Path(__file__).resolve().parent
    certs_dir = base_dir / "certs"
    certs_dir.mkdir(parents=True, exist_ok=True)

    openssl_bin = find_openssl()
    if not openssl_bin:
        print("[!] OpenSSL not found in PATH or standard Git directory.", file=sys.stderr)
        sys.exit(1)

    generate_with_openssl(openssl_bin, certs_dir)


if __name__ == "__main__":
    main()
