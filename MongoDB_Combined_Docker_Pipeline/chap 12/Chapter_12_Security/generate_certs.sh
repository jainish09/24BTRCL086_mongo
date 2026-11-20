#!/usr/bin/env bash
# ==============================================================================
# LAB 12.2: TLS Certificate Authority, Server & Client Certificate Generator
# Generates:
#   1. Self-Signed Root CA (ca.key, ca.crt)
#   2. MongoDB Server Key, CSR, SAN-enabled Certificate, and server.pem
#   3. Authorized Client Key, CSR, ClientAuth Certificate, and client.pem
#   4. Rogue Client Certificate (untrusted CA) for negative TLS validation tests
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"

mkdir -p "${CERTS_DIR}"
cd "${CERTS_DIR}"

echo "[*] Working directory: ${CERTS_DIR}"

# 1. Root Certificate Authority (CA)
echo "[1/4] Generating Root Certificate Authority (CA)..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/C=US/ST=State/L=City/O=MongoDB-Security/OU=Security-CA/CN=MongoSecurityRootCA" \
  -out ca.crt

# 2. Server Private Key and Certificate with SAN (Subject Alternative Names)
echo "[2/4] Generating MongoDB Server Key and SAN-enabled Certificate..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=State/L=City/O=MongoDB-Security/OU=DatabaseServer/CN=localhost"

cat > server_ext.cnf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = chapter12-mongo-security
DNS.3 = mongo-sec
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -sha256 -extfile server_ext.cnf

# Combine certificate and private key into PEM for MongoDB server
cat server.crt server.key > server.pem

# 3. Authorized Client Certificate for PyMongo and mongosh (Mutual TLS)
echo "[3/4] Generating Authorized Client Certificate..."
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
  -subj "/C=US/ST=State/L=City/O=MongoDB-Security/OU=AppClient/CN=app_client"

cat > client_ext.cnf <<EOF
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 825 -sha256 -extfile client_ext.cnf

# Combine client certificate and private key into client.pem
cat client.crt client.key > client.pem

# 4. Rogue / Untrusted Client Certificate (signed by a different untrusted CA)
echo "[4/4] Generating Rogue Client Certificate (for negative TLS validation)..."
openssl genrsa -out rogue_ca.key 2048
openssl req -x509 -new -nodes -key rogue_ca.key -sha256 -days 365 \
  -subj "/CN=UntrustedRogueCA" -out rogue_ca.crt
openssl genrsa -out rogue_client.key 2048
openssl req -new -key rogue_client.key -out rogue_client.csr -subj "/CN=unauthorized_client"
openssl x509 -req -in rogue_client.csr -CA rogue_ca.crt -CAkey rogue_ca.key -CAcreateserial \
  -out rogue_client.crt -days 365 -sha256
cat rogue_client.crt rogue_client.key > rogue_client.pem

# Clean up temp config files
rm -f server_ext.cnf client_ext.cnf server.csr client.csr rogue_client.csr

echo "[+] TLS Certificates successfully generated in ${CERTS_DIR}:"
ls -la "${CERTS_DIR}"
