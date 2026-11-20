# Chapter 12: MongoDB Database Security (RBAC & TLS Encryption in Transit)

A production-grade implementation of MongoDB enterprise database security, covering:
1. **LAB 12.1**: Authentication (`--auth`), Role-Based Access Control (RBAC), Custom Roles via `db.createRole()`, Collection-level scoping, and Field-Level Redaction (Salary omission + SSN masking) using MongoDB Views.
2. **LAB 12.2**: TLS / In-Transit Encryption (`--tlsMode requireTLS`), Self-Signed Root Certificate Authority (CA), Server Certificates with Subject Alternative Names (SAN: `localhost`, `chapter12-mongo-security`, `mongo-sec`, `127.0.0.1`), Client Certificates for Mutual TLS (mTLS), and strict rejection of unencrypted / untrusted connections.

---

## Architecture & Security Highlights

| Feature | Implementation | Security Benefit |
| :--- | :--- | :--- |
| **Authentication** | Mandatory `--auth` flag | Anonymous access denied on all ports. |
| **Encryption in Transit** | `--tlsMode requireTLS` | All plaintext communication rejected at transport layer. |
| **Server Identity** | X.509 with Subject Alternative Names (SAN) | Prevents DNS spoofing and MITM attacks without disabling validation. |
| **Mutual TLS (mTLS)** | Client certificate verification against Root CA | Both client and server authenticate cryptographically. |
| **Custom Scoped RBAC** | `custom_read_safe_role` & `custom_write_audit_role` | Strict principle of least privilege per collection and action. |
| **Field-Level Redaction** | MongoDB View (`employees_safe`) | Drops `salary` completely; masks SSN to `***-**-XXXX`. |
| **View Bypass Prevention** | Collection-level privileges | Application users cannot query the underlying sensitive collection. |

---

## Directory Structure

```text
Chapter_12_Security/
├── certs/                      # Generated X.509 certificates & private keys (.gitignored)
│   ├── ca.crt / ca.key         # Root Certificate Authority
│   ├── server.crt / server.pem # Server Certificate with SANs & combined PEM
│   ├── client.crt / client.pem # Authorized Client Certificate for PyMongo/mongosh
│   └── rogue_*                 # Untrusted certs used for negative TLS testing
├── .env.example                # Template for environment variables and credentials
├── .env                        # Local credentials and port configurations (.gitignored)
├── .gitignore                  # Git safeguard preventing credential and cert commits
├── Dockerfile                  # Containerized Python security test runner
├── docker-compose.yml          # MongoDB 7.0 secure service with persistent storage & healthchecks
├── generate_certs.sh           # Bash OpenSSL certificate generation script
├── generate_certs.py           # Cross-platform Python certificate generation script
├── init_rbac.js                # Shell RBAC initialization script (auto-executed by entrypoint)
├── init_rbac.py                # Python PyMongo RBAC initializer over TLS
├── test_rbac.py                # Test suite for admin, read-only, and read-write user permissions
├── field_redaction.py          # Field-level redaction comparator and bypass verification
├── test_tls.py                 # TLS test suite (rejection of plaintext, mTLS, SAN check)
├── run_all_tests.py            # Master end-to-end automated test runner
├── run_lab12.bat               # Windows 1-click batch runner
├── README.md                   # Complete documentation
└── report.md                   # Engineering report with actual test executions and logs
```

---

## Quick Start (Automated)

### Option A: Windows 1-Click
Double-click or run:
```cmd
run_lab12.bat
```

### Option B: Manual Step-by-Step

#### 1. Generate TLS Certificates
Using Python:
```bash
python generate_certs.py
```
Or using Bash with OpenSSL:
```bash
chmod +x generate_certs.sh
./generate_certs.sh
```

#### 2. Start Secure MongoDB Container
```bash
docker compose up -d mongo-sec
```
*Note: Port `27030` is exposed locally on `127.0.0.1` to avoid conflicting with existing MongoDB chapters (ports 27017–27027).*

#### 3. Run the Security & Validation Suites
```bash
# Run all tests end-to-end:
python run_all_tests.py

# Or run individual tests:
python test_tls.py
python init_rbac.py
python test_rbac.py
python field_redaction.py
```

---

## Detailed Lab Workflows

### LAB 12.1 — Authentication & RBAC

1. **Administrative Authentication**:
   - MongoDB initializes with a root administrative user (`admin_user`) on the `admin` database.
2. **Custom Scoped Roles**:
   - `custom_read_safe_role` on `company_db`:
     - Allowed: `find` on `employees_safe` view and `departments`.
     - Denied: Access to raw `employees` collection, write operations, administrative actions.
   - `custom_write_audit_role` on `company_db`:
     - Allowed: `find`, `insert`, `update`, `remove` on `audit_logs` only.
     - Denied: Access to employee data, dropping collections.
3. **Application Users**:
   - `app_user_read`: Assigned `custom_read_safe_role`.
   - `app_user_write`: Assigned `custom_write_audit_role`.
4. **Field-Level Redaction View (`employees_safe`)**:
   ```javascript
   db.createView("employees_safe", "employees", [
     {
       $project: {
         _id: 1,
         emp_id: 1,
         name: 1,
         department: 1,
         position: 1,
         email: 1,
         ssn: {
           $concat: [
             "***-**-",
             { $substrCP: ["$ssn", 7, 4] }
           ]
         }
       }
     }
   ]);
   ```
5. **View Bypass Protection**:
   `app_user_read` only has find privilege on `company_db.employees_safe`. When they attempt to query `company_db.employees` directly, MongoDB rejects the command with `Error code: 13 (Unauthorized)`.

---

### LAB 12.2 — TLS / In-Transit Encryption

1. **Self-Signed Root CA**:
   Generated with OpenSSL using RSA 4096-bit key and SHA-256 (`ca.crt`, `ca.key`).
2. **SAN-Enabled Server Certificate**:
   Subject Alternative Names added:
   - `DNS:localhost`
   - `DNS:chapter12-mongo-security`
   - `DNS:mongo-sec`
   - `IP:127.0.0.1`
   Combined certificate and private key saved as `server.pem`.
3. **Authorized Client Certificate**:
   Generated with `extendedKeyUsage = clientAuth` (`client.pem`).
4. **MongoDB Daemon Configuration**:
   ```yaml
   command: [
     "mongod",
     "--auth",
     "--tlsMode", "requireTLS",
     "--tlsCertificateKeyFile", "/etc/ssl/mongo/server.pem",
     "--tlsCAFile", "/etc/ssl/mongo/ca.crt",
     "--bind_ip_all"
   ]
   ```
5. **Validation Matrix**:
   - Plaintext unencrypted connections: **REJECTED** (`ServerSelectionTimeoutError`).
   - PyMongo with valid CA & Client Cert: **ACCEPTED**.
   - Hostname verification without bypasses: **ACCEPTED**.
   - Untrusted CA: **REJECTED**.
   - Rogue Client Certificate: **REJECTED**.
   - CLI `mongosh` over TLS: **ACCEPTED**.

---

## Docker Hub Submission Guidelines

When packaging Chapter 12 for Docker Hub:

### 1. Build the Custom Test Runner Image
```bash
docker build -t <your-dockerhub-username>/mongodb-security-runner:latest .
```

### 2. Verify Secrets & Certificates Are NOT Baked into Image
The `Dockerfile` copies only code (`*.py` and `.env.example`). The `certs/` directory is mounted at runtime via Docker volumes and excluded by `.dockerignore` / `.gitignore`.
Never commit or bake `ca.key`, `server.pem`, or `.env` into public images.

### 3. Tag and Push
```bash
docker tag <your-dockerhub-username>/mongodb-security-runner:latest <your-dockerhub-username>/mongodb-security-runner:1.0.0
docker push <your-dockerhub-username>/mongodb-security-runner:1.0.0
```
*(Only execute the push command after obtaining explicit approval).*
