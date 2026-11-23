# 🛡️ APEX: Enterprise API Security Cyber Range (2026 Edition)

[![OWASP API Top 10](https://img.shields.io/badge/OWASP-API%20Top%2010%20(2023)-red.svg)](https://owasp.org/www-project-api-security/)
[![Security Range](https://img.shields.io/badge/Range-Anti--AI%20Hardened-blue.svg)](#anti-ai--anti-scanner-architecture)
[![Flag Format](https://img.shields.io/badge/Flag%20Format-APEX%7B...%7D-purple.svg)](#anti-ai--anti-scanner-architecture)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-success.svg)](#-quick-start-automated--manual)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**APEX** is a production-grade, intentionally vulnerable enterprise e-commerce platform and API gateway engineered for realistic penetration testing, Red Team training, and AppSec candidate evaluations. Designed as a modern, high-complexity counterpart to classic testbeds like OWASP Juice Shop and crAPI, **APEX** models a real-world enterprise emporium for cryptographic hardware (HSMs, physical security dongles, SDR transceivers, seed vaults).

The application simulates modern multi-tier corporate microservices featuring REST endpoints, GraphQL query resolvers, B2B vendor XML invoice ingestion, unmonitored shadow APIs, and fulfillment webhooks.

---

## 🌟 Key Architectural Features

- **100% Real-World Architecture:** No artificial CTF gimmicks or instant-win buttons. All vulnerabilities reside within authentic business logic, authorization filters, and cryptographic parsers.
- **OWASP API Security Top 10 (2023) Complete Coverage:** 31 distinct exploitation vectors spanning authorization, authentication, resource exhaustion, business logic inversions, and cloud metadata SSRF.
- **Anti-AI & Scanner Hardened:** Built specifically so that automated LLMs and static regex crawlers (`grep -rn "APEX{"`) cannot harvest solutions without executing real multi-stage payloads.
- **Standardized Flag Format (`APEX{...}`):** All challenge flags follow the format `APEX{CHALLENGE_ID_HEX10}` derived via HMAC signatures.
- **Examiner Evaluation Portal (`/evaluator`):** Dedicated live matrix console for instructors and assessors to monitor candidate progress, CVSS scoring, and reset instances in real time.
- **1-Click Automated Launchers:**
  - **Windows (`start_lab.bat`):** Auto-detects or installs Python 3 silently, installs dependencies, initializes the database, handles port failover, and opens the browser.
  - **Linux / macOS (`start_lab.sh`):** Auto-installs Python 3 via system package managers (`apt`, `dnf`, `pacman`, `brew`), configures environment, seeds DB, handles port failover, and launches the browser.

---

## 🛡️ Anti-AI & Anti-Scanner Architecture

Most security labs suffer from static flag leakage, allowing candidates or automated tools to grep source code or inspect database seed files to solve challenges without understanding the vulnerability. **APEX** solves this via:

1. **Dynamic Runtime Cryptographic HMAC Derivation:** Flags are not static strings. They are generated dynamically at runtime using server-side HMAC signatures (`APEX{CHALLENGE_ID_HEX10}`). Grepping static repository files yields zero valid flags.
2. **Unrouted Database Secrets:** High-value root records reside inside the `admin_system_vault` table, which is not referenced by any standard route and can only be extracted via multi-column `UNION SELECT` SQLite injection.
3. **True Multithreaded Race Conditions:** The voucher redemption engine enforces sub-millisecond TOCTOU validation (`current_uses > max_uses`), requiring legitimate concurrent multithreading bursts rather than single requests.
4. **Context-Dependent Exploits:** Challenges require active session hijacking, JWT `alg:none` / `kid` path traversal manipulation, reverse-proxy gateway header injections, and DTD entity evaluation.

---

## 🗺️ Vulnerability Matrix (31 Vectors)

| Category | Vector Title | Endpoint | CVSS |
|---|---|---|---|
| **API1:2023 BOLA** | User Profile PII Extraction | `GET /api/v1/users/{id}` | 8.8 |
| **API1:2023 BOLA** | Master Corporate Vault Statement | `GET /api/v1/accounts/{num}/statement` | 9.1 |
| **API1:2023 BOLA** | Audit Transaction History Purge | `DELETE /api/v1/transactions/{id}` | 7.8 |
| **API1:2023 BOLA** | Arbitrary Order Receipt Exposure | `GET /api/v1/orders/{id}/receipt` | 8.6 |
| **API1:2023 BOLA** | Customer Delivery Address Leak | `GET /api/v1/users/{id}/addresses` | 8.2 |
| **API1:2023 BOLA** | Stored Payment Method Deletion | `DELETE /api/v1/payments/{id}` | 7.5 |
| **API2:2023 Broken Auth** | Differential Username Enumeration | `POST /api/v1/auth/login` | 6.5 |
| **API2:2023 Broken Auth** | Credential Stuffing & Helpdesk Breach | `POST /api/v1/auth/login` | 8.4 |
| **API2:2023 Broken Auth** | JWT `alg:none` Signature Bypass | `POST /api/v1/auth/verify-jwt` | 9.8 |
| **API2:2023 Broken Auth** | JWT `kid` Path Traversal (`/dev/null`) | `POST /api/v1/auth/verify-jwt` | 9.4 |
| **API2:2023 Broken Auth** | Master HMAC Signing Key Recovery | `POST /api/v1/auth/refresh-session` | 7.9 |
| **API2:2023 Broken Auth** | Deterministic Reset Token Predictability | `POST /api/v1/auth/reset-password` | 8.1 |
| **API3:2023 BOPLA** | Mass Assignment Privilege Escalation | `POST /api/v1/auth/register` | 8.8 |
| **API3:2023 BOPLA** | Excessive Data Exposure in Reviews | `GET /api/v1/products/{id}/reviews` | 7.5 |
| **API4:2023 Resource DoS** | GraphQL Batch Query Amplification | `POST /api/v1/graphql` | 7.5 |
| **API4:2023 Resource DoS** | Catastrophic ReDoS Backtracking | `POST /api/v1/coupons/validate` | 7.5 |
| **API5:2023 BFLA** | Unauthenticated Database Backup Dump | `GET /api/v1/admin/backup/dump` | 9.8 |
| **API5:2023 BFLA** | HTTP Verb / Method Tampering Bypass | `PUT /api/v1/admin/maintenance` | 8.2 |
| **API5:2023 BFLA** | Reverse-Proxy Header Rewrite (`X-Original-URL`) | `GET /api/v1/dashboard` | 8.8 |
| **API6:2023 Business Flow** | Negative Price Balance Inversion | `POST /api/v1/cart/checkout` | 8.5 |
| **API6:2023 Business Flow** | Concurrency Race Condition (TOCTOU) | `POST /api/v1/coupons/apply` | 8.9 |
| **API7:2023 SSRF** | Cloud Metadata Extraction (IMDSv1) | `GET /api/v1/vendor/webhook-test` | 9.6 |
| **API7:2023 SSRF** | Internal Loopback Microservice Port Scan | `GET /api/v1/vendor/webhook-test` | 8.8 |
| **API8:2023 Misconfig** | CORS Null Origin Credential Theft | `GET /api/v1/user/credentials` | 7.4 |
| **API8:2023 Misconfig** | Production Debug Environment Dump | `GET /api/v1/debug/environment` | 8.6 |
| **API9:2023 Inventory** | Deprecated Shadow API Wire Transfer | `POST /api/v0.9/payments/direct-debit` | 8.3 |
| **API9:2023 Inventory** | Exposed OpenAPI 3.0 Blueprint | `GET /api/v1/openapi.json` | 5.3 |
| **API10:2023 Webhook** | Unsigned Inbound Fulfillment Webhook | `POST /api/v1/webhooks/fulfillment` | 8.5 |
| **Injection (SQLi)** | Raw SQLite UNION Catalog Injection | `GET /api/v1/products/search?q=` | 9.9 |
| **Injection (XXE)** | XML External Entity Invoice Resolution | `POST /api/v1/vendor/invoice-upload` | 9.1 |
| **GraphQL Recon** | Introspection & Hidden Admin Mutations | `POST /api/v1/graphql` | 6.5 |

---

## 🚀 Quick Start (Automated & Manual)

### Option A: Windows 1-Click Launch (Recommended for Windows)
Simply double-click:
```cmd
start_lab.bat
```
The automated batch script will:
1. Detect Python 3. If missing, it will automatically download and install Python 3.
2. Verify and install application dependencies (`Flask`, `Requests`, `graphql-core`).
3. Initialize the SQLite database and seed cryptographic catalog data.
4. Detect open port availability dynamically (starts at 5000, scans upward if occupied).
5. Start the APEX gateway and auto-spawn your default web browser to the active port.

---

### Option B: Linux & macOS 1-Click Launch (Recommended for Linux/Mac)
Open terminal and run:
```bash
chmod +x start_lab.sh
./start_lab.sh
```
The automated shell script will:
1. Detect Python 3. If missing, it will install Python 3 via your package manager (`apt`, `dnf`, `pacman`, or `brew`).
2. Configure a virtual environment and install dependencies (`Flask`, `Requests`, `graphql-core`).
3. Initialize the database with dynamic HMAC flags.
4. Detect port availability dynamically (starts at 5000, scans upward if occupied).
5. Start the server and auto-spawn your default browser (`xdg-open` / `open`) on the active port.

---

### Option C: Manual Cross-Platform Startup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/api-apex-lab.git
   cd api-apex-lab
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize the database:**
   ```bash
   python database.py
   ```

4. **Start the application:**
   ```bash
   python app.py
   ```
   Navigate to: `http://127.0.0.1:5000/` (or active port shown in console)

---

## 🎯 How to Play & Test

1. **Browse the Storefront:** Explore products, read reviews, add items to cart, and test checkout flows at `http://127.0.0.1:5000/`.
2. **Inspect API Traffic:** Use **Burp Suite**, **OWASP ZAP**, **Postman**, or **curl** to map out endpoints and inspect headers.
3. **Consult the OpenAPI Blueprint:** Review `/docs` or fetch `/api/v1/openapi.json` to uncover parameters and route architectures.
4. **Submit Flags:** Click the **"CTF Flag Verification"** tab in the storefront navigation drawer to submit captured `APEX{...}` strings.

---

## 🧑‍🏫 Instructor & Examiner Guide

- **Live Evaluation Matrix:** Assessors can monitor candidate submissions in real time at:
  ```
  http://127.0.0.1:5000/evaluator
  ```
- **Resetting Database & Scores:** Click **"Reset DB & Scores"** on the evaluation portal or send:
  ```bash
  curl -s -X POST http://127.0.0.1:5000/api/v1/system/reset-db
  ```
- **Full Instance Secret Reset:** To rotate instance HMAC secrets and regenerate brand-new dynamic flags:
  ```bash
  curl -s -X POST http://127.0.0.1:5000/api/v1/system/reset-instance
  ```

---

## 🧪 Automated Verification Suite

To verify all endpoints, confirm zero false positives during normal user actions, and test exploit triggers:
```bash
python test_lab.py
```

---

## ⚖️ Disclaimer
**APEX** is intentionally vulnerable software created strictly for educational, security training, and defensive testing purposes. Do not deploy this application on public, unauthenticated networks or production environments.
