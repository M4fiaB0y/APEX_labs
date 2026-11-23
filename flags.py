import hmac
import hashlib
import os
import secrets

# Master secret key configuration file (excluded from Git).
# A cryptographically secure per-instance secret is generated on first run
# and persisted across application restarts.
SECRET_FILE_PATH = os.environ.get("APEX_SECRET_FILE", os.path.join(os.path.dirname(__file__), ".apex_secret"))

def load_or_create_instance_secret() -> str:
    """Loads the instance HMAC secret from disk or generates a new 64-character hex secret."""
    if os.path.exists(SECRET_FILE_PATH):
        try:
            with open(SECRET_FILE_PATH, "r", encoding="utf-8") as f:
                sec = f.read().strip()
                if len(sec) >= 32:
                    return sec
        except Exception:
            pass

    new_sec = secrets.token_hex(32)
    try:
        with open(SECRET_FILE_PATH, "w", encoding="utf-8") as f:
            f.write(new_sec)
    except Exception:
        pass
    return new_sec

def reset_instance_secret() -> str:
    """Forces generation of a brand-new instance secret for a full cyber range reset."""
    global MASTER_FLAG_SECRET
    new_sec = secrets.token_hex(32)
    with open(SECRET_FILE_PATH, "w", encoding="utf-8") as f:
        f.write(new_sec)
    MASTER_FLAG_SECRET = new_sec
    return new_sec

MASTER_FLAG_SECRET = load_or_create_instance_secret()

CHALLENGE_DEFINITIONS = {
    "bola_user_pii": {
        "title": "BOLA User PII Extraction",
        "category": "API1:2023 BOLA",
        "cvss": 8.8,
        "endpoint": "GET /api/v1/users/99",
        "hint": "Inspect how customer accounts and user IDs are referenced across /api/v1/users/{uid}."
    },
    "bola_bank_account": {
        "title": "BOLA Bank Vault Account Statement",
        "category": "API1:2023 BOLA",
        "cvss": 9.1,
        "endpoint": "GET /api/v1/accounts/APEX-VAULT-9999/statement",
        "hint": "Test account authorization boundaries across /api/v1/accounts/{account_num}/statement."
    },
    "bola_tx_delete": {
        "title": "BOLA Delete Audit Transaction",
        "category": "API1:2023 BOLA",
        "cvss": 7.8,
        "endpoint": "DELETE /api/v1/transactions/102",
        "hint": "Review transactions listed in the vault account statement and test transaction deletion permissions."
    },
    "bola_order_receipt": {
        "title": "BOLA Order Receipt Extraction",
        "category": "API1:2023 BOLA",
        "cvss": 8.6,
        "endpoint": "GET /api/v1/orders/99/receipt",
        "hint": "Examine order receipt retrieval across order numbers in /api/v1/orders/{oid}/receipt."
    },
    "bola_address_leak": {
        "title": "BOLA Customer Address Exposure",
        "category": "API1:2023 BOLA",
        "cvss": 8.2,
        "endpoint": "GET /api/v1/users/99/addresses",
        "hint": "Check if customer delivery addresses can be accessed across user IDs via /api/v1/users/{uid}/addresses."
    },
    "bola_card_delete": {
        "title": "BOLA Stored Payment Card Deletion",
        "category": "API1:2023 BOLA",
        "cvss": 7.5,
        "endpoint": "DELETE /api/v1/payments/3",
        "hint": "Inspect saved payment cards (/api/v1/users/{uid}/payments) and test if foreign cards can be purged via DELETE /api/v1/payments/{card_id}."
    },
    "auth_user_enum": {
        "title": "Broken Auth User Enumeration",
        "category": "API2:2023 Auth",
        "cvss": 6.5,
        "endpoint": "POST /api/v1/auth/login",
        "hint": "Analyze server error responses on /api/v1/auth/login when testing existent vs. non-existent usernames (e.g. admin)."
    },
    "auth_brute_force": {
        "title": "Broken Auth Credential Stuffing",
        "category": "API2:2023 Auth",
        "cvss": 8.4,
        "endpoint": "POST /api/v1/auth/login",
        "hint": "Test credential stuffing with common support passwords on /api/v1/auth/login for the support_agent account."
    },
    "jwt_none_alg": {
        "title": "JWT alg:none Signature Bypass",
        "category": "API2:2023 Auth",
        "cvss": 9.8,
        "endpoint": "POST /api/v1/auth/verify-jwt",
        "hint": "Test if /api/v1/auth/verify-jwt accepts tokens crafted with alg: 'none' in the JOSE header."
    },
    "jwt_kid_traversal": {
        "title": "JWT kid Path Traversal Bypass",
        "category": "API2:2023 Auth",
        "cvss": 9.4,
        "endpoint": "POST /api/v1/auth/verify-jwt",
        "hint": "Check if the key identifier (kid) parameter in /api/v1/auth/verify-jwt is vulnerable to path traversal (e.g. /dev/null)."
    },
    "jwt_key_confusion": {
        "title": "JWT HMAC Secret Key Recovery",
        "category": "API2:2023 Auth",
        "cvss": 7.9,
        "endpoint": "POST /api/v1/auth/refresh-session",
        "hint": "Test recovering the master HMAC signing key using standard wordlists against /api/v1/auth/refresh-session."
    },
    "auth_reset_predictable": {
        "title": "Deterministic Password Reset Token",
        "category": "API2:2023 Auth",
        "cvss": 8.1,
        "endpoint": "POST /api/v1/auth/reset-password",
        "hint": "Inspect the token generation algorithm disclosed in /api/v1/auth/reset-password and predict the token for admin@apexmart.local."
    },
    "mass_assign_privesc": {
        "title": "Mass Assignment Role Escalation",
        "category": "API3:2023 BOPLA",
        "cvss": 8.8,
        "endpoint": "POST /api/v1/auth/register",
        "hint": "Test injecting privileged user attributes (such as 'role' or 'wallet_balance') during registration on /api/v1/auth/register."
    },
    "excessive_data_leak": {
        "title": "Excessive Data Exposure in Reviews",
        "category": "API3:2023 BOPLA",
        "cvss": 7.5,
        "endpoint": "GET /api/v1/products/7/reviews",
        "hint": "Inspect the raw JSON response of /api/v1/products/{id}/reviews for sensitive internal schema properties hidden in the UI."
    },
    "graphql_batch_dos": {
        "title": "GraphQL Query Amplification & Batch DoS",
        "category": "API4:2023 DoS",
        "cvss": 7.5,
        "endpoint": "POST /api/v1/graphql",
        "hint": "Test sending a batch array of query operations in a single HTTP request to /api/v1/graphql."
    },
    "redos_email_validation": {
        "title": "ReDoS Catastrophic Backtracking",
        "category": "API4:2023 DoS",
        "cvss": 7.5,
        "endpoint": "POST /api/v1/coupons/validate",
        "hint": "Analyze the email validation regular expression returned by /api/v1/coupons/validate for catastrophic nested quantifiers."
    },
    "bfla_admin_export": {
        "title": "BFLA Unauthenticated Database Backup Dump",
        "category": "API5:2023 BFLA",
        "cvss": 9.8,
        "endpoint": "GET /api/v1/admin/backup/dump",
        "hint": "Investigate disallowed routes in robots.txt to discover unauthenticated administrative backup dump endpoints."
    },
    "bfla_method_tamper": {
        "title": "HTTP Method Tampering Bypass",
        "category": "API5:2023 BFLA",
        "cvss": 8.2,
        "endpoint": "PUT /api/v1/admin/maintenance",
        "hint": "Test alternative HTTP verbs (PUT, PATCH) on restricted administrative endpoints like /api/v1/admin/maintenance."
    },
    "gateway_header_bypass": {
        "title": "Gateway Header Rewrite Bypass",
        "category": "API5:2023 BFLA",
        "cvss": 8.8,
        "endpoint": "GET /api/v1/dashboard",
        "hint": "Test reverse-proxy URL rewrite headers (X-Original-URL, X-Rewrite-URL) to bypass gateway route restrictions on /api/v1/dashboard."
    },
    "business_negative_checkout": {
        "title": "Negative Balance Inversion Flow",
        "category": "API6:2023 Business",
        "cvss": 8.5,
        "endpoint": "POST /api/v1/cart/checkout",
        "hint": "Analyze how /api/v1/cart/checkout handles negative totals or inverted order settlement quantities."
    },
    "race_condition_voucher": {
        "title": "Concurrency Race Condition (TOCTOU)",
        "category": "API6:2023 Business",
        "cvss": 8.9,
        "endpoint": "POST /api/v1/coupons/apply",
        "hint": "Test concurrency (TOCTOU) by dispatching parallel asynchronous redemption requests for voucher APEXVIP500."
    },
    "ssrf_cloud_metadata": {
        "title": "Cloud Instance Metadata SSRF (IMDSv1)",
        "category": "API7:2023 SSRF",
        "cvss": 9.6,
        "endpoint": "GET /api/v1/vendor/webhook-test",
        "hint": "Test the outbound webhook ping utility with cloud metadata address http://169.254.169.254."
    },
    "ssrf_internal_port": {
        "title": "Internal Loopback Microservice Port Scan",
        "category": "API7:2023 SSRF",
        "cvss": 8.8,
        "endpoint": "GET /api/v1/vendor/webhook-test",
        "hint": "Probe internal loopback endpoints (http://127.0.0.1:5000/internal/system-metrics) via the outbound webhook tester."
    },
    "cors_null_origin": {
        "title": "CORS Null Origin Credential Theft",
        "category": "API8:2023 Misconfig",
        "cvss": 7.4,
        "endpoint": "GET /api/v1/user/credentials",
        "hint": "Send requests with Origin: null to /api/v1/user/credentials and evaluate reflected Access-Control-Allow-Origin headers."
    },
    "debug_env_dump": {
        "title": "Exposed Debug Environment & Secrets",
        "category": "API8:2023 Misconfig",
        "cvss": 8.6,
        "endpoint": "GET /api/v1/debug/environment",
        "hint": "Review robots.txt and frontend source maps to discover diagnostic debug endpoints."
    },
    "shadow_api_v0": {
        "title": "Deprecated Shadow API Wire Bypass",
        "category": "API9:2023 Inventory",
        "cvss": 8.3,
        "endpoint": "POST /api/v0.9/payments/direct-debit",
        "hint": "Investigate legacy unindexed API version prefixes discovered in robots.txt (/api/v0.9/)."
    },
    "swagger_docs_leak": {
        "title": "OpenAPI 3.0 Blueprint Leak",
        "category": "API9:2023 Inventory",
        "cvss": 5.3,
        "endpoint": "GET /api/v1/openapi.json",
        "hint": "Explore OpenAPI 3.0 documentation blueprints published at /docs or /api/v1/openapi.json."
    },
    "webhook_unverified_sig": {
        "title": "Spoofed Unsigned Webhook Event",
        "category": "API10:2023 Webhook",
        "cvss": 8.5,
        "endpoint": "POST /api/v1/webhooks/fulfillment",
        "hint": "Test if the fulfillment webhook receiver (/api/v1/webhooks/fulfillment) verifies the X-Apex-Signature header."
    },
    "sqli_transactions": {
        "title": "SQLite UNION SQL Injection",
        "category": "Injection (SQLi)",
        "cvss": 9.9,
        "endpoint": "GET /api/v1/products/search",
        "hint": "Test the product search parameter (/api/v1/products/search?q=) with single quotes and SQLite UNION SELECT queries."
    },
    "xxe_xml_invoice": {
        "title": "XML External Entity (XXE) Injection",
        "category": "Injection (XXE)",
        "cvss": 9.1,
        "endpoint": "POST /api/v1/vendor/invoice-upload",
        "hint": "Inject external entity definitions (ENTITY / SYSTEM) into the B2B XML invoice importer (/api/v1/vendor/invoice-upload)."
    },
    "graphql_introspection": {
        "title": "GraphQL Introspection & Hidden Mutations",
        "category": "GraphQL Recon",
        "cvss": 6.5,
        "endpoint": "POST /api/v1/graphql",
        "hint": "Submit a GraphQL __schema query to /api/v1/graphql to map hidden administrative mutations and types."
    }
}

def get_flag(challenge_id: str) -> str:
    """Derives a dynamic, anti-AI HMAC flag string.
    Example: APEX{BOLA_USER_PII_B8A4D2901F}
    """
    if challenge_id not in CHALLENGE_DEFINITIONS:
        challenge_id = "general"
    
    clean_tag = challenge_id.upper().replace("-", "_")
    token_sig = hmac.new(
        MASTER_FLAG_SECRET.encode(),
        challenge_id.encode(),
        hashlib.sha256
    ).hexdigest()[:10].upper()
    
    return f"APEX{{{clean_tag}_{token_sig}}}"

def verify_submitted_flag(flag_text: str):
    """Validates submitted flag against all known challenge HMAC signatures."""
    if not flag_text or not isinstance(flag_text, str):
        return None
    
    candidate = flag_text.strip()
    for cid in CHALLENGE_DEFINITIONS:
        expected = get_flag(cid)
        if hmac.compare_digest(candidate, expected):
            return cid
    return None

def get_all_flags_for_auditor():
    """Generates the master dictionary of all challenges and their derived flags for examiners."""
    result = {}
    for cid, meta in CHALLENGE_DEFINITIONS.items():
        result[cid] = {
            **meta,
            "flag": get_flag(cid)
        }
    return result

