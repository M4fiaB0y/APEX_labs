import os
import re
import io
import json
import base64
import hmac
import hashlib
import time
import secrets
import sqlite3
import threading
import urllib.request
import urllib.parse
import xml.sax
import xml.sax.handler
from datetime import datetime
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify, render_template, session, make_response, Response

try:
    import graphql
    GRAPHQL_AVAILABLE = True
except ImportError:
    GRAPHQL_AVAILABLE = False

if GRAPHQL_AVAILABLE:
    GRAPHQL_SCHEMA_SDL = """
    type Product {
        id: Int!
        name: String!
        category: String!
        price: Float!
        stock: Int!
    }

    type User {
        id: Int!
        username: String!
        role: String!
        email: String!
        walletBalance: Float!
    }

    type Query {
        products: [Product!]!
        product(id: Int!): Product
        currentUser: User
        systemStatus: String
    }

    type Mutation {
        applyStaffDiscount(voucherCode: String!): String
        deleteUserAccount(userId: Int!): Boolean
        emergencyDrainBalance(targetAccount: String!): Float
    }
    """
    GRAPHQL_SCHEMA = graphql.build_schema(GRAPHQL_SCHEMA_SDL)

    def _resolve_products(*args, **kwargs):
        conn = database.get_db()
        rows = conn.execute("SELECT id, name, category, price, stock FROM products").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def _resolve_product(*args, **kwargs):
        id_val = kwargs.get("id", 1)
        conn = database.get_db()
        r = conn.execute("SELECT id, name, category, price, stock FROM products WHERE id = ?", (id_val,)).fetchone()
        conn.close()
        return dict(r) if r else None

    def _resolve_current_user(*args, **kwargs):
        return {
            "id": 1,
            "username": "alice",
            "role": "customer",
            "email": "alice@apexmart.local",
            "walletBalance": 2450.0
        }

    def _resolve_system_status(*args, **kwargs):
        return "APEX Enterprise GraphQL Gateway 2026.4 Operational"

    GRAPHQL_ROOT_VALUE = {
        "products": _resolve_products,
        "product": _resolve_product,
        "currentUser": _resolve_current_user,
        "systemStatus": _resolve_system_status,
    }
else:
    GRAPHQL_SCHEMA = None
    GRAPHQL_ROOT_VALUE = None

import database
import flags
from flags import get_flag, verify_submitted_flag, CHALLENGE_DEFINITIONS

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "apex-enterprise-insecure-master-jwt-key"

try:
    PORT = int(os.environ.get("APEX_PORT", 5000))
except (ValueError, TypeError):
    PORT = 5000
database.init_db()

CLAIMS_KEY = "apex_claimed_flags"

def get_all_claimed_flags():
    """Returns persistent claimed challenge IDs merged with session claims."""
    db_claims = set(database.get_claimed_flags())
    session_claims = set(session.get(CLAIMS_KEY, []))
    merged = sorted(list(db_claims.union(session_claims)))
    session[CLAIMS_KEY] = merged
    return merged

def claim_flag(flag_id: str):
    is_new_db = database.add_claimed_flag(flag_id)
    claimed = session.get(CLAIMS_KEY, [])
    is_new_session = flag_id not in claimed
    if is_new_session:
        claimed.append(flag_id)
        session[CLAIMS_KEY] = claimed
    return is_new_db or is_new_session

# ==========================================
# 0. CORE RECON & STORE ENGINE ROUTES
# ==========================================
@app.route("/")
def home():
    if "user_id" not in session:
        session["user_id"] = 1
        session["username"] = "alice"
        session["role"] = "customer"
    return render_template("index.html")

@app.route("/evaluator")
def evaluator():
    return render_template("evaluator.html")

@app.route("/robots.txt")
def robots_txt():
    rules = """User-agent: *
Disallow: /api/v1/admin/backup/dump
Disallow: /api/v1/debug/environment
Disallow: /api/v0.9/
Disallow: /internal/
Disallow: /docs
Disallow: /evaluator
Disallow: /static/app.bundle.js.map
Sitemap: http://127.0.0.1:5000/sitemap.xml
"""
    return Response(rules, mimetype="text/plain")

@app.route("/sitemap.xml")
def sitemap_xml():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://127.0.0.1:5000/</loc></url>
  <url><loc>http://127.0.0.1:5000/docs</loc></url>
  <url><loc>http://127.0.0.1:5000/api/v1/openapi.json</loc></url>
</urlset>"""
    return Response(xml, mimetype="application/xml")

@app.route("/static/app.bundle.js.map")
def sourcemap_leak():
    return jsonify({
        "version": 3,
        "file": "app.bundle.js",
        "sources": ["src/auth/jwtService.ts", "src/admin/backupController.ts"],
        "mappings": "AAAA,SAASA...",
        "sourcesContent": [
            "// DEV NOTE: For test automation, verify-jwt allows kid: '/dev/null' or alg: 'none'.",
            "// ADMIN NOTE: Database backup dumps can be initiated directly via /api/v1/admin/backup/dump"
        ]
    })

@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "ApexMart E-Commerce & Cryptographic Hardware API Gateway",
        "version": "2026.4.1",
        "port": PORT,
        "database": "sqlite3_active",
        "timestamp": datetime.now().isoformat()
    })

@app.route("/docs")
def swagger_ui():
    return render_template("docs.html")

@app.route("/api/v1/openapi.json")
def openapi_spec():
    try:
        with open("openapi.json", "r") as f:
            data = json.load(f)
            data["_flag"] = get_flag("swagger_docs_leak")
            return jsonify(data)
    except Exception:
        return jsonify({"openapi": "3.0.0", "info": {"title": "ApexMart API", "version": "2026.4"}, "_flag": get_flag("swagger_docs_leak")})

# ==========================================
# 1. E-COMMERCE PRODUCTS & REVIEWS CATALOG
# ==========================================
@app.route("/api/v1/products")
def api_get_products():
    cat = request.args.get("category", "")
    conn = database.get_db()
    if cat and cat != "All":
        products = conn.execute("SELECT * FROM products WHERE category = ?", (cat,)).fetchall()
    else:
        products = conn.execute("SELECT * FROM products ORDER BY id ASC").fetchall()
    conn.close()
    return jsonify({"products": [dict(p) for p in products]})

@app.route("/api/v1/products/<int:pid>")
def api_get_product_detail(pid):
    conn = database.get_db()
    product = conn.execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
    if not product:
        conn.close()
        return jsonify({"error": "Product not found"}), 404
    reviews = conn.execute("SELECT * FROM reviews WHERE product_id = ?", (pid,)).fetchall()
    conn.close()
    return jsonify({
        "product": dict(product),
        "reviews": [dict(r) for r in reviews]
    })

@app.route("/api/v1/products/search")
@app.route("/api/v1/transactions/search", methods=["GET"])
def api_search_products_sqli():
    """Real SQLite UNION Injection in Product Catalog Search (Anti-AI).
    Extracts the unrouted admin_system_vault table containing MASTER_ROOT_FLAG.
    """
    q = request.args.get("q", "")
    conn = database.get_db()
    
    # Vulnerable raw SQL string concatenation
    raw_query = f"SELECT id, name, category, price, rating FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
    try:
        cursor = conn.cursor()
        cursor.execute(raw_query)
        rows = cursor.fetchall()
        results = [dict(r) for r in rows]
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e), "executed_sql": raw_query}), 500
    conn.close()

    return jsonify({
        "status": "success",
        "query": q,
        "count": len(results),
        "results": results
    })

@app.route("/api/v1/products/<int:pid>/reviews", methods=["GET", "POST"])
def api_product_reviews(pid):
    """Product Reviews endpoint.
    On product 7 (HSM appliance), the admin review contains internal_session_token leaking the flag.
    """
    conn = database.get_db()
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        author = str(data.get("author_name", "Anonymous")).strip() or "Anonymous"
        try:
            rating = int(data.get("rating", 5))
        except (ValueError, TypeError):
            rating = 5
        rating = max(1, min(5, rating))
        comment = str(data.get("comment", "")).strip() or "Verified purchase review."
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        uid = session.get("user_id", 1)
        conn.execute("""
            INSERT INTO reviews (product_id, user_id, author_name, rating, comment, created_at, internal_author_email, internal_session_token)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (pid, uid, author, rating, comment, now, f"{author.lower().replace(' ', '')}@example.com", f"tok_{secrets.token_hex(8)}"))
        conn.execute("UPDATE products SET reviews_count = reviews_count + 1 WHERE id = ?", (pid,))
        conn.commit()
        conn.close()
        return jsonify({
            "status": "success",
            "message": "Review posted successfully!",
            "review": {
                "author_name": author,
                "rating": rating,
                "comment": comment,
                "created_at": now
            }
        }), 201

    reviews = conn.execute("SELECT * FROM reviews WHERE product_id = ?", (pid,)).fetchall()
    conn.close()

    return jsonify({
        "product_id": pid,
        "count": len(reviews),
        "reviews": [dict(r) for r in reviews]
    })

# ==========================================
# 2. ORDERS, RECEIPTS & SHOPPING CART (BOLA & BUSINESS LOGIC)
# ==========================================
@app.route("/api/v1/orders/<int:oid>/receipt")
def api_get_order_receipt(oid):
    """BOLA 1: Read any customer order receipt by order identifier."""
    conn = database.get_db()
    order = conn.execute("SELECT * FROM orders WHERE id = ?", (oid,)).fetchone()
    if not order:
        conn.close()
        return jsonify({"error": "Order receipt not found"}), 404
    items = conn.execute("SELECT * FROM order_items WHERE order_id = ?", (oid,)).fetchall()
    conn.close()

    return jsonify({
        "order": dict(order),
        "items": [dict(i) for i in items]
    })

@app.route("/api/v1/users/<int:uid>/addresses")
def api_get_user_addresses(uid):
    """BOLA 2: Access arbitrary customer physical delivery address."""
    conn = database.get_db()
    addresses = conn.execute("SELECT * FROM addresses WHERE user_id = ?", (uid,)).fetchall()
    conn.close()

    return jsonify({
        "user_id": uid,
        "addresses": [dict(a) for a in addresses]
    })

@app.route("/api/v1/users/<int:uid>/payments", methods=["GET"])
def api_get_user_payments(uid):
    """Retrieve saved payment cards for user.
    Discloses card IDs and available API actions (including DELETE).
    """
    conn = database.get_db()
    cards = conn.execute("SELECT id, card_brand, card_last4, exp_month, exp_year, is_default FROM payment_cards WHERE user_id = ?", (uid,)).fetchall()
    conn.close()
    return jsonify({
        "user_id": uid,
        "cards": [dict(c) for c in cards],
        "api_actions": {
            "delete_card": "/api/v1/payments/{card_id}"
        }
    })

@app.route("/api/v1/payments/<int:card_id>", methods=["DELETE"])
def api_delete_payment_card(card_id):
    """BOLA 3: Delete arbitrary customer payment card.
    Card 3 belongs to admin (user 99). Deleting it reveals the flag.
    """
    conn = database.get_db()
    card = conn.execute("SELECT * FROM payment_cards WHERE id = ?", (card_id,)).fetchone()
    if not card:
        conn.close()
        return jsonify({"error": "Card not found"}), 404
    conn.execute("DELETE FROM payment_cards WHERE id = ?", (card_id,))
    conn.commit()
    conn.close()

    if card_id == 3:
        return jsonify({
            "status": "success",
            "message": "Admin corporate payment card expunged",
            "flag": get_flag("bola_card_delete")
        })

    return jsonify({
        "status": "success",
        "message": f"Payment method #{card_id} expunged from customer profile"
    })

@app.route("/api/v1/cart/checkout", methods=["POST"])
@app.route("/api/v1/store/checkout", methods=["POST"])
def api_cart_checkout():
    """Business Logic: Negative Price Inversion.
    Only when total < 0 does it invert and return the flag!
    """
    data = request.get_json(silent=True) or {}
    total = float(data.get("total", 0.0))
    uid = session.get("user_id", 1)

    if total < 0:
        conn = database.get_db()
        conn.execute("UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?", (total, uid))
        user = conn.execute("SELECT wallet_balance FROM users WHERE id = ?", (uid,)).fetchone()
        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": f"Negative total detected! ${abs(total):.2f} credited to your Apex Wallet!",
            "new_wallet_balance": user["wallet_balance"] if user else 0,
            "flag": get_flag("business_negative_checkout")
        })

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    order_num = f"ORD-2026-{secrets.token_hex(3).upper()}"
    conn = database.get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO orders (order_number, user_id, total_amount, discount_amount, status, payment_method, shipping_address, created_at, receipt_token)
        VALUES (?, ?, ?, 0.0, 'completed', 'Apex Wallet', '742 Evergreen Terrace, Seattle WA', ?, ?)
    """, (order_num, uid, total, now, f"rcpt_{secrets.token_hex(8)}"))
    new_order_id = cur.lastrowid
    conn.commit()
    conn.close()

    return jsonify({
        "status": "success",
        "order_id": new_order_id,
        "order_number": order_num,
        "message": f"Order #{order_num} successfully processed for ${total:.2f}"
    })

REDOS_COUPON_REGEX = re.compile(r"^([a-zA-Z0-9_.-]+)+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

def execute_coupon_regex_safely(coupon_str: str, timeout: float = 0.35):
    """Executes genuine regular expression validation in a worker thread
    with safe timeout limits to detect catastrophic backtracking."""
    res = {"matched": False, "timed_out": False, "elapsed": 0.0}
    t0 = time.perf_counter()

    def worker():
        try:
            m = REDOS_COUPON_REGEX.match(coupon_str)
            res["matched"] = bool(m)
        except Exception:
            res["matched"] = False

    th = threading.Thread(target=worker)
    th.daemon = True
    th.start()
    th.join(timeout=timeout)
    elapsed = time.perf_counter() - t0
    res["elapsed"] = elapsed

    if th.is_alive():
        res["timed_out"] = True
    elif elapsed >= 0.025 and not res["matched"] and len(coupon_str) >= 20:
        res["timed_out"] = True

    return res

@app.route("/api/v1/coupons/apply", methods=["POST"])
@app.route("/api/v1/vouchers/redeem", methods=["POST"])
def api_coupon_apply_race():
    """Business Logic: Concurrency Race Condition (TOCTOU) on APEXVIP500.
    A single request DOES NOT get the flag!
    ONLY when current_uses > max_uses (meaning two or more threads redeemed concurrently)
    is the race condition flag awarded!
    """
    data = request.get_json(silent=True) or {}
    code = data.get("code", "APEXVIP500").strip().upper()
    uid = session.get("user_id", 1)

    conn = database.get_db()
    voucher = conn.execute("SELECT * FROM vouchers WHERE code = ?", (code,)).fetchone()
    if not voucher:
        conn.close()
        return jsonify({"error": "Voucher does not exist"}), 404

    # Vulnerability: Check without atomic lock
    if voucher["current_uses"] >= voucher["max_uses"]:
        conn.close()
        return jsonify({"error": "Voucher usage limit reached"}), 400

    # 120ms race condition execution window allowing concurrent requests to overlap
    time.sleep(0.12)

    conn.execute("UPDATE vouchers SET current_uses = current_uses + 1 WHERE id = ?", (voucher["id"],))
    conn.execute("UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?", (voucher["discount_amount"], uid))
    new_voucher = conn.execute("SELECT * FROM vouchers WHERE id = ?", (voucher["id"],)).fetchone()
    conn.commit()
    conn.close()

    # REAL RACE CONDITION CHECK:
    # Only if multiple concurrent requests succeeded and pushed current_uses above max_uses!
    if new_voucher["current_uses"] > new_voucher["max_uses"]:
        return jsonify({
            "status": "success",
            "message": f"CONCURRENCY RACE CONDITION DETECTED! Voucher redeemed {new_voucher['current_uses']} times (limit was {new_voucher['max_uses']})!",
            "current_uses": new_voucher["current_uses"],
            "max_uses": new_voucher["max_uses"],
            "flag": get_flag("race_condition_voucher")
        })

    return jsonify({
        "status": "success",
        "message": f"Voucher '{code}' applied! Added ${voucher['discount_amount']:.2f} to Apex Wallet.",
        "current_uses": new_voucher["current_uses"],
        "max_uses": new_voucher["max_uses"]
    })

@app.route("/api/v1/coupons/validate", methods=["POST"])
def api_coupon_validate_redos():
    """Resource Consumption: ReDoS Catastrophic Backtracking."""
    data = request.get_json(silent=True) or {}
    coupon = data.get("coupon", "")
    
    exec_result = execute_coupon_regex_safely(coupon)
    if exec_result["timed_out"]:
        return jsonify({
            "status": "warning",
            "regex_complexity": "Catastrophic exponential backtracking triggered",
            "elapsed_seconds": round(exec_result["elapsed"], 4),
            "flag": get_flag("redos_email_validation")
        })

    return jsonify({
        "coupon": coupon,
        "valid": exec_result["matched"],
        "message": "Standard coupon format valid" if exec_result["matched"] else "Standard coupon format invalid",
        "pattern": "^([a-zA-Z0-9_.-]+)+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$"
    })

# ==========================================
# 3. AUTHENTICATION & ADVANCED JWT VULNERABILITIES
# ==========================================
@app.route("/api/v1/auth/login", methods=["POST"])
def api_login():
    """Broken Auth: User Enumeration & Credential Stuffing."""
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    conn = database.get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if not user:
        return jsonify({
            "error": "Account username does not exist in ApexMart directory",
            "account_status": "NOT_FOUND"
        }), 404

    hashed = database.hash_pw(password)
    if user["password_hash"] != hashed:
        resp = {
            "error": "Password authentication failed for existing user",
            "account_status": "BAD_CREDENTIALS"
        }
        if username == "admin":
            resp["flag"] = get_flag("auth_user_enum")
        return jsonify(resp), 401

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 7200
    }).encode()).decode().rstrip("=")
    sig = hmac.new(app.secret_key.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    token = f"{header}.{payload}.{sig_b64}"

    resp_data = {
        "status": "success",
        "token": token,
        "token_type": "Bearer",
        "expires_in": 7200,
        "refresh_url": "/api/v1/auth/refresh-session",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "wallet_balance": user["wallet_balance"]
        }
    }
    if username == "support_agent":
        resp_data["flag"] = get_flag("auth_brute_force")

    return jsonify(resp_data)

@app.route("/api/v1/auth/verify-jwt", methods=["POST"])
def api_verify_jwt_complex():
    """Broken Auth: JWT alg:none AND JWT kid path traversal (/dev/null)."""
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    parts = token.split(".")
    if len(parts) < 2:
        return jsonify({"error": "Malformed JWT token"}), 400

    def pad(s): return s + "=" * ((4 - len(s) % 4) % 4)

    try:
        header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
    except Exception:
        return jsonify({"error": "Invalid base64 encoding"}), 400

    alg = str(header.get("alg", "")).lower()
    kid = str(header.get("kid", ""))
    role = payload.get("role", "customer")

    if alg == "none":
        # Genuine alg:none bypass: accept unsigned token
        if role == "admin":
            return jsonify({
                "status": "success",
                "mode": "alg:none bypass",
                "claims": payload,
                "is_admin": True,
                "flag": get_flag("jwt_none_alg")
            })
        return jsonify({"error": "Admin privileges required"}), 403

    if kid:
        # Genuine kid path traversal: attempt to load key from filesystem using kid path
        key_bytes = None
        clean_kid = kid.replace("\\", "/")
        if "dev/null" in clean_kid or clean_kid.lower().endswith("nul") or clean_kid == "/dev/null":
            key_bytes = b""
        elif os.path.exists(kid):
            try:
                with open(kid, "rb") as kf:
                    key_bytes = kf.read()
            except Exception:
                pass

        if key_bytes is not None:
            # Genuine cryptographic signature verification against key_bytes
            expected_sig = base64.urlsafe_b64encode(
                hmac.new(key_bytes, f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
            ).decode().rstrip("=")
            provided_sig = parts[2] if len(parts) > 2 else ""
            if hmac.compare_digest(provided_sig, expected_sig):
                if role == "admin":
                    return jsonify({
                        "status": "success",
                        "mode": f"kid path traversal ({kid})",
                        "claims": payload,
                        "is_admin": True,
                        "flag": get_flag("jwt_kid_traversal")
                    })
                return jsonify({"error": "Admin privileges required"}), 403
            else:
                return jsonify({"error": "Cryptographic signature verification failed for traversed key"}), 401

    return jsonify({"error": f"Algorithm '{alg}' rejected without valid cryptographic key"}), 400

@app.route("/api/v1/auth/refresh-session", methods=["POST"])
def api_jwt_key_confusion():
    data = request.get_json(silent=True) or {}
    secret_candidate = data.get("secret", "")
    if not secret_candidate:
        return jsonify({
            "error": "Missing 'secret' parameter in JSON payload: {'secret': '<hmac_key>'}",
            "hint": "Recover the master HMAC key via dictionary attack against JWT verification"
        }), 400
    if secret_candidate in (app.secret_key, "secret123", "apex-enterprise-insecure-master-jwt-key"):
        return jsonify({
            "status": "success",
            "message": "Secret cracked! Master signing key matched.",
            "flag": get_flag("jwt_key_confusion")
        })
    return jsonify({"error": "Invalid HMAC key"}), 401

@app.route("/api/v1/auth/reset-password", methods=["POST"])
def api_auth_reset_predictable():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "alice@apexmart.local")).strip()
    host = request.headers.get("X-Forwarded-Host", request.headers.get("Host", "127.0.0.1:5000"))
    token_seed = f"{email}-{datetime.now().strftime('%Y%m%d%H')}"
    reset_token = hashlib.md5(token_seed.encode()).hexdigest()
    resp = {
        "status": "success",
        "debug_reset_link": f"http://{host}/reset-password?token={reset_token}&email={email}",
        "token_algorithm": "MD5(email + YYYYMMDDHH)"
    }
    if email == "admin@apexmart.local":
        resp["flag"] = get_flag("auth_reset_predictable")
        resp["message"] = "Administrator password reset token predicted successfully"
    return jsonify(resp)

@app.route("/api/v1/auth/register", methods=["POST"])
@app.route("/api/v1/users/register", methods=["POST"])
def api_register_mass_assign():
    data = request.get_json(silent=True) or {}
    username = data.get("username", f"user_{secrets.token_hex(4)}")
    email = data.get("email", f"{username}@example.com")
    full_name = data.get("full_name", "Registered Customer")
    password = data.get("password", "TestPass123!")
    role = data.get("role", "customer")
    wallet_balance = float(data.get("wallet_balance", 500.0))
    is_verified = int(data.get("is_verified", 0))

    conn = database.get_db()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (username, email, full_name, role, password_hash, ssn, api_key, wallet_balance, is_verified, totp_secret, salary, internal_notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            username, email, full_name, role, database.hash_pw(password),
            "000-00-0000", f"sk_live_{secrets.token_hex(12)}", wallet_balance, is_verified,
            "JBSWY3DPEHPK3PXP", 50000.0, "Self-registered customer"
        ))
        new_id = cur.lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username already taken"}), 409
    conn.close()

    resp_data = {
        "status": "success",
        "user_id": new_id,
        "username": username,
        "role": role,
        "wallet_balance": wallet_balance
    }
    if role == "admin" or wallet_balance > 10000:
        resp_data["flag"] = get_flag("mass_assign_privesc")

    return jsonify(resp_data), 201

# ==========================================
# 4. BFLA, GATEWAYS & ADMINISTRATIVE APIS
# ==========================================
@app.route("/api/v1/admin/backup/dump")
@app.route("/api/v1/admin/export-database", methods=["GET"])
def api_admin_backup_bfla():
    """BFLA 1: Unauthenticated administrative full DB backup."""
    conn = database.get_db()
    users = conn.execute("SELECT id, username, email, role, ssn, api_key, wallet_balance FROM users").fetchall()
    vault = conn.execute("SELECT * FROM admin_system_vault").fetchall()
    orders = conn.execute("SELECT * FROM orders").fetchall()
    conn.close()

    return jsonify({
        "status": "success",
        "backup_archive": {
            "users": [dict(u) for u in users],
            "vault": [dict(v) for v in vault],
            "orders": [dict(o) for o in orders]
        },
        "flag": get_flag("bfla_admin_export")
    })

@app.route("/api/v1/admin/maintenance", methods=["GET", "POST", "PUT", "PATCH"])
def api_admin_method_tamper():
    """BFLA 2: Method Tampering bypass."""
    if request.method == "GET":
        resp = jsonify({
            "status": "operational",
            "endpoint": "/api/v1/admin/maintenance",
            "message": "Administrative maintenance controller. Use POST with authorization to toggle state.",
            "allowed_verbs": ["POST", "PUT", "PATCH"]
        })
        resp.headers["Allow"] = "POST, PUT, PATCH"
        return resp

    if request.method == "POST":
        resp = jsonify({
            "error": "POST method restricted: requires enterprise admin token",
            "allowed_verbs": ["POST", "PUT", "PATCH"]
        })
        resp.headers["Allow"] = "POST, PUT, PATCH"
        return resp, 403

    return jsonify({
        "status": "success",
        "method_used": request.method,
        "message": "Maintenance state toggled successfully via unmonitored HTTP verb",
        "flag": get_flag("bfla_method_tamper")
    })

@app.route("/api/v1/dashboard")
def api_gateway_header_bypass():
    """BFLA 3: Reverse-proxy gateway header rewrite bypass."""
    orig_url = request.headers.get("X-Original-URL", request.headers.get("X-Rewrite-URL", ""))
    gateway_hdr = {"X-Gateway-Proxy": "Apex-Envoy-Edge/2.4.1 (Rewrite Enabled)"}
    if "/admin" in orig_url or "/vault" in orig_url:
        resp = jsonify({
            "status": "success",
            "gateway_override": orig_url,
            "message": "Gateway routing filter bypassed via header injection",
            "vault_master_key": "sk_apex_vault_root_key_990184",
            "flag": get_flag("gateway_header_bypass")
        })
        for k, v in gateway_hdr.items():
            resp.headers[k] = v
        return resp

    resp = jsonify({"status": "success", "role": "customer", "dashboard": "Standard Customer Dashboard"})
    for k, v in gateway_hdr.items():
        resp.headers[k] = v
    return resp

# ==========================================
# 5. SSRF & VENDOR WEBHOOK / XML INVOICE INGESTION
# ==========================================
@app.route("/api/v1/vendor/webhook-test")
@app.route("/api/v1/integrations/fetch-webhook", methods=["GET"])
def api_ssrf_vendor():
    """SSRF: Cloud metadata (IMDSv1) and internal HSM port scan."""
    target_url = request.args.get("url", "").strip()
    if not target_url:
        return jsonify({"error": "Missing 'url' query parameter"}), 400

    parsed = urllib.parse.urlparse(target_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path

    # 1. Realistic Simulated Cloud Metadata Service (169.254.169.254)
    if hostname == "169.254.169.254":
        if "iam/security-credentials" in path:
            return jsonify({
                "Code": "Success",
                "LastUpdated": "2026-11-23T03:00:00Z",
                "Type": "AWS-HMAC",
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "Token": "AQoDYXdzEJr1k99218...",
                "RoleArn": "arn:aws:iam::123456789012:role/apexmart-production-ec2-role",
                "flag": get_flag("ssrf_cloud_metadata")
            })
        elif "meta-data" in path:
            return f"latest/meta-data/iam/security-credentials/apexmart-production-ec2-role\n{get_flag('ssrf_cloud_metadata')}"
        return jsonify({"error": "Metadata endpoint not found"}), 404

    # 2. Genuine Internal Loopback Dispatch to Local Services
    if hostname in ("127.0.0.1", "localhost", "0.0.0.0", "::1"):
        full_path = path + ("?" + parsed.query if parsed.query else "")
        # Dispatch to application route directly
        with app.test_client() as internal_client:
            internal_resp = internal_client.get(full_path)
            content_type = internal_resp.content_type
            return (
                internal_resp.get_data(),
                internal_resp.status_code,
                {"Content-Type": content_type}
            )

    # 3. Standard external outbound request
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": "ApexMart-WebhookPing/2026"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = resp.read(2048)
            content_type = resp.headers.get("Content-Type", "text/plain")
            return data, resp.status, {"Content-Type": content_type}
    except Exception as e:
        return jsonify({"error": f"Failed to reach target URL: {str(e)}", "target": target_url}), 502

@app.route("/internal/system-metrics")
def api_internal_system_metrics():
    return jsonify({
        "internal_host": "127.0.0.1",
        "hsm_private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0r...",
        "flag": get_flag("ssrf_internal_port")
    })

class SafeLocalEntityResolver(xml.sax.handler.EntityResolver):
    def __init__(self, flag_value: str):
        self.flag_value = flag_value
        self.resolved_entities = []

    def resolveEntity(self, publicId, systemId):
        self.resolved_entities.append(systemId or "")
        sys_id_clean = (systemId or "").lower()
        if "passwd" in sys_id_clean:
            content = f"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\napex_svc:x:1001:1001:APEX Service Account:{self.flag_value}:/opt/apex:/bin/bash\n"
        elif "win.ini" in sys_id_clean or "boot.ini" in sys_id_clean:
            content = f"; for 16-bit app support\n[fonts]\n[extensions]\nAPEX_FLAG={self.flag_value}\n"
        else:
            content = f"[XXE_ENTITY_RESOLVED: {systemId} -> {self.flag_value}]"
        return io.StringIO(content)

class InvoiceXMLHandler(xml.sax.handler.ContentHandler):
    def __init__(self):
        self.elements = {}
        self.current_tag = ""
        self.current_data = []

    def startElement(self, name, attrs):
        self.current_tag = name
        self.current_data = []

    def characters(self, content):
        self.current_data.append(content)

    def endElement(self, name):
        val = "".join(self.current_data).strip()
        if val:
            self.elements[name] = val
        self.current_tag = ""

@app.route("/api/v1/vendor/invoice-upload", methods=["POST"])
@app.route("/api/v1/invoice/xml", methods=["POST"])
def api_vendor_xml_invoice():
    """XXE (XML External Entity): DTD resolution in XML invoice ingestion.
    Only when an external general entity is resolved does it leak the flag.
    """
    raw_xml = request.get_data(as_text=True)
    if not raw_xml:
        return jsonify({"error": "Empty XML body"}), 400

    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, True)
    flag_val = get_flag("xxe_xml_invoice")
    resolver = SafeLocalEntityResolver(flag_val)
    parser.setEntityResolver(resolver)
    handler = InvoiceXMLHandler()
    parser.setContentHandler(handler)

    try:
        parser.parse(io.StringIO(raw_xml))
    except Exception as e:
        return jsonify({"error": f"XML parse error: {str(e)}"}), 400

    has_entity_resolved = len(resolver.resolved_entities) > 0
    has_flag_in_content = any(flag_val in str(v) for v in handler.elements.values())

    if has_entity_resolved or has_flag_in_content:
        extracted = f"[SYSTEM DATA DUMP]: root:x:0:0:root:/root:/bin/bash\nadministrator:win.ini:system_secrets:{flag_val}"
        return jsonify({
            "status": "success",
            "message": "XML invoice parsed with genuine DTD entity resolution",
            "resolved_entities": resolver.resolved_entities,
            "invoice_data": extracted,
            "parsed_elements": handler.elements,
            "flag": flag_val
        })

    return jsonify({
        "status": "success",
        "message": "Invoice processed successfully",
        "elements_count": len(handler.elements),
        "invoice_data": handler.elements
    })

@app.route("/api/v1/webhooks/fulfillment", methods=["POST"])
def api_webhook_fulfillment():
    """Unsafe Consumption: Unsigned webhook accepting fulfillment notifications."""
    data = request.get_json(silent=True) or {}
    order_id = data.get("order_id", 1)
    status = data.get("status", "shipped")

    sig_header = request.headers.get("X-Apex-Signature")
    if not sig_header:
        return jsonify({
            "status": "accepted",
            "message": f"Webhook processed without HMAC signature! Order #{order_id} marked as {status}.",
            "flag": get_flag("webhook_unverified_sig")
        })

    return jsonify({"status": "verified", "order_id": order_id})

# ==========================================
# 6. GRAPHQL & MISCONFIGURATION
# ==========================================
@app.route("/api/v1/graphql", methods=["GET", "POST"])
def api_graphql():
    if request.method == "GET":
        return jsonify({
            "status": "ready",
            "endpoint": "/api/v1/graphql",
            "message": "Send POST request with JSON { 'query': '...' } to query GraphQL gateway.",
            "introspection_enabled": True
        })

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"errors": [{"message": "Invalid JSON or empty body"}]}), 400

    # Batch Query DoS Handling
    if isinstance(data, list):
        results = []
        for i, item in enumerate(data):
            q = item.get("query", "") if isinstance(item, dict) else ""
            if GRAPHQL_AVAILABLE and GRAPHQL_SCHEMA:
                exec_res = graphql.graphql_sync(GRAPHQL_SCHEMA, q, root_value=GRAPHQL_ROOT_VALUE)
                res_dict = {"data": exec_res.data}
                if exec_res.errors:
                    res_dict["errors"] = [str(e) for e in exec_res.errors]
            else:
                res_dict = {"data": {"message": f"Processed batch item #{i}"}}
            res_dict["flag"] = get_flag("graphql_batch_dos")
            results.append(res_dict)
        return jsonify(results)

    query = data.get("query", "")
    if not query:
        return jsonify({"errors": [{"message": "Missing 'query' field in GraphQL request"}]}), 400

    if GRAPHQL_AVAILABLE and GRAPHQL_SCHEMA:
        try:
            document = graphql.parse(query)
        except Exception as e:
            return jsonify({"errors": [{"message": f"GraphQL syntax error: {str(e)}"}]}), 400

        # Execute query against genuine GraphQL schema
        exec_res = graphql.graphql_sync(GRAPHQL_SCHEMA, query, root_value=GRAPHQL_ROOT_VALUE)
        resp_data = {"data": exec_res.data}
        if exec_res.errors:
            resp_data["errors"] = [str(e) for e in exec_res.errors]

        # Check for Introspection or Complexity
        query_text = query.lower()
        if "__schema" in query_text or "__type" in query_text:
            resp_data["flag"] = get_flag("graphql_introspection")
        elif query_text.count("related") > 2 or query_text.count("product") > 3:
            resp_data["flag"] = get_flag("graphql_batch_dos")

        return jsonify(resp_data)
    else:
        # Fallback if graphql-core is missing
        if "__schema" in query or "__type" in query:
            return jsonify({
                "data": {
                    "__schema": {
                        "types": [
                            {"name": "Product", "fields": ["id", "name", "price", "stock"]},
                            {"name": "User", "fields": ["id", "username", "role", "ssn", "wallet_balance"]},
                            {"name": "Mutation", "fields": ["applyStaffDiscount", "deleteUserAccount", "emergencyDrainBalance"]}
                        ]
                    }
                },
                "flag": get_flag("graphql_introspection")
            })
        return jsonify({"data": {"currentUser": {"id": 1, "username": "alice", "role": "customer"}}})

@app.route("/api/v1/user/credentials")
def api_cors_credentials():
    origin = request.headers.get("Origin", "")
    resp_data = {
        "status": "success",
        "user_id": 1,
        "username": "alice",
        "api_secret": "sk_live_alice_super_confidential_token_9918"
    }
    if origin == "null":
        resp_data["flag"] = get_flag("cors_null_origin")
        resp_data["cors_warning"] = "Insecure null origin allowed with credentials"

    resp = make_response(jsonify(resp_data))
    resp.headers["Access-Control-Allow-Origin"] = origin if origin else "null"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp

@app.route("/api/v1/debug/environment")
def api_debug_env():
    return jsonify({
        "debug_mode": True,
        "flask_secret_key": app.secret_key,
        "os_environment": dict(os.environ),
        "database_file": database.DB_PATH,
        "registered_routes": [str(rule) for rule in app.url_map.iter_rules()],
        "flag": get_flag("debug_env_dump")
    })

@app.route("/api/v0.9/")
def api_v0_index():
    return jsonify({
        "api_version": "v0.9-alpha",
        "status": "deprecated",
        "deprecated_notice": "v0.9 legacy endpoints are slated for decommissioning. Use /api/v1 instead.",
        "legacy_endpoints": [
            { "path": "/api/v0.9/payments/direct-debit", "methods": ["GET", "POST"], "auth_required": False }
        ]
    })

@app.route("/api/v0.9/payments/direct-debit", methods=["GET", "POST"])
def api_shadow_payment_legacy():
    if request.method == "GET":
        return jsonify({
            "api_version": "v0.9-alpha-deprecated",
            "endpoint": "/api/v0.9/payments/direct-debit",
            "status": "active_legacy",
            "expected_payload": { "account": "string", "amount": "number" },
            "security_controls": "None (Legacy 2FA check bypassed)"
        })

    data = request.get_json(silent=True) or {}
    amount = float(data.get("amount", 1000.0))
    account = data.get("account", "APEX-OFFSHORE-77")
    return jsonify({
        "status": "success",
        "api_version": "v0.9-alpha-deprecated",
        "security_controls": "None (Legacy 2FA check bypassed)",
        "message": f"Direct debit payment of ${amount:.2f} cleared to {account}",
        "flag": get_flag("shadow_api_v0")
    })

# ==========================================
# 7. BOLA USER PROFILE & ACCOUNT APIS
# ==========================================
@app.route("/api/v1/users/<int:uid>")
def api_get_user_bola(uid):
    conn = database.get_db()
    user = conn.execute("SELECT id, username, email, full_name, role, ssn, api_key, wallet_balance, salary, internal_notes FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"user": dict(user)})

@app.route("/api/v1/accounts/<account_num>/statement")
def api_get_account_statement(account_num):
    conn = database.get_db()
    acc = conn.execute("SELECT * FROM accounts WHERE account_num = ?", (account_num,)).fetchone()
    if not acc:
        conn.close()
        return jsonify({"error": "Account not found"}), 404
    txs = conn.execute("SELECT * FROM transactions WHERE from_account = ? OR to_account = ?", (account_num, account_num)).fetchall()
    conn.close()

    return jsonify({
        "account": dict(acc),
        "transactions": [dict(t) for t in txs],
        "api_actions": {
            "delete_transaction": "/api/v1/transactions/{id}"
        }
    })

@app.route("/api/v1/transactions/<int:tid>", methods=["DELETE"])
def api_delete_transaction(tid):
    conn = database.get_db()
    tx = conn.execute("SELECT * FROM transactions WHERE id = ?", (tid,)).fetchone()
    if not tx:
        conn.close()
        return jsonify({"error": "Transaction not found"}), 404
    conn.execute("DELETE FROM transactions WHERE id = ?", (tid,))
    conn.commit()
    conn.close()

    resp = {"status": "success", "message": f"Transaction #{tid} expunged", "deleted_record": dict(tx)}
    if tid == 102 or "APEX{" in str(tx["reference"]):
        resp["flag"] = get_flag("bola_tx_delete")
    return jsonify(resp)

# ==========================================
# 8. FLAG SUBMISSION & EVALUATOR ENGINE
# ==========================================
@app.route("/api/v1/flags/submit", methods=["POST"])
def api_submit_flag():
    data = request.get_json(silent=True) or {}
    flag = str(data.get("flag", "")).strip()
    if not flag:
        return jsonify({"status": "error", "message": "No flag provided"}), 400

    cid = verify_submitted_flag(flag)
    if not cid:
        return jsonify({"status": "invalid", "message": "Invalid flag signature or unrecognized challenge format."}), 400

    is_new = claim_flag(cid)
    claimed = get_all_claimed_flags()
    meta = CHALLENGE_DEFINITIONS.get(cid, {})
    return jsonify({
        "status": "correct",
        "message": f"Challenge solved: {meta.get('title', cid)}",
        "challenge_id": cid,
        "is_new": is_new,
        "total_score": len(claimed),
        "max_score": len(CHALLENGE_DEFINITIONS)
    })

@app.route("/api/v1/flags/progress")
def api_flags_progress():
    claimed = get_all_claimed_flags()
    return jsonify({
        "score": len(claimed),
        "total_challenges": len(CHALLENGE_DEFINITIONS),
        "claimed_challenges": claimed
    })

@app.route("/api/v1/evaluator/matrix")
def api_evaluator_matrix():
    claimed = get_all_claimed_flags()
    instructor_key = request.args.get("instructor_key", request.headers.get("X-Instructor-Key", ""))
    is_instructor = (instructor_key == "apex-instructor-2026")
    challenges = []
    for cid, meta in CHALLENGE_DEFINITIONS.items():
        is_captured = cid in claimed
        flag_val = get_flag(cid) if (is_captured or is_instructor) else "APEX{••••••••••••••••}"
        challenges.append({
            "id": cid,
            "title": meta["title"],
            "category": meta["category"],
            "cvss": meta["cvss"],
            "endpoint": meta["endpoint"],
            "flag": flag_val,
            "captured": is_captured,
            "hint": meta.get("hint", "")
        })
    return jsonify({
        "score": len(claimed),
        "total": len(CHALLENGE_DEFINITIONS),
        "percentage": round((len(claimed) / len(CHALLENGE_DEFINITIONS)) * 100) if CHALLENGE_DEFINITIONS else 0,
        "challenges": challenges
    })

@app.route("/api/v1/system/reset-db", methods=["POST"])
def api_reset_db():
    session[CLAIMS_KEY] = []
    database.reset_claimed_flags()
    database.init_db(force=True)
    return jsonify({"status": "reset", "message": "Database wiped, re-seeded, and flags cleared"})

@app.route("/api/v1/system/reset-instance", methods=["POST"])
def api_reset_instance():
    """Full instance reset: regenerates HMAC master secret, wipes DB, and resets progress."""
    session[CLAIMS_KEY] = []
    flags.reset_instance_secret()
    database.reset_claimed_flags()
    database.init_db(force=True)
    return jsonify({
        "status": "reset",
        "message": "Full instance reset: generated new cryptographic HMAC secret, re-seeded database, and cleared learner progress."
    })

if __name__ == "__main__":
    print(f"[*] ApexMart Cyber Hardware Store running at http://127.0.0.1:{PORT}")
    app.run(host="127.0.0.1", port=PORT, debug=False)
