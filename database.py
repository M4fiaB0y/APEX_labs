import sqlite3
import os
import hashlib
from datetime import datetime
from flags import get_flag

DB_PATH = os.environ.get("APEX_DB_PATH", os.path.join(os.path.dirname(__file__), "apex_lab.db"))

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=20.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def init_db(force: bool = False):
    if force and os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except Exception:
            pass

    conn = get_db()
    cur = conn.cursor()

    # 1. Users Table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'customer',
        password_hash TEXT NOT NULL,
        ssn TEXT NOT NULL,
        api_key TEXT NOT NULL,
        wallet_balance REAL NOT NULL DEFAULT 500.0,
        is_verified INTEGER NOT NULL DEFAULT 0,
        totp_secret TEXT NOT NULL,
        salary REAL NOT NULL,
        internal_notes TEXT
    )
    """)

    # 2. Product Catalog
    cur.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT NOT NULL,
        price REAL NOT NULL,
        stock INTEGER NOT NULL DEFAULT 50,
        rating REAL NOT NULL DEFAULT 4.8,
        reviews_count INTEGER NOT NULL DEFAULT 12,
        image_url TEXT NOT NULL
    )
    """)

    # 3. Product Reviews (Excessive Data Exposure)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        author_name TEXT NOT NULL,
        rating INTEGER NOT NULL,
        comment TEXT NOT NULL,
        created_at TEXT NOT NULL,
        internal_author_email TEXT,
        internal_session_token TEXT,
        FOREIGN KEY (product_id) REFERENCES products(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # 4. Customer Addresses (BOLA)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS addresses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        recipient_name TEXT NOT NULL,
        street_address TEXT NOT NULL,
        city TEXT NOT NULL,
        state TEXT NOT NULL,
        zip_code TEXT NOT NULL,
        phone TEXT NOT NULL,
        is_default INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # 5. Orders & Invoices (BOLA)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_number TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        total_amount REAL NOT NULL,
        discount_amount REAL NOT NULL DEFAULT 0.0,
        status TEXT NOT NULL DEFAULT 'completed',
        payment_method TEXT NOT NULL DEFAULT 'Apex Wallet',
        shipping_address TEXT NOT NULL,
        created_at TEXT NOT NULL,
        receipt_token TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # 6. Order Line Items
    cur.execute("""
    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        product_name TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        unit_price REAL NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders(id)
    )
    """)

    # 7. Promo Vouchers (Concurrency Race Condition TOCTOU)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vouchers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        discount_amount REAL NOT NULL,
        max_uses INTEGER NOT NULL,
        current_uses INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1
    )
    """)

    # 8. Banking Accounts & Corporate Vault (BOLA)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        account_num TEXT UNIQUE NOT NULL,
        routing_num TEXT NOT NULL,
        account_type TEXT NOT NULL,
        balance REAL NOT NULL,
        currency TEXT NOT NULL DEFAULT 'USD',
        status TEXT NOT NULL DEFAULT 'active',
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # 9. Stored Payment Cards (BOLA Deletion)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS payment_cards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        card_brand TEXT NOT NULL,
        card_last4 TEXT NOT NULL,
        exp_month INTEGER NOT NULL,
        exp_year INTEGER NOT NULL,
        cardholder_name TEXT NOT NULL,
        billing_zip TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # 10. Financial Audit Transactions (BOLA Deletion)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_account TEXT NOT NULL,
        to_account TEXT NOT NULL,
        amount REAL NOT NULL,
        currency TEXT NOT NULL DEFAULT 'USD',
        reference TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'completed',
        created_at TEXT NOT NULL
    )
    """)

    # 11. Secret System Vault Table (Can ONLY be accessed via UNION SQL Injection - Anti-AI!)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS admin_system_vault (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        secret_name TEXT NOT NULL,
        secret_value TEXT NOT NULL,
        access_level TEXT NOT NULL
    )
    """)

    # 12. Persistent Learner Challenge Claims (survives restarts)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS challenge_claims (
        challenge_id TEXT PRIMARY KEY,
        claimed_at TEXT NOT NULL
    )
    """)

    # Seed data
    cur.execute("SELECT COUNT(*) FROM products")
    if cur.fetchone()[0] == 0:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. Users
        users = [
            (1, "alice", "alice@apexmart.local", "Alice Walker", "customer", hash_pw("alice123"), "331-44-1029", "sk_live_alice_98fa72b", 2450.00, 1, "JBSWY3DPEHPK3PXP", 85000.0, "VIP Hardware Customer - Tier 1 Priority Support"),
            (2, "bob", "bob@apexmart.local", "Bob Martinez", "customer", hash_pw("bob2024"), "442-55-8831", "sk_live_bob_11fe44a", 150.00, 0, "GEZDGNBVGY3TQOJQ", 62000.0, "Consumer Tech Enthusiast Account"),
            (3, "support_agent", "support@apexmart.local", "Sarah Connor", "support", hash_pw("password123"), "551-77-9921", "sk_live_supp_55a901c", 4100.00, 1, "MZXW6YTBOI======", 75000.0, "Tier 2 Helpdesk Technical Support Specialist"),
            (99, "admin", "admin@apexmart.local", "Master Enterprise Administrator", "admin", hash_pw("admin2024!"), "999-00-1337", "sk_live_admin_master_007", 1000000.00, 1, "NBSWY3DPEHPK3PXP", 240000.0, f"ROOT ACCESS - Master Cloud Operations - {get_flag('bola_user_pii')}")
        ]
        cur.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", users)

        # 2. Products
        products = [
            (1, "NitroKey 3A NFC Crypto Dongle", "Security Hardware", "Next-gen FIDO2 & U2F physical authentication key with USB-A and NFC wireless interface. Open source firmware.", 69.99, 45, 4.9, 28, "nitrokey.png"),
            (2, "YubiKey 5C NFC Dual Interface", "Security Hardware", "Industry standard multi-protocol hardware security key supporting FIDO2, WebAuthn, PIV, OATH, and OpenPGP.", 55.00, 120, 5.0, 142, "yubikey.png"),
            (3, "HackRF One 1MHz-6GHz SDR Transceiver", "RF & Wireless", "Software Defined Radio peripheral capable of transmission or reception of radio signals from 1 MHz to 6 GHz.", 340.00, 15, 4.8, 19, "hackrf.png"),
            (4, "Flipper Zero Multi-Tool Pen-Tester", "Hardware Tools", "Portable multi-tool device for geeks and hardware pentesters in a toy-like body with Sub-GHz, RFID, NFC, and GPIO.", 169.00, 8, 4.9, 210, "flipper.png"),
            (5, "Raspberry Pi 5 (8GB RAM) Lab Cluster", "Embedded Systems", "Broadcom BCM2712 64-bit quad-core ARM Cortex-A76 processor at 2.4GHz with PCIe 2.0 interface.", 80.00, 60, 4.7, 65, "raspi.png"),
            (6, "Google Coral Edge TPU Coprocessor", "AI & Machine Learning", "USB accelerator bringing on-device ML inferencing to Linux, Mac, and Windows systems via Edge TPU ML chip.", 59.99, 30, 4.6, 14, "coral.png"),
            (7, "Dedicated 1U HSM Cryptographic Appliance", "Enterprise Infrastructure", "Hardware Security Module rack unit for high-throughput AES-256 and RSA-4096 signature verification.", 4500.00, 3, 5.0, 4, "hsm.png"),
            (8, "Titanium Cryptographic Seed Vault Capsule", "Cold Storage", "Indestructible cold storage backup cylinder for 24-word BIP39 cryptocurrency and private master seeds.", 89.00, 85, 4.8, 33, "seedvault.png")
        ]
        cur.executemany("INSERT INTO products VALUES (?,?,?,?,?,?,?,?,?)", products)

        # 3. Reviews (Review 4 on Product 7 leaks the excessive data token)
        reviews = [
            (1, 1, 1, "Alice Walker", 5, "Unbelievable build quality! Flawless integration with my enterprise vault.", now, "alice@apexmart.local", "tok_alice_session_99a81"),
            (2, 2, 2, "Bob Martinez", 5, "Must-have security device for every serious security engineer.", now, "bob@apexmart.local", "tok_bob_session_11b22"),
            (3, 4, 3, "Sarah Connor", 5, "Verified for penetration testing engagements. Battery lasts for days.", now, "support@apexmart.local", "tok_supp_session_44c33"),
            (4, 7, 99, "Admin Master", 5, "CONFIDENTIAL NOTE: HSM seed backup synced with AWS KMS us-east-1 cluster.", now, "admin@apexmart.local", get_flag('excessive_data_leak'))
        ]
        cur.executemany("INSERT INTO reviews VALUES (?,?,?,?,?,?,?,?,?)", reviews)

        # 4. Customer Addresses (User 99 leaks address flag)
        addresses = [
            (1, 1, "Alice Walker", "742 Evergreen Terrace", "Seattle", "WA", "98101", "206-555-0199", 1),
            (2, 2, "Bob Martinez", "100 Innovation Way", "Austin", "TX", "78701", "512-555-0144", 1),
            (3, 99, "Executive Security Directorate", "1000 Classified Defense Road", "Washington", "DC", "20001", f"202-555-0999 (AuthRef: {get_flag('bola_address_leak')})", 1)
        ]
        cur.executemany("INSERT INTO addresses VALUES (?,?,?,?,?,?,?,?,?)", addresses)

        # 5. Orders (Order 99 leaks receipt flag)
        orders = [
            (1, "ORD-2026-9001", 1, 124.99, 0.0, "completed", "Apex Wallet", "742 Evergreen Terrace, Seattle WA", now, "rcpt_alice_live_8821"),
            (2, "ORD-2026-9002", 2, 55.00, 0.0, "completed", "Visa ending in 8765", "100 Innovation Way, Austin TX", now, "rcpt_bob_live_4412"),
            (99, "ORD-2026-SECRET-9999", 99, 45000.00, 0.0, "completed", "Apex Corporate Credit Line", "1000 Classified Defense Road, Washington DC", now, get_flag('bola_order_receipt'))
        ]
        cur.executemany("INSERT INTO orders VALUES (?,?,?,?,?,?,?,?,?,?)", orders)

        # 6. Order Items
        order_items = [
            (1, 1, 1, "NitroKey 3A NFC Crypto Dongle", 1, 69.99),
            (2, 1, 2, "YubiKey 5C NFC Dual Interface", 1, 55.00),
            (3, 2, 2, "YubiKey 5C NFC Dual Interface", 1, 55.00),
            (4, 99, 7, "Dedicated 1U HSM Cryptographic Appliance", 10, 4500.00)
        ]
        cur.executemany("INSERT INTO order_items VALUES (?,?,?,?,?,?)", order_items)

        # 7. Vouchers
        vouchers = [
            (1, "APEXVIP500", 500.00, 1, 0, 1),
            (2, "CYBERWEEK20", 20.00, 500, 42, 1),
            (3, "BLACKHAT100", 100.00, 1, 0, 1)
        ]
        cur.executemany("INSERT INTO vouchers VALUES (?,?,?,?,?,?)", vouchers)

        # 8. Bank Accounts (Vault leaks statement flag)
        accounts = [
            (1, 1, "APEX-CHK-1001", "021000021", "Checking Account", 2450.00, "USD", "active"),
            (2, 2, "APEX-CHK-2002", "021000021", "Checking Account", 150.00, "USD", "active"),
            (3, 3, "APEX-SAV-3003", "021000021", "Savings Account", 4100.00, "USD", "active"),
            (4, 99, "APEX-VAULT-9999", "021000021", "Master Corporate Vault", 1000000.00, "USD", f"active [VaultSignature: {get_flag('bola_bank_account')}]")
        ]
        cur.executemany("INSERT INTO accounts VALUES (?,?,?,?,?,?,?,?)", accounts)

        # 9. Payment Cards (Card 3 belongs to admin)
        cards = [
            (1, 1, "MasterCard", "4321", 11, 2028, "Alice Walker", "98101"),
            (2, 2, "Visa", "8765", 8, 2027, "Bob Martinez", "78701"),
            (3, 99, "American Express Corporate", "0001", 12, 2030, f"ApexMart Enterprise Vault [{get_flag('bola_card_delete')}]", "20001")
        ]
        cur.executemany("INSERT INTO payment_cards VALUES (?,?,?,?,?,?,?,?)", cards)

        # 10. Audit Transactions (Tx 102 leaks BOLA tx flag)
        txs = [
            (101, "APEX-CHK-1001", "APEX-CHK-2002", 50.00, "USD", "Split hardware order", "completed", now),
            (102, "APEX-VAULT-9999", "APEX-CHK-1001", 5000.00, "USD", f"Q3 Security Clearance Audit [{get_flag('bola_tx_delete')}]", "completed", now),
            (103, "APEX-CHK-2002", "APEX-STORE-EXT", 29.99, "USD", "Firmware Subscription", "completed", now),
            (999, "APEX-VAULT-9999", "APEX-OFFSHORE-77", 250000.00, "USD", "Classified Reserve Transfer", "completed", now)
        ]
        cur.executemany("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?)", txs)

        # 11. Secret System Vault Table (Can ONLY be accessed via UNION SQL Injection!)
        vault = [
            (1, "MASTER_ROOT_FLAG", get_flag('sqli_transactions'), "TOP_SECRET_LEVEL_5"),
            (2, "AWS_PROD_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE", "RESTRICTED"),
            (3, "JWT_BACKDOOR_KEY", "apex-enterprise-insecure-master-jwt-key", "RESTRICTED"),
            (4, "STRIPE_SECRET_API_KEY", "rk_live_99214481023_sec_token", "RESTRICTED")
        ]
        cur.executemany("INSERT INTO admin_system_vault VALUES (?,?,?,?)", vault)

    conn.commit()
    conn.close()

def get_claimed_flags():
    """Retrieves all solved challenge IDs from the persistent database table."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT challenge_id FROM challenge_claims ORDER BY claimed_at ASC")
    rows = cur.fetchall()
    conn.close()
    return [r[0] for r in rows]

def add_claimed_flag(challenge_id: str) -> bool:
    """Persists a solved challenge ID to the database. Returns True if newly added, False if already claimed."""
    conn = get_db()
    cur = conn.cursor()
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("INSERT INTO challenge_claims (challenge_id, claimed_at) VALUES (?, ?)", (challenge_id, now))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def reset_claimed_flags():
    """Wipes all claimed challenges from the database."""
    conn = get_db()
    conn.execute("DELETE FROM challenge_claims")
    conn.commit()
    conn.close()

def find_free_port(start: int = 5000, end: int = 5100) -> int:
    """Finds an available TCP loopback port starting from start up to end."""
    import socket
    for p in range(start, end):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                res = s.connect_ex(('127.0.0.1', p))
                if res != 0:
                    return p
        except Exception:
            return p
    return start

def check_health(port: int = None) -> bool:
    """Polls the local /health endpoint. Returns True if healthy (200), False otherwise."""
    import urllib.request
    if port is None:
        try:
            port = int(os.environ.get("APEX_PORT", 5000))
        except (ValueError, TypeError):
            port = 5000
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as resp:
            return resp.status == 200
    except Exception:
        return False

if __name__ == "__main__":
    init_db(force=True)
    print("Database initialized successfully at:", DB_PATH)
