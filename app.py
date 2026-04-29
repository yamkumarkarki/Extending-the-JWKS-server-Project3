import os
import sqlite3
import uuid
import time
import base64
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque

from flask import Flask, jsonify, request
import jwt
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "totally_not_my_privateKeys.db")

ISSUER = "jwks-server"
ph = PasswordHasher()
rate_limit_store = defaultdict(deque)


def get_cipher():
    secret = os.environ.get("NOT_MY_KEY", "default-secret-key")
    key = base64.urlsafe_b64encode(secret.ljust(32)[:32].encode())
    return Fernet(key)


def db():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY,
        key TEXT NOT NULL,
        exp INTEGER NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()


def generate_key(kid, expired=False):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    encrypted_key = get_cipher().encrypt(pem).decode()

    exp = int(
        (datetime.now(timezone.utc) +
         timedelta(hours=-1 if expired else 1)).timestamp()
    )

    conn = db()
    cur = conn.cursor()

    cur.execute(
        "INSERT OR REPLACE INTO keys(kid, key, exp) VALUES (?, ?, ?)",
        (kid, encrypted_key, exp)
    )

    conn.commit()
    conn.close()


def ensure_keys():
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM keys")
    count = cur.fetchone()[0]

    conn.close()

    if count == 0:
        generate_key(1, False)
        generate_key(2, True)


def decrypt_private_key(enc):
    pem = get_cipher().decrypt(enc.encode())
    return serialization.load_pem_private_key(pem, password=None)


def get_key(expired=False):
    now = int(datetime.now(timezone.utc).timestamp())

    conn = db()
    cur = conn.cursor()

    if expired:
        cur.execute("SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1", (now,))
    else:
        cur.execute("SELECT kid, key FROM keys WHERE exp > ? LIMIT 1", (now,))

    row = cur.fetchone()
    conn.close()

    if not row:
        return None, None

    kid, enc = row
    return kid, decrypt_private_key(enc)


def int_to_base64url(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def log_auth(user_id=None):
    ip = request.remote_addr or "unknown"

    conn = db()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO auth_logs(request_ip, user_id) VALUES (?, ?)",
        (ip, user_id)
    )

    conn.commit()
    conn.close()


def get_user_id(username):
    if not username:
        return None

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cur.fetchone()

    conn.close()

    return row[0] if row else None


def rate_limited():
    ip = request.remote_addr or "unknown"
    now = time.time()

    q = rate_limit_store[ip]

    while q and now - q[0] > 1:
        q.popleft()

    if len(q) >= 10:
        return True

    q.append(now)
    return False


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    email = data.get("email")

    if not username or not email:
        return jsonify({"error": "missing fields"}), 400

    password = str(uuid.uuid4())
    password_hash = ph.hash(password)

    try:
        conn = db()
        cur = conn.cursor()

        cur.execute(
            "INSERT INTO users(username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email)
        )

        conn.commit()
        conn.close()

    except sqlite3.IntegrityError:
        return jsonify({"error": "exists"}), 409

    return jsonify({"password": password}), 201


@app.route("/auth", methods=["POST"])
def auth():
    if rate_limited():
        return jsonify({"error": "Too Many Requests"}), 429

    expired = request.args.get("expired") == "true"

    username = None
    data = request.get_json(silent=True)

    if data:
        username = data.get("username")

    kid, private_key = get_key(expired)

    if not private_key:
        return jsonify({"error": "no key"}), 500

    now = datetime.now(timezone.utc)
    exp_time = now - timedelta(hours=1) if expired else now + timedelta(hours=1)

    payload = {
        "sub": username or "user",
        "iat": int(now.timestamp()),
        "exp": int(exp_time.timestamp()),
        "iss": ISSUER
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": str(kid)}
    )

    user_id = get_user_id(username)
    log_auth(user_id)

    return token


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    now = int(datetime.now(timezone.utc).timestamp())

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))
    rows = cur.fetchall()

    conn.close()

    keys = []

    for kid, enc in rows:
        private_key = decrypt_private_key(enc)
        public_key = private_key.public_key()
        nums = public_key.public_numbers()

        keys.append({
            "kty": "RSA",
            "use": "sig",
            "kid": str(kid),
            "alg": "RS256",
            "n": int_to_base64url(nums.n),
            "e": int_to_base64url(nums.e)
        })

    return jsonify({"keys": keys})


if __name__ == "__main__":
    init_db()
    ensure_keys()
    app.run(host="127.0.0.1", port=8080)