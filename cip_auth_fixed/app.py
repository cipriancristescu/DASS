"""
cip_auth - Aplicatie de autentificare SECURIZATA
Versiunea: v2 (fixed)
Scop: Versiunea remediata a v1 pentru cursul DASS

Ruleaza pe portul 5001 (v1 ruleaza pe 5000).
"""

import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta

import bcrypt
from flask import (
    Flask, render_template, request,
    redirect, url_for, session
)

app = Flask(__name__)

# FIX #5a: Secret key din variabila de mediu.
# Daca nu e setata, generam unul aleatoriu la fiecare pornire (sigur pentru dev).
# In productie: export SECRET_KEY="<cheie-lunga-aleatorie>"
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# FIX #5b: Configurare sesiune securizata
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # nu accesibil din JavaScript
    SESSION_COOKIE_SECURE=False,        # True in productie (HTTPS obligatoriu)
    SESSION_COOKIE_SAMESITE="Strict",   # protectie CSRF
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
)

DATABASE = "cip_auth_fixed.db"


# ─────────────────────────────────────────────
# RATE LIMITING (FIX #3)
# ─────────────────────────────────────────────
# Dict in-memorie: { ip: [timestamp1, timestamp2, ...] }
# Nu necesita dependente externe — suficient pentru un server single-process.

_login_attempts = {}
RATE_WINDOW = 60    # fereastra de timp in secunde
RATE_MAX    = 5     # incercari maxime in fereastra


def _clean_window(ip):
    """Pastreaza doar incercarile din fereastra curenta."""
    cutoff = time.time() - RATE_WINDOW
    _login_attempts[ip] = [t for t in _login_attempts.get(ip, []) if t > cutoff]


def is_rate_limited(ip):
    """Returneaza (blocat: bool, secunde_ramase: int)."""
    _clean_window(ip)
    attempts = _login_attempts.get(ip, [])
    if len(attempts) >= RATE_MAX:
        remaining = int(RATE_WINDOW - (time.time() - attempts[0]))
        return True, max(remaining, 1)
    return False, 0


def record_failed_attempt(ip):
    _login_attempts.setdefault(ip, []).append(time.time())


def clear_attempts(ip):
    _login_attempts.pop(ip, None)


# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            role        TEXT DEFAULT 'USER',
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            locked      INTEGER DEFAULT 0
        )
    """)
    # FIX #6: Coloana expires_at pentru expirarea tokenului
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reset_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT NOT NULL,
            token       TEXT UNIQUE NOT NULL,
            expires_at  TEXT NOT NULL,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            action      TEXT,
            resource    TEXT,
            ip_address  TEXT,
            timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def log_action(user_id, action, resource, ip):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)",
        (user_id, action, resource, ip)
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# HASH PAROLE (FIX #2)
# ─────────────────────────────────────────────

def hash_password(password):
    # bcrypt genereaza automat un salt unic si aplica 12 runde de hashing.
    # Este intentionat lent: ~250ms/hash face brute force impractical.
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())


# ─────────────────────────────────────────────
# VALIDARE PAROLA (FIX #1)
# ─────────────────────────────────────────────

def validate_password(password):
    """Returneaza mesajul de eroare sau None daca parola respecta politica."""
    if len(password) < 8:
        return "Parola trebuie sa aiba cel putin 8 caractere."
    if not re.search(r"[A-Z]", password):
        return "Parola trebuie sa contina cel putin o litera mare (A-Z)."
    if not re.search(r"[0-9]", password):
        return "Parola trebuie sa contina cel putin o cifra (0-9)."
    return None


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("login"))


# ── REGISTER ──────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            return render_template("register.html",
                                   error="Campurile sunt obligatorii.")

        # FIX #1: Validare politica parola inainte de stocare
        err = validate_password(password)
        if err:
            return render_template("register.html", error=err)

        conn = get_db()
        try:
            # FIX #2: Stocare cu bcrypt (nu MD5)
            conn.execute(
                "INSERT INTO users (email, password) VALUES (?, ?)",
                (email, hash_password(password))
            )
            conn.commit()
            log_action(None, "REGISTER", "auth", request.remote_addr)
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template("register.html",
                                   error="Email-ul exista deja.")
        finally:
            conn.close()

    return render_template("register.html")


# ── LOGIN ─────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip       = request.remote_addr
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # FIX #3: Rate limiting — verificam inainte de orice interogare DB
        blocked, remaining = is_rate_limited(ip)
        if blocked:
            return render_template(
                "login.html",
                error=f"Prea multe incercari esuate. Reincearca in {remaining}s."
            )

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        conn.close()

        # FIX #4: Mesaj generic — nu revela daca emailul exista sau nu.
        # FIX #2: Verificare cu bcrypt (timp constant).
        if not user or not verify_password(password, user["password"]):
            record_failed_attempt(ip)
            # FIX #3: Logam si incercarile esuate
            log_action(None, "LOGIN_FAILED", "auth", ip)
            return render_template("login.html",
                                   error="Credentiale invalide.")

        # Login reusit — stergem contorul de incercari
        clear_attempts(ip)
        session.permanent = True
        session["user_id"] = user["id"]
        session["email"]   = user["email"]
        session["role"]    = user["role"]
        log_action(user["id"], "LOGIN", "auth", ip)

        # FIX #5: Nu mai setam cookie-ul user_email nesecurizat
        return redirect(url_for("dashboard"))

    return render_template("login.html")


# ── DASHBOARD ─────────────────────────────────

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10",
        (session["user_id"],)
    ).fetchall()
    conn.close()

    return render_template(
        "dashboard.html",
        email=session["email"],
        role=session["role"],
        logs=logs
    )


# ── LOGOUT ────────────────────────────────────

@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    log_action(user_id, "LOGOUT", "auth", request.remote_addr)
    session.clear()
    return redirect(url_for("login"))


# ── FORGOT PASSWORD ───────────────────────────

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()

        conn = get_db()
        # FIX #6b: Stergem toate tokenurile vechi pentru acest email
        conn.execute("DELETE FROM reset_tokens WHERE email = ?", (email,))

        # FIX #6a: Token criptografic aleatoriu (256 biti de entropie)
        token = secrets.token_urlsafe(32)

        # FIX #6c: Expirare dupa 15 minute
        expires_at = (datetime.utcnow() + timedelta(minutes=15)).isoformat()

        conn.execute(
            "INSERT INTO reset_tokens (email, token, expires_at) VALUES (?, ?, ?)",
            (email, token, expires_at)
        )
        conn.commit()
        conn.close()

        # In productie, link-ul se trimite pe email (nu se afiseaza in UI).
        # Afisam link-ul doar pentru demonstratia de laborator.
        reset_link = url_for("reset_password", token=token, _external=True)
        return render_template(
            "forgot_password.html",
            message="Link de resetare generat (valid 15 minute):",
            link=reset_link
        )

    return render_template("forgot_password.html")


# ── RESET PASSWORD ────────────────────────────

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = get_db()

    # FIX #6c: Verificam existenta SI expirarea tokenului
    now = datetime.utcnow().isoformat()
    reset_entry = conn.execute(
        "SELECT * FROM reset_tokens WHERE token = ? AND expires_at > ?",
        (token, now)
    ).fetchone()

    if not reset_entry:
        conn.close()
        return render_template("reset_password.html",
                               error="Token invalid sau expirat.", token=token)

    if request.method == "POST":
        new_password = request.form.get("password", "")

        # FIX #1: Validam si noua parola
        err = validate_password(new_password)
        if err:
            conn.close()
            return render_template("reset_password.html", token=token, error=err)

        conn.execute(
            "UPDATE users SET password = ? WHERE email = ?",
            (hash_password(new_password), reset_entry["email"])
        )
        # FIX #6d: Stergem tokenul dupa utilizare (one-time use)
        conn.execute("DELETE FROM reset_tokens WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        return redirect(url_for("login"))

    conn.close()
    return render_template("reset_password.html", token=token)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="0.0.0.0", port=5001)
