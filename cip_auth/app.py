"""
cip_auth - Aplicatie de autentificare INTENTIONAT VULNERABILA
Versiunea: v1 (vulnerable)
Scop: Demonstrarea vulnerabilitatilor de autentificare pentru cursul DASS

ATENTIE: Aceasta versiune contine vulnerabilitati intentionate pentru scop educational.
NU se foloseste in productie.
"""

import sqlite3
import hashlib
import time
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, make_response
)

app = Flask(__name__)

# VULNERABILITATE #5: Secret key slab si hardcodat in cod
# Un atacator care vede codul poate forja cookie-uri de sesiune
app.secret_key = "secret123"

DATABASE = "cip_auth.db"


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
    # VULNERABILITATE #6: Tokenuri de resetare fara expirare
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reset_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT NOT NULL,
            token       TEXT NOT NULL,
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
# HASH PAROLE
# ─────────────────────────────────────────────

# VULNERABILITATE #2: MD5 fara salt
# MD5 este considerat complet compromis pentru stocarea parolelor.
# Tabele rainbow precompute pot sparge MD5 in secunde.
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


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

        # VULNERABILITATE #1: Nu exista nicio validare a parolei.
        # Sunt acceptate parole extrem de slabe precum "1", "a", "123456".
        # Nicio verificare de lungime, complexitate sau liste de parole comune.

        if not email or not password:
            return render_template("register.html", error="Campurile sunt obligatorii.")

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (email, password) VALUES (?, ?)",
                (email, hash_password(password))
            )
            conn.commit()
            log_action(None, "REGISTER", "auth", request.remote_addr)
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Email-ul exista deja.")
        finally:
            conn.close()

    return render_template("register.html")


# ── LOGIN ─────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # VULNERABILITATE #3: Fara rate limiting.
        # Un atacator poate incerca sute de parole pe secunda fara nicio blocare.
        # Nu exista lockout, CAPTCHA sau delay artificial.

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        conn.close()

        # VULNERABILITATE #4: User enumeration.
        # Mesajele de eroare diferentiate permit unui atacator sa afle
        # ce adrese de email sunt inregistrate in sistem.
        if not user:
            return render_template("login.html", error="Utilizatorul nu a fost gasit!")

        if user["password"] != hash_password(password):
            return render_template("login.html", error="Parola este gresita!")

        # Login reusit
        session["user_id"] = user["id"]
        session["email"]   = user["email"]
        session["role"]    = user["role"]

        log_action(user["id"], "LOGIN", "auth", request.remote_addr)

        # VULNERABILITATE #5: Cookie nesecurizat.
        # httponly=False  → cookie accesibil din JavaScript (risc XSS)
        # secure=False    → cookie trimis si pe HTTP, nu doar HTTPS
        # samesite=None   → vulnerabil la CSRF
        response = make_response(redirect(url_for("dashboard")))
        response.set_cookie(
            "user_email",
            email,
            httponly=False,
            secure=False,
            samesite=None
        )
        return response

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

        # VULNERABILITATE #6a: Token predictibil.
        # Tokenul este timestamp-ul Unix curent.
        # Un atacator care stie aproximativ cand a fost ceruta resetarea
        # poate enumera toate valorile posibile.
        token = str(int(time.time()))

        conn = get_db()
        # VULNERABILITATE #6b: Tokenurile vechi nu sunt sterse.
        # Un token emis anterior ramane valid → poate fi reutilizat.
        conn.execute(
            "INSERT INTO reset_tokens (email, token) VALUES (?, ?)",
            (email, token)
        )
        conn.commit()
        conn.close()

        # In productie link-ul s-ar trimite pe email.
        # Aici il afisam direct pentru demonstratie (PoC).
        reset_link = url_for("reset_password", token=token, _external=True)
        return render_template(
            "forgot_password.html",
            message="Link de resetare generat:",
            link=reset_link
        )

    return render_template("forgot_password.html")


# ── RESET PASSWORD ────────────────────────────

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = get_db()

    # VULNERABILITATE #6c: Nu verificam expirarea tokenului.
    # Un token de acum 3 zile este la fel de valid ca unul de acum 3 secunde.
    reset_entry = conn.execute(
        "SELECT * FROM reset_tokens WHERE token = ?", (token,)
    ).fetchone()

    if not reset_entry:
        conn.close()
        return render_template("reset_password.html", error="Token invalid.", token=token)

    if request.method == "POST":
        new_password = request.form.get("password", "")

        conn.execute(
            "UPDATE users SET password = ? WHERE email = ?",
            (hash_password(new_password), reset_entry["email"])
        )

        # VULNERABILITATE #6d: Tokenul NU este sters dupa utilizare.
        # Acelasi token poate fi folosit din nou pentru a schimba parola.
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
    # VULNERABILITATE: Debug=True in productie expune stack traces
    app.run(debug=True, host="0.0.0.0", port=5000)
