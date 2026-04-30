# cip_auth — Break the Login (v1 Vulnerable)

Proiect pentru cursul **Dezvoltarea Aplicatiilor Software Securizate**  
Facultatea de Matematica si Informatica, Universitatea din Bucuresti

> **ATENTIE:** Aceasta este versiunea **intentionat vulnerabila** (v1).  
> Scopul este educational — demonstrarea si exploatarea vulnerabilitatilor de autentificare.  
> **NU rulati in productie sau pe o retea publica.**

---

## Despre aplicatie

**cip_auth** simuleaza o aplicatie interna a companiei fictive "AuthX".  
Contine urmatoarele module:

| Modul | Ruta |
|---|---|
| Register | `/register` |
| Login | `/login` |
| Dashboard | `/dashboard` |
| Logout | `/logout` |
| Forgot password | `/forgot_password` |
| Reset password | `/reset_password/<token>` |

---

## Vulnerabilitati intentionate (v1)

| # | Categorie | Descriere scurta |
|---|---|---|
| 4.1 | Password Policy slab | Nicio validare — accepta parole de 1 caracter |
| 4.2 | Stocare nesigura | Parole hashuite cu MD5 fara salt |
| 4.3 | Brute force | Fara rate limiting sau lockout pe login |
| 4.4 | User Enumeration | Mesaje diferite: "User not found" vs "Wrong password" |
| 4.5 | Sesiuni nesecurizate | Cookie fara HttpOnly, Secure, SameSite |
| 4.6 | Reset parola nesigur | Token = timestamp, reutilizabil, fara expirare |

---

## v1 vs v2 — comparație rapidă

| Aspect | v1 (vulnerabil) `cip_auth/` | v2 (securizat) `cip_auth_fixed/` |
|---|---|---|
| Port | 5000 | 5001 |
| Hash parole | MD5 fără salt | bcrypt rounds=12 |
| Politică parolă | Nicio validare | Min 8 chars + uppercase + digit |
| Rate limiting | Absent | 5 încercări / 60s per IP |
| Mesaj login eșuat | Diferit (user/parolă) | Generic: "Credentiale invalide" |
| Cookie sesiune | Fără HttpOnly/SameSite | HttpOnly + SameSite=Strict |
| Secret key | `"secret123"` hardcodat | `secrets.token_hex(32)` / env var |
| Reset token | `int(time.time())` | `secrets.token_urlsafe(32)` |
| Expirare token | Niciodată | 15 minute |
| Reutilizare token | Posibilă | Ștears după utilizare |

---

## Cum rulezi v1 (vulnerabil)

```bash
cd cip_auth
pip install -r requirements.txt
python app.py
# → http://localhost:5000
```

## Cum rulezi v2 (securizat)

```bash
cd cip_auth_fixed
pip install -r requirements.txt
python app.py
# → http://localhost:5001
```

Pot rula simultan — baze de date separate, porturi separate.

---

## Cerinte sistem

- Python 3.9+
- pip

---

## Instalare si rulare

```bash
# 1. Clonati sau copiati proiectul
cd cip_auth

# 2. (Optional) Creati un virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 3. Instalati dependentele
pip install -r requirements.txt

# 4. Porniti aplicatia
python app.py
```

Aplicatia ruleaza la: **http://localhost:5000**

---

## Structura proiectului

```
cip_auth/
├── app.py                  # Aplicatia Flask principala (cu vulnerabilitati comentate)
├── requirements.txt        # Dependente Python
├── cip_auth.db             # Baza de date SQLite (generata automat la start)
├── static/
│   └── style.css           # Stilizare UI
├── templates/
│   ├── base.html           # Template de baza (navbar)
│   ├── register.html       # Pagina de inregistrare
│   ├── login.html          # Pagina de autentificare
│   ├── dashboard.html      # Dashboard protejat
│   ├── forgot_password.html
│   └── reset_password.html
└── documentatie/
    ├── main.tex            # Document LaTeX principal
    ├── introducere.tex
    ├── setup_mediu.tex
    ├── implementare_mvp.tex
    ├── vulnerabilitati.tex
    ├── atac_poc.tex
    ├── analiza_impact.tex
    ├── implementare_fix.tex
    ├── retest.tex
    ├── audit_logging.tex
    └── concluzii.tex
```

---

## Utilizatori de test

Dupa pornire, inregistrati manual un cont prin `/register`.  
Puteti folosi parole extrem de slabe (ex: `1`, `a`, `pass`) — vulnerabilitatea #1.

---

## Demonstrarea vulnerabilitatilor

### User Enumeration (4.4)
```bash
# User inexistent → "Utilizatorul nu a fost gasit!"
curl -X POST http://localhost:5000/login \
  -d "email=inexistent@test.com&password=orice"

# User existent, parola gresita → "Parola este gresita!"
curl -X POST http://localhost:5000/login \
  -d "email=real@test.com&password=gresita"
```

### Brute Force (4.3)
```bash
# Incercati parole multiple fara blocare
for p in 1 a pass 123 admin secret parola; do
  curl -s -X POST http://localhost:5000/login \
    -d "email=victim@test.com&password=$p" | grep -o "gresita\|gasit\|dashboard"
done
```

### Token predictibil (4.6)
```bash
# Generati un token si observati ca este timestamp-ul curent
curl -X POST http://localhost:5000/forgot_password \
  -d "email=victim@test.com"
# Tokenul va fi ceva de genul: 1714000000
# Puteti enumera: for t in $(seq 1713999990 1714000010); do curl .../reset_password/$t; done
```

### Cookie nesecurizat (4.5)
Dupa login, deschideti consola browserului (F12) si rulati:
```javascript
document.cookie  // Veti vedea user_email in clar
```

---

## Baza de date

SQLite — fisierul `cip_auth.db` este creat automat.  
Puteti inspecta datele cu:
```bash
sqlite3 cip_auth.db
sqlite> SELECT email, password FROM users;
sqlite> SELECT * FROM reset_tokens;
sqlite> SELECT * FROM audit_logs;
```

Parolele sunt stocate ca MD5 — puteti verifica pe [crackstation.net](https://crackstation.net).

---

## Tehnologii folosite

- **Python 3** + **Flask 3.0**
- **SQLite** (via modulul `sqlite3` din stdlib)
- **Jinja2** (inclus in Flask) pentru template-uri HTML
- **CSS** custom (fara framework extern)
