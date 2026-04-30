import requests

url = "http://127.0.0.1:5001/login"
email = "fixed@test.com"

passwords = ["admin", "123456", "password", "test", "parola", "Parola12"]

session = requests.Session()

for password in passwords:
    response = session.post(
        url,
        data={"email": email, "password": password},
        allow_redirects=False
    )

    print(f"Incerc parola: {password} | status={response.status_code}")

    # detect rate limiting
    if "Prea multe incercari" in response.text:
        print("[+] Rate limiting activ — atac blocat")
        break

    # detect succes (teoretic)
    if response.status_code == 302 and "/dashboard" in response.headers.get("Location", ""):
        print(f"[!] Parola gasita: {password}")
        break