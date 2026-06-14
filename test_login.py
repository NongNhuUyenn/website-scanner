import requests
import re

dvwa_local = "http://localhost"
dvwa_zap   = "http://172.18.0.3"
ZAP_API_URL = "http://127.0.0.1:8080"

print("1. Lấy token...")
session = requests.Session()
r = session.get(f"{dvwa_local}/login.php", timeout=10)
token_match = re.search(r"user_token.*?value='([a-f0-9]+)'", r.text)
token = token_match.group(1) if token_match else ""
print(f"   Token: {token}")

print("2. Đăng nhập...")
session.post(f"{dvwa_local}/login.php", data={
    "username": "admin", "password": "password",
    "Login": "Login", "user_token": token
}, allow_redirects=True, timeout=10)
phpsessid = session.cookies.get("PHPSESSID")
print(f"   PHPSESSID: {phpsessid}")

print("3. Gửi sendRequest tới ZAP...")
raw_login = (
    f"POST {dvwa_zap}/login.php HTTP/1.1\r\n"
    f"Host: 172.18.0.3\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Cookie: PHPSESSID={phpsessid}; security=low\r\n"
    f"\r\n"
    f"username=admin&password=password&Login=Login&user_token={token}"
)
resp = requests.post(
    f"{ZAP_API_URL}/JSON/core/action/sendRequest/",
    data={"request": raw_login, "followRedirects": "true"},
    timeout=30
)
print(f"   Status: {resp.status_code}")
print(f"   Response: {resp.text[:300]}")

print("4. Set security=low...")
raw_security = (
    f"GET {dvwa_zap}/security.php HTTP/1.1\r\n"
    f"Host: 172.18.0.3\r\n"
    f"Cookie: PHPSESSID={phpsessid}; security=low\r\n"
    f"\r\n"
)
resp2 = requests.post(
    f"{ZAP_API_URL}/JSON/core/action/sendRequest/",
    data={"request": raw_security, "followRedirects": "true"},
    timeout=30
)
print(f"   Status: {resp2.status_code}")
print("Xong!")