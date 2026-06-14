import requests
import re
import time

ZAP_API    = "http://localhost:8080"
DVWA_LOCAL = "http://localhost"
DVWA_ZAP   = "http://172.18.0.3"

# Bước 1: Lấy token và cookie qua localhost (Python có thể kết nối)
session = requests.Session()
r = session.get(f"{DVWA_LOCAL}/login.php")
token = re.search(r"user_token.*?value='([a-f0-9]+)'", r.text)
token = token.group(1) if token else ""
print(f"[1] Token: {token}")

# Bước 2: Đăng nhập qua localhost để lấy session hợp lệ
r = session.post(f"{DVWA_LOCAL}/login.php", data={
    "username": "admin",
    "password": "password",
    "Login":    "Login",
    "user_token": token
}, allow_redirects=True)
phpsessid = session.cookies.get("PHPSESSID")
print(f"[2] PHPSESSID: {phpsessid}")

# Bước 3: Xây dựng raw HTTP request để ZAP gửi đăng nhập
# ZAP sẽ gửi request này và lưu cookie nhận được vào bộ nhớ của nó
raw_request = (
    f"POST {DVWA_ZAP}/login.php HTTP/1.1\r\n"
    f"Host: 172.18.0.3\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Cookie: PHPSESSID={phpsessid}; security=low\r\n"
    f"\r\n"
    f"username=admin&password=password&Login=Login&user_token={token}"
)

r = requests.post(
    f"{ZAP_API}/JSON/core/action/sendRequest/",
    data={"request": raw_request, "followRedirects": "true"}
)
resp = r.json()
# Lấy cookie ZAP nhận được từ DVWA
cookie_params = resp.get("sendRequest", [{}])[0].get("cookieParams", "")
print(f"[3] ZAP login response cookies: {cookie_params}")

# Bước 4: Set security=low
raw2 = (
    f"GET {DVWA_ZAP}/security.php HTTP/1.1\r\n"
    f"Host: 172.18.0.3\r\n"
    f"Cookie: PHPSESSID={phpsessid}; security=low\r\n"
    f"\r\n"
)
requests.post(f"{ZAP_API}/JSON/core/action/sendRequest/",
              data={"request": raw2, "followRedirects": "true"})
print("[4] Security level set")

# Bước 5: Chạy Spider với cookie trong context
r = requests.get(f"{ZAP_API}/JSON/spider/action/scan/", params={
    "url":         f"{DVWA_ZAP}/",
    "maxChildren": "30",
    "recurse":     "true"
})
scan_id = r.json().get("scan", "0")
print(f"[5] Spider ID: {scan_id}")

# Bước 6: Đợi Spider xong
print("[6] Đang Spider...")
for _ in range(40):
    r   = requests.get(f"{ZAP_API}/JSON/spider/view/status/",
                       params={"scanId": scan_id})
    pct = int(r.json().get("status", 0))
    print(f"    {pct}%")
    if pct >= 100:
        break
    time.sleep(3)

# Bước 7: In kết quả
r    = requests.get(f"{ZAP_API}/JSON/spider/view/results/",
                    params={"scanId": scan_id})
urls = r.json().get("results", [])
print(f"\n[7] Tổng URL tìm được: {len(urls)}")
print("Các trang quan trọng:")
for u in urls:
    if any(x in u for x in ["sqli","xss","upload","vulnerab",
                             "index.php","brute","exec","fi","csrf"]):
        print(f"  >> {u}")