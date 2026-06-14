import requests
import re

ZAP_API    = "http://localhost:8080"
DVWA_LOCAL = "http://localhost"
DVWA_ZAP   = "http://172.18.0.3"

# Xóa rule cũ
requests.get(f"{ZAP_API}/JSON/replacer/action/removeRule/", params={"description": "auth_cookie"})
requests.get(f"{ZAP_API}/JSON/replacer/action/removeRule/", params={"description": "dvwa_auth_cookie"})

# Đăng nhập lấy cookie
session = requests.Session()
r = session.get(f"{DVWA_LOCAL}/login.php")
token = re.search(r"user_token.*?value='([a-f0-9]+)'", r.text)
token = token.group(1) if token else ""
session.post(f"{DVWA_LOCAL}/login.php", data={
    "username": "admin", "password": "password",
    "Login": "Login", "user_token": token
})
phpsessid = session.cookies.get("PHPSESSID")
print(f"PHPSESSID: {phpsessid}")

# Inject cookie vào ZAP
requests.get(f"{ZAP_API}/JSON/replacer/action/addRule/", params={
    "description": "dvwa_auth_cookie",
    "enabled":     "true",
    "matchType":   "REQ_HEADER",
    "matchRegex":  "false",
    "matchString": "Cookie",
    "replacement": f"PHPSESSID={phpsessid}; security=low",
    "initiators":  ""
})
print("Cookie đã inject vào ZAP. Bây giờ quét từ http://localhost:5000")