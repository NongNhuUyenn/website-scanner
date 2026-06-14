from flask import Flask, render_template, request, jsonify
import threading
import time
import requests
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import ZAP_API_URL, SCAN_TIMEOUT
from scanner.analyzer import xu_ly_canh_bao

app = Flask(__name__)

trang_thai = {
    "dang_quet": False,
    "tien_do": 0,
    "buoc": "",
    "ket_qua": None,
    "loi": None
}


def dang_nhap_dvwa(target_url):
    """
    Đăng nhập DVWA và inject cookie vào ZAP.
    Chuyển từ black-box sang gray-box — ZAP có thể quét
    các trang sau màn hình đăng nhập (SQLi, XSS, Upload...).
    Trả về True nếu thành công.
    """
    try:
        # Xác định base URL của DVWA
        if "172.18.0.3" in target_url:
            dvwa_local = "http://localhost"
            dvwa_zap   = "http://172.18.0.3"
        else:
            return False  # Không phải DVWA, bỏ qua

        # Bước 1: Lấy CSRF token từ trang login
        session = requests.Session()
        r = session.get(f"{dvwa_local}/login.php", timeout=5)
        token_match = re.search(r"user_token.*?value='([a-f0-9]+)'", r.text)
        token = token_match.group(1) if token_match else ""

        # Bước 2: Đăng nhập lấy PHPSESSID
        session.post(f"{dvwa_local}/login.php", data={
            "username":   "admin",
            "password":   "password",
            "Login":      "Login",
            "user_token": token
        }, allow_redirects=True, timeout=5)
        phpsessid = session.cookies.get("PHPSESSID")
        if not phpsessid:
            return False

        # Bước 3: Cho ZAP gửi request login để lưu session
        raw_login = (
            f"POST {dvwa_zap}/login.php HTTP/1.1\r\n"
            f"Host: 172.18.0.3\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Cookie: PHPSESSID={phpsessid}; security=low\r\n"
            f"\r\n"
            f"username=admin&password=password&Login=Login&user_token={token}"
        )
        requests.post(
            f"{ZAP_API_URL}/JSON/core/action/sendRequest/",
            data={"request": raw_login, "followRedirects": "true"},
            timeout=10
        )

        # Bước 4: Set security=low
        raw_security = (
            f"GET {dvwa_zap}/security.php HTTP/1.1\r\n"
            f"Host: 172.18.0.3\r\n"
            f"Cookie: PHPSESSID={phpsessid}; security=low\r\n"
            f"\r\n"
        )
        requests.post(
            f"{ZAP_API_URL}/JSON/core/action/sendRequest/",
            data={"request": raw_security, "followRedirects": "true"},
            timeout=10
        )

        # Bước 5: Xóa rule cũ nếu có, rồi inject cookie mới
        try:
            rules = requests.get(
                f"{ZAP_API_URL}/JSON/replacer/view/rules/",
                timeout=5
            ).json().get("rules", [])
            for rule in rules:
                if rule.get("description") == "dvwa_auth_cookie":
                    requests.get(
                        f"{ZAP_API_URL}/JSON/replacer/action/removeRule/",
                        params={"description": "dvwa_auth_cookie"},
                        timeout=5
                    )
        except Exception:
            pass

        requests.get(f"{ZAP_API_URL}/JSON/replacer/action/addRule/", params={
            "description": "dvwa_auth_cookie",
            "enabled":     "true",
            "matchType":   "REQ_HEADER",
            "matchRegex":  "false",
            "matchString": "Cookie",
            "replacement": f"PHPSESSID={phpsessid}; security=low",
            "initiators":  ""
        }, timeout=5)

        return True

    except Exception:
        return False


def chay_quet(target_url):
    global trang_thai
    trang_thai.update({"dang_quet": True, "tien_do": 0, "ket_qua": None, "loi": None})

    try:
        # Bước 1: Kiểm tra ZAP
        trang_thai["buoc"] = "Đang kết nối ZAP..."
        r = requests.get(f"{ZAP_API_URL}/JSON/core/view/version/", timeout=120)
        if r.status_code != 200:
            raise Exception("Không kết nối được ZAP daemon")

        # Bước 1.5: Đăng nhập nếu là DVWA
        if "dvwa" in target_url.lower() or "172.18.0.3" in target_url:
            trang_thai["buoc"] = "Đang đăng nhập DVWA (gray-box)..."
            trang_thai["tien_do"] = 5
            ok = dang_nhap_dvwa(target_url)
            if ok:
                trang_thai["buoc"] = "Đăng nhập thành công — ZAP có thể quét bên trong..."
            time.sleep(1)

        # Bước 2: Spider
        trang_thai["buoc"] = "Spider đang duyệt website..."
        trang_thai["tien_do"] = 10
        r = requests.get(f"{ZAP_API_URL}/JSON/spider/action/scan/", params={
            "url": target_url, "maxChildren": 30, "recurse": "true"
        })
        spider_id = r.json().get("scan", "0")

        start = time.time()
        while time.time() - start < SCAN_TIMEOUT:
            r = requests.get(f"{ZAP_API_URL}/JSON/spider/view/status/",
                             params={"scanId": spider_id})
            pct = int(r.json().get("status", 0))
            trang_thai["tien_do"] = 10 + int(pct * 0.25)
            trang_thai["buoc"] = f"Spider đang duyệt website... {pct}%"
            if pct >= 100:
                break
            time.sleep(3)

        # Bước 3: Active Scan
        trang_thai["buoc"] = "Đang quét lỗ hổng (Active Scan)..."
        trang_thai["tien_do"] = 35
        r = requests.get(f"{ZAP_API_URL}/JSON/ascan/action/scan/", params={
            "url": target_url, "recurse": "true"
        })
        ascan_result = r.json()

        # Nếu url_not_found thì lấy URL từ sites tree
        if ascan_result.get("code") == "url_not_found":
            sites_r = requests.get(f"{ZAP_API_URL}/JSON/core/view/sites/")
            sites = sites_r.json().get("sites", [])
            for s in sites:
                domain = target_url.split("//")[-1].split("/")[0]
                if domain in s:
                    r = requests.get(f"{ZAP_API_URL}/JSON/ascan/action/scan/", params={
                        "url": s, "recurse": "true"
                    })
                    ascan_result = r.json()
                    break

        ascan_id = ascan_result.get("scan", "0")

        start = time.time()
        while time.time() - start < SCAN_TIMEOUT:
            r = requests.get(f"{ZAP_API_URL}/JSON/ascan/view/status/",
                             params={"scanId": ascan_id})
            pct = int(r.json().get("status", 0))
            trang_thai["tien_do"] = 35 + int(pct * 0.55)
            trang_thai["buoc"] = f"Đang quét lỗ hổng... {pct}%"
            if pct >= 100:
                break
            time.sleep(5)

        # Bước 4: Lấy kết quả
        trang_thai["buoc"] = "Đang phân tích kết quả..."
        trang_thai["tien_do"] = 92
        r = requests.get(f"{ZAP_API_URL}/JSON/core/view/alerts/", params={
            "baseurl": target_url, "start": 0, "count": 500
        })
        canh_bao = r.json().get("alerts", [])

        # Fallback: lấy tất cả nếu không có
        if not canh_bao:
            r = requests.get(f"{ZAP_API_URL}/JSON/core/view/alerts/", params={
                "start": 0, "count": 500
            })
            canh_bao = r.json().get("alerts", [])

        ket_qua = xu_ly_canh_bao(canh_bao)

        trang_thai["tien_do"] = 100
        trang_thai["buoc"] = "Hoàn thành!"
        trang_thai["ket_qua"] = {"url": target_url, "canh_bao": ket_qua}

    except Exception as e:
        trang_thai["loi"] = str(e)
    finally:
        trang_thai["dang_quet"] = False


@app.route("/")
def trang_chu():
    return render_template("index.html")


@app.route("/quet", methods=["POST"])
def bat_dau_quet():
    url = request.form.get("url", "").strip()
    if not url.startswith("http"):
        return jsonify({"loi": "URL phải bắt đầu bằng http hoặc https"}), 400
    if trang_thai["dang_quet"]:
        return jsonify({"loi": "Đang có lượt quét khác chạy, vui lòng đợi"}), 400

    thread = threading.Thread(target=chay_quet, args=(url,))
    thread.daemon = True
    thread.start()
    return jsonify({"ok": True})


@app.route("/tien-do")
def xem_tien_do():
    return jsonify({
        "dang_quet": trang_thai["dang_quet"],
        "tien_do":   trang_thai["tien_do"],
        "buoc":      trang_thai["buoc"],
        "xong":      trang_thai["ket_qua"] is not None,
        "loi":       trang_thai["loi"]
    })


@app.route("/ket-qua")
def xem_ket_qua():
    if trang_thai["ket_qua"] is None:
        return render_template("index.html")
    return render_template("result.html", data=trang_thai["ket_qua"])


if __name__ == "__main__":
    app.run(debug=True, port=5000)