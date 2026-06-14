import requests
import time
import sys
sys.path.append("..")
from config import ZAP_API_URL, SCAN_TIMEOUT


def kiem_tra_zap():
    """Kiểm tra ZAP daemon có đang chạy không."""
    try:
        r = requests.get(f"{ZAP_API_URL}/JSON/core/view/version/", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def bat_dau_spider(target_url):
    """Chạy Spider để ZAP duyệt toàn bộ các liên kết trên website mục tiêu."""
    r = requests.get(f"{ZAP_API_URL}/JSON/spider/action/scan/", params={
        "url": target_url,
        "maxChildren": 10,
        "recurse": "true"
    })
    return r.json().get("scan", "0")


def cho_spider_xong(scan_id):
    """Đợi Spider duyệt xong, trả về True nếu hoàn thành."""
    start = time.time()
    while time.time() - start < SCAN_TIMEOUT:
        r = requests.get(f"{ZAP_API_URL}/JSON/spider/view/status/", params={"scanId": scan_id})
        tien_do = int(r.json().get("status", 0))
        print(f"Spider: {tien_do}%")
        if tien_do >= 100:
            return True
        time.sleep(3)
    return False


def bat_dau_active_scan(target_url):
    """Chạy Active Scan để ZAP thử các payload tấn công."""
    r = requests.get(f"{ZAP_API_URL}/JSON/ascan/action/scan/", params={
        "url": target_url,
        "recurse": "true"
    })
    return r.json().get("scan", "0")


def cho_active_scan_xong(scan_id):
    """Đợi Active Scan hoàn thành."""
    start = time.time()
    while time.time() - start < SCAN_TIMEOUT:
        r = requests.get(f"{ZAP_API_URL}/JSON/ascan/view/status/", params={"scanId": scan_id})
        tien_do = int(r.json().get("status", 0))
        print(f"Active Scan: {tien_do}%")
        if tien_do >= 100:
            return True
        time.sleep(5)
    return False


def lay_canh_bao(target_url):
    """Lấy toàn bộ cảnh báo lỗ hổng ZAP tìm được."""
    r = requests.get(f"{ZAP_API_URL}/JSON/core/view/alerts/", params={
        "baseurl": target_url,
        "start": 0,
        "count": 200
    })
    return r.json().get("alerts", [])