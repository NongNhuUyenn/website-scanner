# scanner/analyzer.py

# ── OWASP TOP 10 2025 ─────────────────────────────────────────────────────────
OWASP_TOP10 = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

# ── FALLBACK: CWE → OWASP 2025 ───────────────────────────────────────────────
CWE_SANG_OWASP = {
    # A01 - Broken Access Control
    "22": "A01", "23": "A01", "284": "A01", "285": "A01",
    "639": "A01", "352": "A01", "601": "A01", "548": "A01",

    # A02 - Security Misconfiguration
    "1021": "A02", "693": "A02", "16": "A02", "200": "A02",
    "209": "A02", "215": "A02", "614": "A02", "1004": "A02", "1275": "A02",

    # A04 - Cryptographic Failures
    "326": "A04", "327": "A04", "330": "A04", "311": "A04",
    "319": "A04", "497": "A04",

    # A05 - Injection
    "89": "A05", "77": "A05", "78": "A05", "94": "A05",
    "79": "A05", "80": "A05", "917": "A05",

    # A07 - Authentication Failures
    "287": "A07", "306": "A07", "521": "A07",

    # A08 - Software or Data Integrity Failures
    "611": "A08", "434": "A08",

    # A10 - Mishandling of Exceptional Conditions
    "755": "A10", "390": "A10",
}

# ── MỨC ĐỘ ───────────────────────────────────────────────────────────────────
MUC_DO_VIET = {
    "High":          "Cao",
    "Medium":        "Trung bình",
    "Low":           "Thấp",
    "Informational": "Thông tin",
}

MUC_DO_MAU = {
    "High":          "red",
    "Medium":        "orange",
    "Low":           "yellow",
    "Informational": "blue",
}

MUC_DO_THU_TU = {
    "High": 4, "Medium": 3, "Low": 2, "Informational": 1
}


# ── HÀM LẤY TAG TỪ ZAP ───────────────────────────────────────────────────────
def lay_owasp_tu_tags(tags: dict) -> str:
    """Ưu tiên 2025, fallback 2021, fallback 2017."""
    for prefix in ["OWASP_2025_", "OWASP_2021_", "OWASP_2017_"]:
        for key in tags:
            if key.startswith(prefix):
                return key.replace(prefix, "")
    return None


def lay_wstg_tu_tags(tags: dict) -> list:
    return [{"id": k, "url": v} for k, v in tags.items() if k.startswith("WSTG-")]


def lay_links_tu_tags(tags: dict, cweid: str) -> list:
    links = []
    for key, url in tags.items():
        if not url:
            continue
        if key.startswith("OWASP_2025_"):
            links.append({
                "nhan": f"OWASP Top 10 2025 - {key.replace('OWASP_2025_', '')}",
                "url": url
            })
        elif key.startswith("CWE-"):
            links.append({
                "nhan": f"CWE-{key[4:]} - MITRE",
                "url": url
            })
        elif key.startswith("WSTG-"):
            links.append({
                "nhan": key,
                "url": url
            })
    if cweid and cweid != "0":
        links.append({
            "nhan": f"Tra CVE theo CWE-{cweid} - NVD NIST",
            "url":  f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=CWE-{cweid}"
        })
    return links


# ── HÀM CHÍNH ─────────────────────────────────────────────────────────────────
def xu_ly_canh_bao(canh_bao_list: list) -> list:
    ket_qua = []
    da_them = set()

    for cb in canh_bao_list:
        ten    = cb.get("name", cb.get("alert", "Không rõ"))
        url    = cb.get("url", "")
        # Dedup theo tên + url — mỗi endpoint là một phát hiện riêng
        khoa   = f"{ten}|{url}"
        if khoa in da_them:
            continue
        da_them.add(khoa)

        muc_do = cb.get("risk", "Informational")
        cweid  = str(cb.get("cweid", ""))
        tags   = cb.get("tags", {})

        owasp_id  = lay_owasp_tu_tags(tags) or CWE_SANG_OWASP.get(cweid, "A02")
        owasp_ten = OWASP_TOP10.get(owasp_id, "Security Misconfiguration")

        wstg_list = lay_wstg_tu_tags(tags)
        links     = lay_links_tu_tags(tags, cweid)

        ket_qua.append({
            "ten":         ten,
            "mo_ta":       cb.get("description", ""),
            "giai_phap":   cb.get("solution", ""),
            "url":         url,
            "param":       cb.get("param", ""),
            "evidence":    cb.get("evidence", ""),
            "muc_do":      muc_do,
            "muc_do_viet": MUC_DO_VIET.get(muc_do, muc_do),
            "mau":         MUC_DO_MAU.get(muc_do, "blue"),
            "thu_tu":      MUC_DO_THU_TU.get(muc_do, 0),
            "owasp_id":    owasp_id,
            "owasp_ten":   owasp_ten,
            "cweid":       cweid,
            "wstg_list":   wstg_list,
            "links":       links,
            "confidence":  cb.get("confidence", ""),
        })

    ket_qua.sort(key=lambda x: x["thu_tu"], reverse=True)
    return ket_qua