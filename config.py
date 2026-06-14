ZAP_HOST = "127.0.0.1"
ZAP_PORT = 8080
ZAP_API_URL = f"http://{ZAP_HOST}:{ZAP_PORT}"

DVWA_URL = "http://172.18.0.3/dvwa"
DVWA_LOGIN_URL = "http://172.18.0.3/dvwa/login.php"

SCAN_TIMEOUT = 700

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