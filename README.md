# Website Security Scanner

Cong cu kiem thu bao mat ung dung web tu dong, xay dung tren nen OWASP ZAP.

## Tinh nang
- Giao dien web don gian, khong can cai dat them
- Quet co xac thuc (gray-box) - phat hien lo hong sau man hinh dang nhap
- Phan loai lo hong tu dong theo OWASP Top 10 2025
- Hien thi ket qua hai tang: tong quan va chi tiet ky thuat
- Kem CWE ID, WSTG test case, link tra cuu NVD NIST va MITRE CWE
- Hien thi do tin cay (Confidence) cua tung canh bao

## Cong nghe su dung
- OWASP ZAP v2.17.0 - Engine quet DAST
- Python 3.10 + Flask - Backend va giao dien web
- Docker - Moi truong chay ZAP
- OWASP Top 10 2025 - Chuan phan loai rui ro
- OWASP WSTG v4.2 - Tai lieu kiem tra ky thuat
- NVD NIST / MITRE CWE - Nguon tra cuu lo hong

## Cach chay
1. Khoi dong ZAP: docker start zap
2. Cai thu vien: pip install -r requirements.txt
3. Chay ung dung: python app.py
4. Truy cap: http://localhost:5000

## Ket qua thuc nghiem tren DVWA
- 1 lo hong Cao: SQL Injection (CWE-89, OWASP A05)
- 64 lo hong Trung binh: CSP thieu, Clickjacking, CSRF, Directory Browsing
- 89 lo hong Thap: Server version leak, X-Content-Type-Options
- 33 muc Thong tin: Potential XSS, Debug comments

## Cau truc project
- app.py: Flask backend, dieu phoi ZAP
- config.py: Cau hinh ZAP, timeout
- scanner/analyzer.py: Xu ly ket qua, map OWASP/CWE/WSTG
- templates/: Giao dien web
