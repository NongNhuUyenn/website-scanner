import requests
import re

# Đăng nhập lấy cookie mới
s = requests.Session()
r = s.get('http://localhost/login.php')
token = re.search(r"user_token.*?value='([a-f0-9]+)'", r.text)
token = token.group(1) if token else ''
s.post('http://localhost/login.php', data={
    'username': 'admin',
    'password': 'password',
    'Login': 'Login',
    'user_token': token
})
phpsessid = s.cookies.get('PHPSESSID')
print(f'PHPSESSID mới: {phpsessid}')

# Xóa rule cũ
rules = requests.get('http://localhost:8080/JSON/replacer/view/rules/').json().get('rules', [])
for rule in rules:
    if rule.get('description') == 'dvwa_auth_cookie':
        requests.get('http://localhost:8080/JSON/replacer/action/removeRule/',
                     params={'description': 'dvwa_auth_cookie'})
        print('Đã xóa rule cũ')

# Inject cookie mới
requests.get('http://localhost:8080/JSON/replacer/action/addRule/', params={
    'description': 'dvwa_auth_cookie',
    'enabled': 'true',
    'matchType': 'REQ_HEADER',
    'matchRegex': 'false',
    'matchString': 'Cookie',
    'replacement': f'PHPSESSID={phpsessid}; security=low',
    'initiators': ''
})
print('Đã inject cookie mới')

# Chạy Spider lại
r = requests.get('http://localhost:8080/JSON/spider/action/scan/', params={
    'url': 'http://172.18.0.3/',
    'maxChildren': 50,
    'recurse': 'true'
})
scan_id = r.json().get('scan')
print(f'Spider ID mới: {scan_id}')