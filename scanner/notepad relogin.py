import requests
import re

session = requests.Session()
r = session.get('http://localhost/login.php', timeout=5)
token = re.search(r"user_token.*?value='([a-f0-9]+)'", r.text)
token = token.group(1) if token else ''
print('Token:', token)

session.post('http://localhost/login.php', data={
    'username': 'admin',
    'password': 'password',
    'Login': 'Login',
    'user_token': token
}, allow_redirects=True, timeout=5)
phpsessid = session.cookies.get('PHPSESSID')
print('PHPSESSID moi:', phpsessid)

# Xóa rule cũ
requests.get('http://localhost:8080/JSON/replacer/action/removeRule/',
             params={'description': 'dvwa_auth_cookie'})

# Inject cookie mới
requests.get('http://localhost:8080/JSON/replacer/action/addRule/', params={
    'description':  'dvwa_auth_cookie',
    'enabled':      'true',
    'matchType':    'REQ_HEADER',
    'matchRegex':   'false',
    'matchString':  'Cookie',
    'replacement':  f'PHPSESSID={phpsessid}; security=low',
    'initiators':   ''
})
print('Injected cookie moi vao ZAP')

# Verify
r2 = requests.get('http://localhost:8080/JSON/core/action/accessUrl/',
                  params={'url': 'http://172.18.0.3/vulnerabilities/sqli/?Submit=Submit&id=1',
                          'followRedirects': 'true'})
resp = r2.json().get('accessUrl', [{}])[0].get('responseHeader', '')[:80]
print('Response:', resp)