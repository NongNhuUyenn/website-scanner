import requests

ZAP = 'http://127.0.0.1:8080'
requests.get(f'{ZAP}/JSON/replacer/action/removeRule/', params={'description': 'auth_cookie'})
requests.get(f'{ZAP}/JSON/replacer/action/removeRule/', params={'description': 'dvwa_auth_cookie'})
print('Đã xóa. Rules còn lại:')
r = requests.get(f'{ZAP}/JSON/replacer/view/rules/')
for rule in r.json().get('rules', []):
    if rule.get('enabled') == 'true':
        print(' -', rule.get('description'))