import requests
from collections import Counter

r = requests.get('http://localhost:8080/JSON/core/view/alerts/', params={'start':0,'count':2000})
alerts = r.json().get('alerts', [])

ten = Counter(a['alert'] for a in alerts)
print('=== LOAI LO HONG ===')
for name, count in ten.most_common():
    a = next(x for x in alerts if x['alert']==name)
    risk = a['risk']
    conf = a['confidence']
    tags = a.get('tags', {}) or {}
    owasp = next((k.replace('OWASP_2025_','') for k in tags if 'OWASP_2025' in k), 'N/A')
    print(f'{count:3d}x [{risk}][Conf:{conf}] {name} | OWASP {owasp}')

print(f'=== TONG: {len(alerts)} alert, {len(ten)} loai ===')