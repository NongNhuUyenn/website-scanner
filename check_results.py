import requests
from collections import Counter

r = requests.get('http://localhost:8080/JSON/core/view/alerts/', params={'start': 0, 'count': 500})
alerts = r.json().get('alerts', [])

muc = Counter(a.get('risk') for a in alerts)
print(f'Tổng: {len(alerts)}')
for k, v in sorted(muc.items(), key=lambda x: {'High':4,'Medium':3,'Low':2,'Informational':1}.get(x[0],0), reverse=True):
    print(f'  {k}: {v}')

print('\nLỗ hổng High:')
for a in alerts:
    if a.get('risk') == 'High':
        print(f'  {a.get("alert")} — {a.get("url")}')