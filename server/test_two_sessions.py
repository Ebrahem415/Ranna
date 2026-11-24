#!/usr/bin/env python3
"""Two real browser sessions (two headless Chrome instances) against رنة live v2, with screenshots."""
import json, subprocess, time, urllib.request, base64, os
import websocket

CHROME = 'google-chrome-stable'
BASE = 'http://localhost:8765'

def launch(port, profile):
    os.system(f'rm -rf {profile}')
    p = subprocess.Popen([CHROME, '--headless=new', '--no-sandbox', '--disable-gpu',
                          f'--remote-debugging-port={port}', '--remote-allow-origins=*',
                          f'--user-data-dir={profile}', '--window-size=390,760',
                          'about:blank'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    return p

def first_tab(port):
    tabs = json.load(urllib.request.urlopen(f'http://localhost:{port}/json/list'))
    return [t for t in tabs if t['type'] == 'page'][0]

class Tab:
    def __init__(self, info):
        self.ws = websocket.create_connection(info['webSocketDebuggerUrl'], timeout=30)
        self.mid = 0
    def cmd(self, method, params=None):
        self.mid += 1
        self.ws.send(json.dumps({'id': self.mid, 'method': method, 'params': params or {}}))
        while True:
            m = json.loads(self.ws.recv())
            if m.get('id') == self.mid:
                return m.get('result', {})
    def ev(self, expr, await_promise=False):
        r = self.cmd('Runtime.evaluate', {'expression': expr, 'awaitPromise': await_promise, 'returnByValue': True})
        if 'exceptionDetails' in r:
            raise RuntimeError(str(r['exceptionDetails'])[:400])
        return r.get('result', {}).get('value')
    def goto(self, url):
        self.cmd('Page.navigate', {'url': url})
        time.sleep(1.5)
    def shot(self, path):
        v = self.ev("({'auth': !document.getElementById('authView').hidden, 'chat': !document.getElementById('chatView').hidden})")
        print('  capture state:', v)
        self.cmd('Emulation.setDeviceMetricsOverride', {'width': 390, 'height': 760, 'deviceScaleFactor': 1, 'mobile': True})
        time.sleep(1.2)
        r = self.cmd('Page.captureScreenshot', {'format': 'png', 'fromSurface': True})
        with open(path, 'wb') as f:
            f.write(base64.b64decode(r['data']))

p1, p2 = launch(9222, '/tmp/chrome-ranna-a'), launch(9223, '/tmp/chrome-ranna-b')
t1, t2 = Tab(first_tab(9222)), Tab(first_tab(9223))
t1.goto(BASE); t2.goto(BASE)

def register(tab, u, p, n):
    return tab.ev(f"""(async () => {{
      document.getElementById('u').value = '{u}';
      document.getElementById('p').value = '{p}';
      document.getElementById('regBtn').click();
      await new Promise(r => setTimeout(r, 100));
      document.getElementById('n').value = '{n}';
      document.getElementById('regBtn').click();
      await new Promise(r => setTimeout(r, 800));
      return {{ listVisible: !document.getElementById('listView').hidden }};
    }})()""", True)

r1 = register(t1, 'ebrahem', 'test-pass-1', 'إبراهيم')
r2 = register(t2, 'sara', 'test-pass-2', 'سارة')
print('registered:', r1, r2)
assert r1['listVisible'] and r2['listVisible']

empty = t1.ev("document.getElementById('convos').innerText")
print('tab1 list before lookup:', repr(empty[:80]))
assert 'سارة' not in empty and 'sara' not in empty, 'member list leaked'

t1.ev("""(async () => {
  document.getElementById('lookupQ').value = 'sara';
  document.getElementById('lookupBtn').click();
  await new Promise(r => setTimeout(r, 800));
})()""", True)
assert t1.ev("!document.getElementById('chatView').hidden"), 'lookup did not open chat'

t1.ev("""(async () => {
  document.getElementById('t').value = 'أول رسالة حقيقية بين حسابين 🔔';
  document.getElementById('sendBtn').click();
  await new Promise(r => setTimeout(r, 700));
})()""", True)

t2.ev("enterList()")
time.sleep(1.2)
t2.ev("""(() => {
  const row = document.querySelector('.row[data-u="ebrahem"]');
  if (row) row.click();
})()""")
time.sleep(1.5)
m2 = t2.ev("document.getElementById('msgs').innerText")
print('tab2 sees:', repr(m2[:120]))
assert 'أول رسالة حقيقية بين حسابين' in m2

t2.ev("""(async () => {
  document.getElementById('t').value = 'وصلت! المراسلة شغالة بين المتصفحين ✅';
  document.getElementById('sendBtn').click();
  await new Promise(r => setTimeout(r, 700));
})()""", True)
time.sleep(3)
m1 = t1.ev("document.getElementById('msgs').innerText")
print('tab1 sees:', repr(m1[:200]))
assert 'وصلت! المراسلة شغالة بين المتصفحين' in m1
assert '✓✓' in m1

dark = t1.ev("(() => { document.getElementById('darkBtn').click(); return document.body.classList.contains('dark'); })()")
assert dark
print('dark mode toggles:', dark)
time.sleep(0.5)

# real presence: both browsers polling, so tab1 must show sara online
who_online = t1.ev("document.getElementById('whois').textContent")
print('tab1 presence while sara active:', who_online)
assert who_online == 'متصل الآن', who_online

t1.shot('/downloads/ranna-live-chat-tab1.png')
t2.shot('/downloads/ranna-live-chat-tab2.png')
print('screenshots saved')

# presence goes stale when the other browser closes
p2.terminate()
time.sleep(12)
who_offline = t1.ev("document.getElementById('whois').textContent")
print('tab1 presence after sara closed:', who_offline)
assert who_offline == 'غير متصل الآن', who_offline

print('ALL UI TESTS PASSED')
p1.terminate()
