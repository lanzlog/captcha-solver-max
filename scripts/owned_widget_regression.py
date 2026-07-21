#!/usr/bin/env python3
"""Owned Turnstile widget regression. Writes redacted metrics only."""
import json,time,urllib.request
from pathlib import Path
URL='http://127.0.0.1:8877/v1/task'
SECRET_PATH=Path.home()/'.config/hermes/turnstile/csm-portable-sim.secret'
OUT=Path('/home/ubuntu/captcha-build/captcha-solver/bench/owned-widget/latest.json')
raw=SECRET_PATH.read_text().strip()
# Accept raw secret or a multi-line key=value card. Never print values.
fields={}
for line in raw.splitlines():
    if '=' in line:
        k,v=line.split('=',1); fields[k.strip().lower()]=v.strip()
secret=fields.get('secret') or (raw if '\n' not in raw and '=' not in raw else '')
if not secret:
    raise RuntimeError('secret field missing')
body={
 'type':'turnstile','sitekey':'0x4AAAAAAD32v2KelCNWf0bC',
 'url':'https://ilalangliar.xyz','secret':secret,'mint_method':'explicit',
 'timeout_s':120
}
t=time.monotonic(); req=urllib.request.Request(URL,data=json.dumps(body).encode(),headers={'Content-Type':'application/json'},method='POST')
try:
 with urllib.request.urlopen(req,timeout=140) as r: x=json.loads(r.read())
 err=None
except Exception as e:
 x={};err=f'{type(e).__name__}: {e}'
sv=x.get('siteverify') or {}; tok=x.get('token') or ''
out={
 'ts':time.time(),'elapsed_s':round(time.monotonic()-t,2),'http_error':err,
 'solved':bool(x.get('solved')),'token_len':len(tok),'method':x.get('method'),
 'usage':x.get('usage'),'portable':x.get('portable'),
 'siteverify_success':sv.get('success'),'hostname':sv.get('hostname'),
 'error_codes':sv.get('error-codes') or [],
 'secret_path':str(SECRET_PATH),
}
OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_text(json.dumps(out,indent=2));print(json.dumps(out,indent=2))
