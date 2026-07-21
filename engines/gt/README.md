# Geetest v4 runner (CSM)

Free pure-HTTP Geetest v4 solver. **No browser.**

Vendored protocol client from [xKiian/GeekedTest](https://github.com/xKiian/GeekedTest)
(MIT — see `LICENSE.GeekedTest`).

## Supported risk types

| risk_type | method |
|---|---|
| `slide` | Canny + matchTemplate gap (cv2) |
| `icon` | ddddocr det + custom ONNX charset |
| `gobang` / `winlinze` | pure logic 4-in-line |
| `ai` / `invisible` | PoW + empty userresponse |

## API

```bash
curl -sS -X POST http://127.0.0.1:8877/solve \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "geetest",
    "captcha_id": "54088bb07d2df3c46b79f80300b0abbe",
    "risk_type": "slide",
    "proxy": "http://user:pass@host:port"
  }'
```

`sitekey` is accepted as alias of `captcha_id`. No `url` required.

Response (success):

```json
{
  "type": "geetest",
  "solved": true,
  "token": "<pass_token>",
  "method": "geetest_v4",
  "lot_number": "...",
  "pass_token": "...",
  "captcha_output": "...",
  "gen_time": "...",
  "seccode": { "...": "full seccode dict" }
}
```

## How to find captcha_id + risk_type

1. DevTools → Network → filter `verify` / `load`
2. Look for `gcaptcha4.geevisit.com` or `geetest.com` query params
3. Copy `captcha_id` and `risk_type`

Demo: https://gt4.geetest.com/demov4/index-en.html

## Deps

- `curl_cffi`, `pycryptodome`, `opencv-python-headless`, `numpy`, `ddddocr`
- Bundled: `gtproto/models/geetest_v4_icon.onnx` + `charsets.json`

## Maintenance note

If Geetest rotates JS constants (`sign.py` mapping / `abo`), re-run upstream
`deobfuscate.py` against their client and patch `gtproto/sign.py`.
