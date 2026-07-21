# CSM Task API (captcha-solver-max)

Free-first multi-vendor captcha solver. Merges the best of open-source engines
into one service that **solves as much as possible without paying**, and only
falls back to paid APIs (2captcha / YesCaptcha) when free paths fail **and** you
have configured keys.

License: **MIT**. No GPL code is embedded (GPL tools stay sidecar/clean-room only).

## What it solves (free path)

| Type | Method | Cost | Notes |
|---|---|---|---|
| `cloudflare` | CloakBrowser harvests `cf_clearance` | **$0** | Needs residential proxy |
| `turnstile` | CloakBrowser headful + route intercept | **$0** | Real sites need clean residential IP |
| `recaptcha` v3 | CloakBrowser score harvest | **$0** | Via residential proxy |
| `recaptcha` v2 / invisible | CloakBrowser + optional vision LLM | **$0** | Image grids need free vision key (Qwen) |
| `hcaptcha` | CloakBrowser + optional vision LLM | **$0** | Image grids need free vision key |
| `image_text` | ddddocr → ppllocr → Tesseract | **$0** | Multi-engine + casing/double-letter repair |
| `math` | OCR cascade + eval | **$0** | `"7+5"` → `"12"` |
| `slider` | ddddocr → YOLO ONNX → Canny cascade | **$0** | Gap / puzzle piece offset |
| `geetest` | pure-HTTP Geetest v4 (GeekedTest MIT) | **$0** | slide / icon / gobang / ai — no browser |
| `awswaf` / `botguard` / `datadome` / `perimeterx` / `akamai` / `aliyun` | CloakBrowser harvest | **$0** | Browser harvest path |

Paid safety net (optional): set `TWOCAPTCHA_API_KEY` / `YESCAPTCHA_API_KEY` — only
fires when free browser path fails for turnstile / recaptcha / hcaptcha.

### Optional: GPL hCaptcha sidecar (process boundary)

Hard image grids (count / drag) may need [hcaptcha-challenger](https://github.com/QIN2DIM/hcaptcha-challenger)
(**GPL-3.0**). We **do not merge** its source into this MIT tree. Run it as a
separate process and talk HTTP only:

| Process | Port | License |
|---|---|---|
| captcha-solver-max (this repo) | `:8877` | MIT |
| hcaptcha-sidecar (`~/captcha-build/hcaptcha-sidecar`) | `:8878` | GPL-3.0 |

```bash
# on VPS — outside this repo
cd ~/captcha-build/hcaptcha-sidecar
# put real GEMINI_API_KEY in .env (https://aistudio.google.com/apikey)
./install.sh && sudo systemctl enable --now hcaptcha-sidecar

# enable fallback from MIT solver
echo 'HCAPTCHA_SIDECAR_FALLBACK=1' >> ~/captcha-build/captcha-solver/.env
echo 'HCAPTCHA_SIDECAR_URL=http://127.0.0.1:8878' >> ~/captcha-build/captcha-solver/.env
sudo systemctl restart captcha-solver-max
```

`/v1/health` on `:8877` reports `hcaptcha_sidecar.{enabled,status,gemini_key}`.

## Proven on this build

```
cf_clearance  nowsecure.nl   ~12s    $0   via US residential OwlProxy
reCAPTCHA v3  real token     ~8s     $0   via residential proxy
Turnstile     CF test keys   ~3-8s   $0   forced-interactive + always-pass
image_text    multi-engine   ~ms     $0   ddddocr → ppllocr → tesseract
math          4/4 samples    ~ms     $0   7+5 / 9-3 / 4x6 / 8+9
slider        cascade        ~ms     $0   ddddocr → yolo → canny
geetest v4    pure HTTP      ~1-3s   $0   slide/icon/gobang (GeekedTest MIT)
```

## Architecture

Self-hosted multi-engine solver. Browser challenges run through **CloakBrowser**
(anti-detect Chromium) with sticky residential proxy support. Image/OCR challenges
use a free local cascade; Geetest v4 has a pure-HTTP path.

| Component | Role | License |
|---|---|---|
| CloakBrowser driver | Turnstile / CF clearance / reCAPTCHA / hCaptcha / WAF harvest | — |
| Free OCR cascade | ddddocr → ppllocr → Tesseract (+ optional vision LLM) | MIT / Apache |
| Slider cascade | ddddocr → YOLO ONNX → Canny | MIT |
| Geetest v4 | pure-HTTP protocol (`type=geetest`) via GeekedTest-class MIT code | MIT |
| Paid fallback (optional) | CapSolver / 2captcha / YesCaptcha when free path fails | SaaS |
| hCaptcha sidecar (optional) | separate GPL process on `:8878` — HTTP only, not merged | GPL-3.0 |

No Camoufox / Playwright / Patchright dependency. Secrets stay in local `.env` (gitignored).

## Quick start (VPS kerja)

```bash
cd ~/captcha-build/captcha-solver
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
sudo apt-get install -y tesseract-ocr xvfb

chmod +x start.sh
SOLVER_PROXY_FILE=~/cf-factory/proxies.txt ./start.sh

# or systemd:
sudo cp captcha-solver-max.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now captcha-solver-max
```

Health: `curl http://127.0.0.1:8877/health`  
Docs:   `http://127.0.0.1:8877/docs` (Swagger)

## API — native

```bash
# Cloudflare clearance
curl -X POST http://127.0.0.1:8877/solve \
  -H 'Content-Type: application/json' \
  -d '{"type":"cloudflare","url":"https://nowsecure.nl"}'

# Image text OCR
curl -X POST http://127.0.0.1:8877/solve \
  -H 'Content-Type: application/json' \
  -d '{"type":"image_text","image":"<base64 png>"}'

# Slider / gap match
curl -X POST http://127.0.0.1:8877/solve \
  -H 'Content-Type: application/json' \
  -d '{"type":"slider","target_image":"<piece b64>","background_image":"<bg b64>"}'
```

Uniform response: always read top-level `solved` bool.

## API — YesCaptcha / CapSolver compatible

Drop-in for clients that already speak `createTask` / `getTaskResult`:

```bash
# create
curl -X POST http://127.0.0.1:8877/createTask \
  -H 'Content-Type: application/json' \
  -d '{"clientKey":"any","task":{"type":"ImageToTextTask","body":"<base64>"}}'
# → {"errorId":0,"taskId":"..."}

# poll
curl -X POST http://127.0.0.1:8877/getTaskResult \
  -H 'Content-Type: application/json' \
  -d '{"clientKey":"any","taskId":"..."}'
# → {"errorId":0,"status":"ready","solution":{"text":"..."}}

# balance (symbolic free service)
curl -X POST http://127.0.0.1:8877/getBalance \
  -H 'Content-Type: application/json' \
  -d '{"clientKey":"any"}'
```

Mapped task types: `TurnstileTask(Proxyless)`, `RecaptchaV2/V3*`, `HCaptcha*`,
`ImageToTextTask`, `MathCaptchaTask`, `SliderTask` / `GapMatchTask`.

Optional: set `SOLVER_CLIENT_KEY` to require a matching `clientKey`.

## Vision LLM (free hCaptcha / reCAPTCHA-v2 image grids)

Easiest free path — Qwen Cloud (70M+ free tokens per new account):

```bash
export DASHSCOPE_API_KEY=sk-...
# endpoint + model auto-flip to dashscope-intl + qwen-vl-plus
# or pin manually:
# export VISION_ENDPOINT=https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions
# export VISION_MODEL=qwen-vl-plus
```

Keys also accepted via `VISION_API_KEY` / `MISTRAL_API_KEY` or `csm/apikey.txt`
(one key per line). Restart the service after setting keys.

## Env knobs

| Env | Default | Purpose |
|---|---|---|
| `SOLVER_PROXY_ROTATE` | `1` | Round-robin from proxy file |
| `SOLVER_PROXY_FILE` | `~/cf-factory/proxies.txt` | OwlProxy dump |
| `TURNSTILE_HEADLESS` | `0` | Headful for interactive Turnstile |
| `CLOUDFLARE_PROXY` | auto first pool line | Sticky proxy for IP-bound cookies |
| `DASHSCOPE_API_KEY` | empty | Free Qwen VL for image grids |
| `VISION_ENDPOINT` / `VISION_MODEL` | auto | Override vision backend |
| `TWOCAPTCHA_API_KEY` | empty | Paid tier-2 |
| `YESCAPTCHA_API_KEY` | empty | Paid tier-3 |
| `SOLVER_CLIENT_KEY` | empty | Gate YesCaptcha-compat endpoints |

## Why free needs residential proxy

Tencent / AWS / GCP datacenter IPs are hard-blocked by Cloudflare on real sites.
Engine is solid (CF test sitekeys pass without proxy). Point `SOLVER_PROXY_FILE`
at a residential pool and real-site solves work.

## Attribution

Upstream solvers retained their original licenses in their module trees.
This packaging layer + `csm/yescaptcha_api.py` + OCR cascade are original MIT.
