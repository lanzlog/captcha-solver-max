# FunCaptcha / Arkose Labs — MIT status (Jul 2026)

## Verdict for captcha-solver-max

**Not implemented as a free CloakBrowser engine.** Remaining free OSS is weak or audio-only; solid free visual solvers are rare under MIT without paid backends.

## Screened repos (stars / license)

| Repo | ★ | License | Notes |
|---|---|---|---|
| NopeCHALLC/nopecha-python | 1.6k | MIT | **Paid API SDK** — not free-solve |
| 2captcha/2captcha-python | 776 | MIT | Paid wrapper (we already have paid_fallback) |
| useragents/Funcaptcha-Audio-Solver | 384 | ? | Audio path only — Arkose often disables audio |
| Pr0t0ns/Funcaptcha-Solver | 86 | MIT | Audio-based |
| xtekky/funcaptcha | 39 | MIT | Scraper WIP |
| BoarIncorporated/Funcaptcha-Solver-Bloxcaptcha | 33 | ? | Leaked / stale |

## Why we skip for now

1. **Engine rule** — stay CloakBrowser-only; no Patchright reintro.
2. **Free visual FunCaptcha** needs model training / reverse of Arkose blob — multi-day, not a drop-in MIT module.
3. **Audio** is rate-limited / disabled on many public keys.
4. **Paid path already exists** — set `TWOCAPTCHA_API_KEY` / `YESCAPTCHA_API_KEY` when FunCaptcha appears; facade can map later.

## If operator forces free FunCaptcha later

1. Prototype audio-only MIT module behind `type=funcaptcha` + feature flag.
2. Or clean-room vision on public demo keys only (no leaked blobs).
3. Do **not** merge GPL / leaked closed source.

## Related already in tree

- hCaptcha **drag** challenges — best-effort grid drag in `engines/hc/vision.py` (MIT).
- reCAPTCHA image grids — tile classify via DashScope pool.
- Slider / Aliyun gap — ddddocr + local ONNX.
