# Sticky proxy for IP-bound cookies

## Why

`cf_clearance` (and some WAF session cookies) are bound to:

1. Exit **IP**
2. **User-Agent**
3. TLS fingerprint (JA3 / JA4)

If you solve on proxy A then replay from proxy B, the cookie is rejected even when the value is correct.

## How captcha-solver-max pins

| Layer | Behavior |
|---|---|
| `ProxyPool.sticky(session_key)` | First call for a key pins a pool proxy; later calls reuse it |
| `browser_kwargs(..., sticky_key=)` | Prefer sticky pin over round-robin |
| `cloudflare.run_cf_clearance` | Sticky key = URL **host** (`nowsecure.nl`) |
| Response field `proxy` | Full proxy URL used for the solve — client must reuse it |
| Response field `sticky_key` | Host key that was pinned |
| Response field `user_agent` | Exact UA — must match on replay |

Round-robin still applies for Turnstile / reCAPTCHA / hCaptcha widget solves (different risk model — rotate IPs).

## Env

```bash
export SOLVER_PROXY_ROTATE=1
export SOLVER_PROXY_FILE=$HOME/cf-factory/proxies.txt   # host:port:user:pass
# optional force one sticky line for all CF:
# export CLOUDFLARE_PROXY=http://user:pass@host:port
```

OwlProxy sticky sessions often encode `sid_…_time_90` in the **username** — those lines already pin the residential IP for ~90s at the provider. Our process-level sticky map keeps the **same line** across re-solves for the same host even after that window if the line is still in the file.

## Client replay checklist

```text
1. Call POST /solve type=cloudflare url=https://target.example
2. Read response.proxy, response.user_agent, response.cf_clearance / cookies
3. HTTP client must:
   - use the SAME proxy URL
   - set User-Agent exactly
   - send Cookie: cf_clearance=...
4. Prefer a TLS stack close to Chrome (curl-impersonate / real browser)
```

## Ops notes

- `/health` → `proxy.count` / `proxy.sticky_sessions` (no secrets).
- `ProxyPool.release_sticky(key)` exists for forced rotate after hard fail (not auto-wired yet).
- `start.sh` still sets `CLOUDFLARE_PROXY` from the **first** pool line as a boot-time default for page-level CF when nothing else is set.
