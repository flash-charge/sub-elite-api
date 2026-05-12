# Sub Elite API

Sub Elite API is the Cloudflare Worker backend for the Sub Elite frontend. It handles conversion requests, creates subscription records, and serves generated Mihomo YAML from Cloudflare KV.

Frontend repository:

```text
https://github.com/superencrypt-dev/sub-elite
```

Backend repository:

```text
https://github.com/superencrypt-dev/sub-elite-api
```

## Endpoints

```text
GET  /healthz
POST /api/convert
POST /api/subscriptions
GET  /sub/<secret>/config.yaml
```

## Worker Config

`wrangler.toml`:

```toml
name = "sub-elite-api"
main = "worker/index.js"
compatibility_date = "2026-05-10"
workers_dev = true
preview_urls = false

[[kv_namespaces]]
binding = "SUBSCRIPTIONS"
id = "65fd37b0b58e46e89b4caaf06425199a"
```

KV namespace:

```text
sub-elite
```

Recommended Worker secret:

```text
SUB_ELITE_PROXY_SECRET=<same-random-secret-as-pages>
```

Set the same value in the `sub-elite` Pages project. When this secret is configured, `POST /api/convert` and `POST /api/subscriptions` require the Pages proxy header and direct Worker POST requests are rejected.

## Deployment Guide

### 1. Cloudflare KV Setup
Create a KV namespace in your Cloudflare dashboard named `sub-elite` (or any name) and copy the ID. Update `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "SUBSCRIPTIONS"
id = "<your-kv-id>"
```

### 2. Environment Variables
Set these in the Cloudflare Worker dashboard (**Settings > Variables**):

- `SUB_ELITE_PROXY_SECRET`: A random string (must match the frontend).

### 3. Deploy via Git
Connect this repository to Cloudflare Workers:
- **Build command:** `npm ci`
- **Deploy command:** `npx wrangler deploy`

## Local Checks

`GET /healthz`

Returns a JSON health check:

```json
{
  "ok": true
}
```

`POST /api/convert`

Converts pasted proxy links or Mihomo YAML into the app config model and YAML output.

Request body:

```json
{
  "input": "vmess://...",
  "template": "simple",
  "rulesPreset": "default",
  "namePattern": "{name}",
  "namePrefix": ""
}
```

`POST /api/subscriptions`

Stores YAML in KV and returns a secret subscription URL.

Request body:

```json
{
  "yaml": "proxies:\n  - name: example\n",
  "expiresIn": "30d"
}
```

Supported `expiresIn` values:

```text
7d
30d
never
```

Response includes:

```json
{
  "ok": true,
  "url": "https://sub-elite-api.<account>.workers.dev/sub/<secret>/config.yaml",
  "expiresIn": "30d"
}
```

`GET /sub/<secret>/config.yaml`

Returns the stored YAML as:

```text
content-type: text/yaml; charset=utf-8
cache-control: no-store
```

Subscription URLs are secret URLs. Anyone with the URL can read the generated config.

## Exposure Controls

- CORS is universal and reflects the request `Origin`, or `*` when no `Origin` header is present.
- If `SUB_ELITE_PROXY_SECRET` is configured, POST endpoints require the Pages Function proxy secret header.
- `POST /api/subscriptions` has a lightweight per-IP KV rate limit.
- The create-subscription response returns only the full `url`, not the raw secret as a separate field.
- JSON and YAML responses include security headers such as CSP, HSTS, `X-Frame-Options`, and `X-Content-Type-Options`.

## Local Checks

Install dependencies:

```sh
npm install
```

Run tests:

```sh
npm test
```

Run lint:

```sh
npm run lint
```

Check Worker deploy package without deploying:

```sh
npm run worker:check
```

Deploy manually only when needed:

```sh
npm run worker:deploy
```

The preferred production flow is Cloudflare Workers Git auto deploy from this repository.
