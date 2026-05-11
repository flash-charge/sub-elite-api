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
id = "804df1bbafd644ad83b42f91161a547e"
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

## Deploy With Cloudflare Workers Git

Use these settings in Cloudflare Workers Git deploy:

```text
Build command: npm ci
Deploy command: npx wrangler deploy
```

Expected Worker URL:

```text
https://sub-elite-api.<account>.workers.dev
```

After deployment, the frontend normally reaches this Worker through same-origin Pages Functions. If the Worker URL changes, set this value in the frontend Cloudflare Pages project:

```text
SUB_ELITE_BACKEND_ORIGIN=https://sub-elite-api.<account>.workers.dev
```

Then redeploy the frontend Pages project.

## API Behavior

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

- CORS is restricted to `sub-elite.pages.dev`, preview hosts ending in `.sub-elite.pages.dev`, and local development hosts.
- `POST /api/convert` and `POST /api/subscriptions` reject requests from other origins.
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
