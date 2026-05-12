# Sub Elite API

Sub Elite API is the Cloudflare Worker backend for the Sub Elite frontend. It handles conversion requests, creates subscription records, and serves generated Mihomo YAML from Cloudflare KV.

Frontend repository:

```text
https://github.com/flash-charge/sub-elite
```

Backend repository:

```text
https://github.com/flash-charge/sub-elite-api
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

Production Worker URL:

```text
https://sub-elite-api.arbalest.workers.dev
```

## Required Cloudflare Settings

Create a KV namespace and bind it to the Worker:

```text
Binding name: SUBSCRIPTIONS
```

Set this Worker secret:

```text
SUB_ELITE_PROXY_SECRET=<same-random-secret-as-pages>
```

Set the same value in the `sub-elite` Pages project:

```text
SUB_ELITE_PROXY_SECRET=<same-random-secret-as-worker>
```

When this secret is configured, `POST /api/convert` and `POST /api/subscriptions` require the Pages proxy header. Direct browser POST requests to the Worker are rejected unless they include the secret header.

## Deploy Order

Deploy this backend first, then deploy the `sub-elite` frontend.

1. Create or confirm the `SUBSCRIPTIONS` KV namespace.
2. Deploy this Worker.
3. Set `SUB_ELITE_PROXY_SECRET` in this Worker.
4. Confirm `/healthz` is healthy.
5. Set `SUB_ELITE_BACKEND_ORIGIN` in Pages to this Worker URL.
6. Set the same `SUB_ELITE_PROXY_SECRET` in Pages.
7. Redeploy Pages.

## Deploy via Cloudflare Worker Upload

Use this when deploying manually from the Cloudflare Dashboard.

Build/check locally first:

```sh
npm install
npm run check
```

Dashboard path:

```text
Cloudflare Dashboard > Workers & Pages > Workers > Create Worker
```

Upload or paste the Worker entry file from:

```text
worker/index.js
```

This Worker imports:

```text
worker/http.js
lib/converter.ts
```

For reliability, Wrangler or GitHub deployment is preferred because it uploads the module graph consistently.

After upload, configure:

```text
Settings > Bindings > KV namespace bindings
Variable name: SUBSCRIPTIONS
KV namespace: <your namespace>

Settings > Variables and Secrets > Add secret
SUB_ELITE_PROXY_SECRET=<same-random-secret-as-pages>
```

## Deploy via Wrangler

Login and verify account:

```sh
npx wrangler login
npx wrangler whoami
```

Create a KV namespace if needed:

```sh
npx wrangler kv namespace create SUBSCRIPTIONS
```

Copy the namespace ID into `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "SUBSCRIPTIONS"
id = "<your-kv-id>"
```

Set or rotate the Worker secret:

```sh
printf '%s' '<same-random-secret-as-pages>' \
  | npx wrangler secret put SUB_ELITE_PROXY_SECRET
```

Check the Worker package without deploying:

```sh
npm install
npm run check
```

Deploy:

```sh
npm run worker:deploy
```

Check deployments:

```sh
npx wrangler deployments list
```

## Deploy via Connect GitHub

In Cloudflare Dashboard:

```text
Workers & Pages > Workers > Create application > Connect to Git
```

Select:

```text
Repository: flash-charge/sub-elite-api
Production branch: master
Build command: npm ci
Deploy command: npx wrangler deploy
Root directory: /
```

After the first deployment, configure:

```text
Settings > Bindings > KV namespace bindings
Variable name: SUBSCRIPTIONS
KV namespace: <your namespace>

Settings > Variables and Secrets > Secrets
SUB_ELITE_PROXY_SECRET=<same-random-secret-as-pages>
```

Then redeploy the Worker.

## Verify Production

```sh
curl https://sub-elite-api.arbalest.workers.dev/healthz
```

Expected:

```json
{"ok":true}
```

Direct POST without the proxy secret should be rejected:

```sh
curl -X POST https://sub-elite-api.arbalest.workers.dev/api/convert \
  -H 'content-type: application/json' \
  --data '{"input":"trojan://secret@example.com:443#Test"}'
```

Expected:

```json
{"error":"Request is not allowed."}
```

Through the frontend Pages proxy, the same request should succeed:

```sh
curl -X POST https://sub-elite-d3e.pages.dev/api/convert \
  -H 'content-type: application/json' \
  --data '{"input":"trojan://secret@example.com:443#Test"}'
```

## Endpoint Details

`GET /healthz`

Returns:

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

```sh
npm install
npm run lint
npm run typecheck
npm test
npm run worker:check
```

Or run the full check:

```sh
npm run check
```
