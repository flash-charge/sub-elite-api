import { convertToClashMeta } from '../lib/converter.ts'
import {
  byteLength,
  clientIp,
  hasHttpUrl,
  isAllowedOrigin,
  isTrustedApiRequest,
  json,
  MAX_INPUT_BYTES,
  MAX_SUBSCRIPTION_BYTES,
  options,
  randomSecret,
  readConvertOptions,
  SUBSCRIPTION_EXPIRY,
  SUBSCRIPTION_RATE_LIMIT,
  subscriptionHeaders,
} from './http.js'

export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    const pathname = url.pathname

    try {
      if (request.method === 'OPTIONS') return handleOptions(pathname, request, env)
      if (pathname === '/healthz' && request.method === 'GET') return json({ ok: true }, 200, 'GET,OPTIONS', request, env)
      if (pathname === '/api/convert' && request.method === 'POST') return handleConvert(request, env)
      if (pathname === '/api/subscriptions' && request.method === 'POST') return handleCreateSubscription(request, env)
      if (/^\/sub\/[A-Za-z0-9_-]+\/config\.yaml$/u.test(pathname) && request.method === 'GET') {
        return handleSubscription(pathname, env, request)
      }

      return json({ error: 'Not found' }, 404, 'GET,POST,OPTIONS', request, env)
    } catch (error) {
      return json({ error: error.message || 'Server error' }, error.statusCode || 500, 'GET,POST,OPTIONS', request, env)
    }
  },
}

function handleOptions(pathname, request, env) {
  if (pathname === '/healthz') return options('GET,OPTIONS', request, env)
  if (pathname === '/api/convert' || pathname === '/api/subscriptions') return options('POST,OPTIONS', request, env)
  if (/^\/sub\/[A-Za-z0-9_-]+\/config\.yaml$/u.test(pathname)) {
    return new Response(null, { status: isAllowedOrigin(request, env) ? 204 : 403, headers: subscriptionHeaders(request, env) })
  }
  return options('GET,POST,OPTIONS', request, env)
}

async function handleConvert(request, env) {
  if (!isTrustedApiRequest(request, env)) return json({ error: 'Request is not allowed.' }, 403, 'POST,OPTIONS', request, env)

  const contentLength = Number(request.headers.get('content-length') || 0)
  if (contentLength > MAX_INPUT_BYTES) return json({ error: 'Input is too large.' }, 413, 'POST,OPTIONS', request, env)

  const payload = await request.json().catch(() => null)
  if (!payload) return json({ error: 'Body must be valid JSON.' }, 400, 'POST,OPTIONS', request, env)

  const input = String(payload.input || '').trim()
  if (!input) return json({ error: 'Input cannot be empty.' }, 400, 'POST,OPTIONS', request, env)
  if (byteLength(input) > MAX_INPUT_BYTES) return json({ error: 'Input is too large.' }, 413, 'POST,OPTIONS', request, env)
  if (hasHttpUrl(input)) {
    return json({ error: 'Paste config links directly, not http/https subscription URLs.' }, 400, 'POST,OPTIONS', request, env)
  }

  return json(convertToClashMeta(input, readConvertOptions(payload)), 200, 'POST,OPTIONS', request, env)
}

async function handleCreateSubscription(request, env) {
  if (!isTrustedApiRequest(request, env)) return json({ error: 'Request is not allowed.' }, 403, 'POST,OPTIONS', request, env)
  if (!env.SUBSCRIPTIONS) return json({ error: 'KV binding SUBSCRIPTIONS is not available.' }, 500, 'POST,OPTIONS', request, env)

  const contentType = request.headers.get('content-type') || ''
  if (!contentType.toLowerCase().includes('application/json')) {
    return json({ error: 'Content-Type must be application/json.' }, 415, 'POST,OPTIONS', request, env)
  }

  const contentLength = Number(request.headers.get('content-length') || 0)
  if (contentLength > MAX_SUBSCRIPTION_BYTES + 4096) {
    return json({ error: 'YAML is too large. Maximum size is 256 KB.' }, 413, 'POST,OPTIONS', request, env)
  }

  const rateLimitResponse = await checkSubscriptionRateLimit(request, env)
  if (rateLimitResponse) return rateLimitResponse

  const payload = await request.json().catch(() => null)
  if (!payload) return json({ error: 'Body must be valid JSON.' }, 400, 'POST,OPTIONS', request, env)

  const yaml = String(payload.yaml || '').trim()
  if (!yaml) return json({ error: 'YAML cannot be empty.' }, 400, 'POST,OPTIONS', request, env)
  if (byteLength(yaml) > MAX_SUBSCRIPTION_BYTES) {
    return json({ error: 'YAML is too large. Maximum size is 256 KB.' }, 413, 'POST,OPTIONS', request, env)
  }

  const expiresIn = Object.hasOwn(SUBSCRIPTION_EXPIRY, payload.expiresIn) ? payload.expiresIn : '30d'
  const secret = randomSecret(32)
  const record = JSON.stringify({
    yaml,
    createdAt: new Date().toISOString(),
    expiresIn,
  })
  const ttl = SUBSCRIPTION_EXPIRY[expiresIn]
  const writeOptions = ttl ? { expirationTtl: ttl } : undefined
  await env.SUBSCRIPTIONS.put(`sub:${secret}`, record, writeOptions)

  return json({
    ok: true,
    url: new URL(`/sub/${secret}/config.yaml`, request.url).toString(),
    expiresIn,
  }, 200, 'POST,OPTIONS', request, env)
}

async function checkSubscriptionRateLimit(request, env) {
  const now = Date.now()
  const bucket = Math.floor(now / (SUBSCRIPTION_RATE_LIMIT.windowSeconds * 1000))
  const ip = clientIp(request)
  const key = `rate:subscriptions:${bucket}:${ip}`
  const prevKey = `rate:subscriptions:${bucket - 1}:${ip}`
  const [current, prev] = await Promise.all([
    env.SUBSCRIPTIONS.get(key).then((v) => Number(v || 0)),
    env.SUBSCRIPTIONS.get(prevKey).then((v) => Number(v || 0)),
  ])
  const elapsed = (now % (SUBSCRIPTION_RATE_LIMIT.windowSeconds * 1000)) / (SUBSCRIPTION_RATE_LIMIT.windowSeconds * 1000)
  const weighted = Math.floor(prev * (1 - elapsed)) + current
  if (weighted >= SUBSCRIPTION_RATE_LIMIT.max) {
    return json({ error: 'Too many subscription requests. Try again later.' }, 429, 'POST,OPTIONS', request, env)
  }
  await env.SUBSCRIPTIONS.put(key, String(current + 1), {
    expirationTtl: SUBSCRIPTION_RATE_LIMIT.windowSeconds * 2,
  })
  return null
}

async function handleSubscription(pathname, env, request) {
  if (!env.SUBSCRIPTIONS) {
    return new Response('KV binding SUBSCRIPTIONS is not available.', {
      status: 500,
      headers: subscriptionHeaders(request, env),
    })
  }

  const secret = pathname.split('/')[2]
  const record = await env.SUBSCRIPTIONS.get(`sub:${secret}`)
  if (!record) {
    return new Response('Subscription not found.', {
      status: 404,
      headers: subscriptionHeaders(request, env),
    })
  }

  let yaml = record
  try {
    const parsed = JSON.parse(record)
    if (parsed && typeof parsed.yaml === 'string') yaml = parsed.yaml
  } catch {
    yaml = record
  }

  return new Response(yaml.endsWith('\n') ? yaml : `${yaml}\n`, {
    status: 200,
    headers: subscriptionHeaders(request, env),
  })
}
