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
      if (pathname === '/api/subscriptions' && request.method === 'GET') return handleListSubscriptions(request, env)
      if (/^\/api\/subscriptions\/[A-Za-z0-9_-]+$/u.test(pathname) && request.method === 'DELETE') {
        return handleDeleteSubscription(pathname, request, env)
      }
      if (/^\/sub\/[A-Za-z0-9_-]+\/[A-Za-z0-9._-]+\.ya?ml$/u.test(pathname) && request.method === 'GET') {
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
  if (pathname === '/api/convert') return options('POST,OPTIONS', request, env)
  if (pathname === '/api/subscriptions') return options('GET,POST,OPTIONS', request, env)
  if (/^\/api\/subscriptions\/[A-Za-z0-9_-]+$/u.test(pathname)) return options('DELETE,OPTIONS', request, env)
  if (/^\/sub\/[A-Za-z0-9_-]+\/[A-Za-z0-9._-]+\.ya?ml$/u.test(pathname)) {
    return new Response(null, { status: isAllowedOrigin(request, env) ? 204 : 403, headers: subscriptionHeaders(request, env) })
  }
  return options('GET,POST,OPTIONS', request, env)
}

async function handleConvert(request, env) {
  if (!isTrustedApiRequest(request, env)) return json({ error: 'Request is not allowed.' }, 403, 'POST,OPTIONS', request, env)

  const body = await readLimitedBody(request, MAX_INPUT_BYTES)
  if (body === null) return json({ error: 'Input is too large.' }, 413, 'POST,OPTIONS', request, env)

  let payload
  try { payload = JSON.parse(body) } catch { payload = null }
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

  const rateLimitResponse = await checkSubscriptionRateLimit(request, env)
  if (rateLimitResponse) return rateLimitResponse

  const body = await readLimitedBody(request, MAX_SUBSCRIPTION_BYTES + 4096)
  if (body === null) return json({ error: 'YAML is too large. Maximum size is 256 KB.' }, 413, 'POST,OPTIONS', request, env)

  let payload
  try { payload = JSON.parse(body) } catch { payload = null }
  if (!payload) return json({ error: 'Body must be valid JSON.' }, 400, 'POST,OPTIONS', request, env)

  const yaml = String(payload.yaml || '').trim()
  if (!yaml) return json({ error: 'YAML cannot be empty.' }, 400, 'POST,OPTIONS', request, env)
  if (byteLength(yaml) > MAX_SUBSCRIPTION_BYTES) {
    return json({ error: 'YAML is too large. Maximum size is 256 KB.' }, 413, 'POST,OPTIONS', request, env)
  }

  const filename = normalizeSubscriptionFilename(payload.filename)
  const secret = randomSecret(32)
  const record = JSON.stringify({
    yaml,
    createdAt: new Date().toISOString(),
    ip: clientIp(request),
  })
  await env.SUBSCRIPTIONS.put(`sub:${secret}`, record)

  const ip = clientIp(request)
  const indexKey = `idx:${ip}`
  const existing = JSON.parse(await env.SUBSCRIPTIONS.get(indexKey) || '[]')
  existing.push({ secret, createdAt: new Date().toISOString() })
  await env.SUBSCRIPTIONS.put(indexKey, JSON.stringify(existing))

  return json({
    ok: true,
    url: new URL(`/sub/${secret}/${filename}`, request.url).toString(),
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

async function handleListSubscriptions(request, env) {
  if (!isTrustedApiRequest(request, env)) return json({ error: 'Request is not allowed.' }, 403, 'GET,OPTIONS', request, env)
  if (!env.SUBSCRIPTIONS) return json({ error: 'KV binding SUBSCRIPTIONS is not available.' }, 500, 'GET,OPTIONS', request, env)

  const ip = clientIp(request)
  const indexKey = `idx:${ip}`
  const entries = JSON.parse(await env.SUBSCRIPTIONS.get(indexKey) || '[]')

  const items = []
  for (const entry of entries) {
    const record = await env.SUBSCRIPTIONS.get(`sub:${entry.secret}`)
    if (record) {
      items.push({
        secret: entry.secret,
        url: new URL(`/sub/${entry.secret}/config.yaml`, request.url).toString(),
        createdAt: entry.createdAt,

      })
    }
  }

  if (items.length !== entries.length) {
    await env.SUBSCRIPTIONS.put(indexKey, JSON.stringify(entries.filter((e) => items.some((i) => i.secret === e.secret))))
  }

  return json({ ok: true, subscriptions: items }, 200, 'GET,OPTIONS', request, env)
}

async function handleDeleteSubscription(pathname, request, env) {
  if (!isTrustedApiRequest(request, env)) return json({ error: 'Request is not allowed.' }, 403, 'DELETE,OPTIONS', request, env)
  if (!env.SUBSCRIPTIONS) return json({ error: 'KV binding SUBSCRIPTIONS is not available.' }, 500, 'DELETE,OPTIONS', request, env)

  const secret = pathname.split('/')[3]
  const record = await env.SUBSCRIPTIONS.get(`sub:${secret}`)
  if (!record) return json({ error: 'Subscription not found.' }, 404, 'DELETE,OPTIONS', request, env)

  let storedIp = ''
  try { storedIp = JSON.parse(record).ip || '' } catch { /* ignore */ }
  const requestIp = clientIp(request)
  if (storedIp && storedIp !== requestIp) return json({ error: 'Not authorized to delete this subscription.' }, 403, 'DELETE,OPTIONS', request, env)

  await env.SUBSCRIPTIONS.delete(`sub:${secret}`)

  const indexKey = `idx:${requestIp}`
  const entries = JSON.parse(await env.SUBSCRIPTIONS.get(indexKey) || '[]')
  const filtered = entries.filter((e) => e.secret !== secret)
  if (filtered.length) await env.SUBSCRIPTIONS.put(indexKey, JSON.stringify(filtered))
  else await env.SUBSCRIPTIONS.delete(indexKey)

  return json({ ok: true }, 200, 'DELETE,OPTIONS', request, env)
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
    else yaml = record.startsWith('{') ? '' : record
  } catch {
    // not JSON — use record as-is
  }

  if (!yaml) {
    return new Response('Subscription data is corrupted.', {
      status: 500,
      headers: subscriptionHeaders(request, env),
    })
  }

  return new Response(yaml.endsWith('\n') ? yaml : `${yaml}\n`, {
    status: 200,
    headers: subscriptionHeaders(request, env),
  })
}

async function readLimitedBody(request, maxBytes) {
  const reader = request.body?.getReader()
  if (!reader) return ''
  const chunks = []
  let size = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > maxBytes) { reader.cancel(); return null }
    chunks.push(value)
  }
  return new TextDecoder().decode(chunks.length === 1 ? chunks[0] : concatUint8(chunks, size))
}

function concatUint8(chunks, size) {
  const result = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength }
  return result
}

function normalizeSubscriptionFilename(value) {
  const name = String(value || 'config.yaml').trim().replace(/[^A-Za-z0-9._-]/g, '-')
  return /\.ya?ml$/i.test(name) ? name : 'config.yaml'
}
