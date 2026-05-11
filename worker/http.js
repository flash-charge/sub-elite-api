export const MAX_INPUT_BYTES = 1024 * 1024
export const MAX_SUBSCRIPTION_BYTES = 256 * 1024
export const SUBSCRIPTION_RATE_LIMIT = {
  max: 20,
  windowSeconds: 60,
}
export const SUBSCRIPTION_EXPIRY = {
  '7d': 7 * 24 * 60 * 60,
  '30d': 30 * 24 * 60 * 60,
  never: undefined,
}

const SECRET_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
const PROXY_SECRET_HEADER = 'x-sub-elite-proxy-secret'
const DEFAULT_ALLOWED_ORIGIN = 'https://sub-elite.pages.dev'
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1'])

export function json(payload, status = 200, methods = 'GET,POST,OPTIONS', request, env) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      ...corsHeaders(methods, request, env),
      'content-type': 'application/json; charset=utf-8',
      ...securityHeaders(),
    },
  })
}

export function options(methods = 'GET,POST,OPTIONS', request, env) {
  return new Response(null, {
    status: isAllowedOrigin(request, env) ? 204 : 403,
    headers: corsHeaders(methods, request, env),
  })
}

export function corsHeaders(methods = 'GET,POST,OPTIONS', request, env) {
  return {
    'access-control-allow-origin': allowedCorsOrigin(request, env) || DEFAULT_ALLOWED_ORIGIN,
    'access-control-allow-methods': methods,
    'access-control-allow-headers': `content-type, ${PROXY_SECRET_HEADER}`,
    vary: 'Origin',
    ...securityHeaders(),
  }
}

export function subscriptionHeaders(request, env) {
  return {
    ...corsHeaders('GET,OPTIONS', request, env),
    'content-type': 'text/yaml; charset=utf-8',
    'cache-control': 'no-store',
    ...securityHeaders(),
  }
}

export function byteLength(value) {
  return new TextEncoder().encode(value).byteLength
}

export function randomSecret(length) {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  let output = ''
  for (const byte of bytes) output += SECRET_ALPHABET[byte % SECRET_ALPHABET.length]
  return output
}

export function hasHttpUrl(input) {
  return input
    .split(/\s+/)
    .some((item) => /^https?:\/\//i.test(item.trim()))
}

export function isAllowedOrigin(request, env) {
  const origin = request?.headers?.get('origin')
  if (!origin) return true
  return Boolean(allowedCorsOrigin(request, env))
}

export function isTrustedApiRequest(request, env) {
  const expectedSecret = proxySecret(env)
  if (expectedSecret) return constantTimeEqual(request.headers.get(PROXY_SECRET_HEADER) || '', expectedSecret)
  return Boolean(allowedCorsOrigin(request, env))
}

export function allowedCorsOrigin(request, env) {
  const origin = request?.headers?.get('origin')
  if (!origin) return ''

  try {
    const url = new URL(origin)
    const host = url.hostname.toLowerCase()
    if (host === 'sub-elite.pages.dev' || host.endsWith('.sub-elite.pages.dev')) return origin
    if (LOCAL_HOSTS.has(host)) return origin

    // Support custom domains via environment variable
    const customDomains = String(env?.ALLOWED_DOMAINS || '').split(',').map(d => d.trim().toLowerCase())
    if (customDomains.includes(host)) return origin
  } catch {
    return ''
  }

  return ''
}

export function clientIp(request) {
  return (
    request.headers.get('cf-connecting-ip') ||
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    'unknown'
  )
}

export function securityHeaders() {
  return {
    'content-security-policy': [
      "default-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "form-action 'none'",
    ].join('; '),
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()',
    'referrer-policy': 'no-referrer',
    'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
  }
}

function proxySecret(env) {
  return String(env?.SUB_ELITE_PROXY_SECRET || '').trim()
}

function constantTimeEqual(left, right) {
  const leftValue = String(left)
  const rightValue = String(right)
  let mismatch = leftValue.length ^ rightValue.length
  const maxLength = Math.max(leftValue.length, rightValue.length)

  for (let index = 0; index < maxLength; index += 1) {
    mismatch |= (leftValue.charCodeAt(index) || 0) ^ (rightValue.charCodeAt(index) || 0)
  }

  return mismatch === 0
}

export function readConvertOptions(payload) {
  return {
    template: payload.template,
    rulesPreset: payload.rulesPreset,
    namePattern: payload.namePattern,
    namePrefix: payload.namePrefix,
  }
}
