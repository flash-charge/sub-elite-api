export type ProxyNode = Record<string, any>

export const PROTOCOL_RE = /^(vmess|vless|trojan|ss|ssr|socks|socks5|hysteria|hysteria2|hy2|tuic|wireguard):\/\//i
export const PROVIDER_TYPES = ['http', 'file', 'inline']
export const TRANSPORT_TYPES = ['http', 'h2', 'grpc', 'ws', 'xhttp']
export const TRANSPORT_TYPES_BY_PROXY: Record<string, string[]> = {
  vmess: ['ws', 'http', 'h2', 'grpc'],
  vless: ['ws', 'http', 'h2', 'grpc', 'xhttp'],
  trojan: ['ws', 'grpc'],
}
export const TLS_FIELDS_BY_PROXY: Record<string, string[]> = {
  vmess: ['sni', 'alpn', 'client-fingerprint', 'fingerprint', 'skip-cert-verify', 'certificate', 'private-key', 'reality', 'ech'],
  vless: ['sni', 'alpn', 'client-fingerprint', 'fingerprint', 'skip-cert-verify', 'certificate', 'private-key', 'reality', 'ech'],
  trojan: ['sni', 'alpn', 'client-fingerprint', 'fingerprint', 'skip-cert-verify', 'certificate', 'private-key', 'reality', 'ech'],
  anytls: ['sni', 'alpn', 'client-fingerprint', 'fingerprint', 'skip-cert-verify'],
  hysteria: ['sni', 'alpn', 'skip-cert-verify', 'fingerprint'],
  hysteria2: ['sni', 'alpn', 'skip-cert-verify', 'fingerprint'],
  tuic: ['sni', 'alpn', 'skip-cert-verify', 'fingerprint'],
  socks5: ['sni', 'skip-cert-verify'],
  http: ['sni', 'skip-cert-verify'],
}
export const TLS_FLAG_PROXY_TYPES = new Set(['vmess', 'vless', 'trojan', 'socks5', 'http'])
export const PROXY_PRIVATE_KEY_TYPES = new Set(['wireguard', 'masque'])
export const REQUIRED_PROXY_FIELDS: Record<string, string[]> = {
  vmess: ['server', 'port', 'uuid'],
  vless: ['server', 'port', 'uuid'],
  trojan: ['server', 'port', 'password'],
  ss: ['server', 'port', 'cipher', 'password'],
  ssr: ['server', 'port', 'cipher', 'password', 'protocol', 'obfs'],
  socks5: ['server', 'port'],
  http: ['server', 'port'],
  hysteria: ['server', 'port', 'auth-str'],
  hysteria2: ['server', 'port', 'password'],
  tuic: ['server', 'port', 'uuid', 'password'],
  wireguard: ['server', 'port', 'private-key', 'public-key'],
  ssh: ['server', 'port', 'username'],
}

export function formatKey(key) {
  if (/^[a-zA-Z0-9_-]+$/.test(key)) return key
  return JSON.stringify(key)
}

export function formatScalar(value, indent = 0) {
  if (value === null) return 'null'
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'null'
  if (typeof value === 'boolean') return String(value)
  const str = String(value)
  if (str.includes('\n')) {
    const scalarPad = ' '.repeat(indent + 2)
    return '|\n' + str.split(/\r?\n/).map(line => scalarPad + line).join('\n')
  }
  return JSON.stringify(str)
}

export function isScalar(value) {
  return value === null || ['string', 'number', 'boolean'].includes(typeof value)
}

export function isEmptyProxyField(value) {
  if (value === undefined || value === null) return true
  if (typeof value === 'string' && value.trim() === '') return true
  if (Array.isArray(value) && value.length === 0) return true
  return false
}

export function missingProxyProviderPayloadFields(proxy) {
  if (!isPlainObject(proxy)) return ['name', 'type']
  const type = String(proxy.type || '').toLowerCase()
  const requiredFields = ['name', 'type', ...(REQUIRED_PROXY_FIELDS[type] || ['server', 'port'])]
  return requiredFields.filter((field) => isEmptyProxyField(proxy[field]))
}

export function isValidProxyProviderPayloadProxy(proxy) {
  return isPlainObject(proxy) && !hasRuleSeparator(proxy.name) && missingProxyProviderPayloadFields(proxy).length === 0
}

export function hasRuleSeparator(value) {
  return String(value || '').includes(',')
}

export function normalizeObject(value: ProxyNode = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  return { ...value }
}

export function normalizeBooleanValue(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback
  if (value === true || value === false) return value
  const normalized = String(value).trim().toLowerCase()
  if (['true', '1', 'yes', 'on'].includes(normalized)) return true
  if (['false', '0', 'no', 'off'].includes(normalized)) return false
  return Boolean(value)
}

export function isTruthyBooleanValue(value) {
  if (value === true) return true
  if (typeof value === 'string') return ['true', '1', 'yes', 'on'].includes(value.trim().toLowerCase())
  return false
}

export function normalizeProxyModelNode(proxy: ProxyNode = {}) {
  const normalized = { ...proxy }
  normalized.name = String(normalized.name || '').trim()
  normalized.type = String(normalized.type || '').trim().toLowerCase()
  if (normalized.enabled !== undefined) normalized.enabled = normalizeBooleanValue(normalized.enabled, true)
  if (normalized['dialer-proxy'] !== undefined) normalized['dialer-proxy'] = String(normalized['dialer-proxy'] || '').trim()
  if (normalized.network !== undefined) normalized.network = String(normalized.network || '').trim().toLowerCase()
  return normalized
}

export function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

export function omitKeys(value: ProxyNode = {}, keys: string[]) {
  const omitted = new Set(keys)
  return Object.fromEntries(Object.entries(value).filter(([key]) => !omitted.has(key)))
}

export function normalizeList(value, fallback) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean)
  if (typeof value === 'string') return value.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean)
  return fallback
}

export function normalizeLineList(value, fallback) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean)
  if (typeof value === 'string') return value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean)
  return fallback
}

export function normalizeRuleList(value, fallback) {
  return normalizeLineList(value, fallback).map(normalizeRuleLine).filter(Boolean)
}

export function normalizeRuleLine(rule) {
  return splitRuleParts(rule).filter((part) => part !== '').join(',')
}

export function splitRuleParts(rule) {
  const parts: string[] = []
  let current = ''
  let depth = 0
  for (const char of String(rule)) {
    if (char === '(') depth += 1
    else if (char === ')' && depth > 0) depth -= 1

    if (char === ',' && depth === 0) {
      parts.push(current.trim())
      current = ''
    } else {
      current += char
    }
  }
  parts.push(current.trim())
  return parts
}

export function finalizeProxyTransport(proxy) {
  if (proxy.network && !isTransportSupportedByProxy(proxy, proxy.network)) {
    delete proxy.network
    cleanupProxyTransportOptions(proxy)
    return proxy
  }

  if (proxy.network === 'xhttp') applyXhttpDefaults(proxy)
  return proxy
}

export function isTransportSupportedByProxy(proxy, network) {
  if (!network) return true
  const proxyType = String(proxy.type || '').toLowerCase()
  const supported = TRANSPORT_TYPES_BY_PROXY[proxyType]
  return Array.isArray(supported) ? supported.includes(network) : false
}

export function cleanupProxyTransportOptions(proxy) {
  delete proxy['ws-opts']
  delete proxy['grpc-opts']
  delete proxy['h2-opts']
  delete proxy['http-opts']
  delete proxy['httpupgrade-opts']
  delete proxy['xhttp-opts']
}

export function applyXhttpDefaults(proxy) {
  if (!Array.isArray(proxy.alpn) || !proxy.alpn.length) proxy.alpn = ['h2']
  if (proxy.encryption === undefined) proxy.encryption = ''
  proxy['xhttp-opts'] = {
    path: '/',
    ...(proxy['xhttp-opts'] || {}),
    'no-grpc-header': booleanValue(proxy['xhttp-opts']?.['no-grpc-header']),
    'x-padding-obfs-mode': booleanValue(proxy['xhttp-opts']?.['x-padding-obfs-mode']),
  }
}

export function booleanValue(value) {
  if (value === true || value === false) return value
  return ['1', 'true', 'yes'].includes(String(value || '').toLowerCase())
}

export function normalizeTransport(value) {
  const transport = String(value || '').toLowerCase()
  if (!transport || transport === 'tcp') return undefined
  return TRANSPORT_TYPES.includes(transport) ? transport : undefined
}

export function makeUniqueProviderNames(providers, basePath = './rules') {
  const seen = new Map()
  for (const provider of providers) {
    if (!provider.name) continue
    const base = provider.name
    const count = seen.get(base) || 0
    seen.set(base, count + 1)
    provider.name = count === 0 ? base : `${base}-${count + 1}`
    if (!provider.path) provider.path = `${basePath}/${provider.name}.yaml`
  }
}

export function compact(object) {
  return Object.fromEntries(
    Object.entries(object).filter(([, value]) => {
      if (value === undefined || value === null || value === '') return false
      if (typeof value === 'number' && Number.isNaN(value)) return false
      if (value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0) return false
      return true
    }),
  )
}

export function defaultPort(protocol, params) {
  if (protocol === 'trojan') return 443
  return params.get('security') === 'tls' || params.get('security') === 'reality' ? 443 : 80
}

export function defaultProxyPort(protocol) {
  if (protocol === 'ss' || protocol === 'ssr') return 8388
  return 443
}

export function getProtocol(line) {
  const match = String(line || '').match(/^([a-z0-9+.-]+):\/\//i)
  return match ? match[1].toLowerCase() : ''
}

export function snippet(value) {
  const text = String(value || '').trim()
  const redacted = text.replace(/^((?:wireguard|trojan|hy2|hysteria2|tuic):\/\/)[^@]+@/i, '$1***@')
  return redacted.length > 96 ? `${redacted.slice(0, 96)}...` : redacted
}

export function required(value, field) {
  if (value === undefined || value === null || value === '') throw new Error(`${field} is required`)
  return value
}

export function toPort(value) {
  const port = Number(value)
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('port is invalid')
  return port
}

export function toUrl(link) {
  try {
    return new URL(link)
  } catch {
    throw new Error('URL is invalid')
  }
}

export function boolParam(value) {
  if (value === null || value === undefined || value === '') return undefined
  return ['1', 'true', 'yes'].includes(String(value).toLowerCase())
}

export function numberParam(value) {
  if (value === null || value === undefined || value === '') return undefined
  const number = Number(value)
  return Number.isFinite(number) ? number : undefined
}

export function parseReserved(value) {
  if (!value) return undefined
  const parts = value.split(',').map((s) => s.trim())
  if (parts.every((p) => /^\d+$/.test(p))) return parts.map(Number)
  return value
}

export function cleanName(value) {
  const decoded = decodeText(String(value || '')).trim()
  return decoded || 'proxy'
}

export function decodeText(value) {
  try {
    return decodeURIComponent(String(value).replace(/\+/g, '%20'))
  } catch {
    return String(value)
  }
}

export function base64Param(params, key) {
  const value = params.get(key)
  return value ? tryBase64Decode(value) : undefined
}

export function tryBase64Decode(value) {
  const raw = String(value || '').trim()
  if (!raw) return ''
  try {
    const normalized = raw.replace(/-/g, '+').replace(/_/g, '/')
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')
    const binary = atob(padded)
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0))
    return new TextDecoder().decode(bytes).trim()
  } catch {
    return ''
  }
}
