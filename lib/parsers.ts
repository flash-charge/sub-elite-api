import {
  type ProxyNode, PROTOCOL_RE, TRANSPORT_TYPES_BY_PROXY,
  compact, normalizeList, normalizeTransport, finalizeProxyTransport,
  defaultPort, snippet, required, toPort, toUrl, boolParam, numberParam,
  parseReserved, cleanName, decodeText, base64Param, tryBase64Decode,
} from './helpers.ts'

export function extractLinks(input) {
  const trimmed = String(input || '').trim()
  if (!trimmed) return []

  const candidates = [trimmed]
  const decoded = tryBase64Decode(trimmed)
  if (decoded && decoded !== trimmed) candidates.unshift(decoded)

  for (const candidate of candidates) {
    const links = candidate
      .replace(/,(?=(?:vmess|vless|trojan|ss|ssr|socks|socks5|hysteria|hysteria2|hy2|tuic|wireguard):\/\/)/gi, '\n')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#') && !line.startsWith('//'))
      .flatMap((line) => {
        const matches = line.match(/[a-z0-9+.-]+:\/\/\S+/gi)
        return matches || [line]
      })
      .map((line) => line.trim().replace(/,$/, ''))
      .filter(Boolean)

    if (links.some((line) => PROTOCOL_RE.test(line))) return links
  }

  return candidates[0]
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
}

export function parseLink(link) {
  const protocol = link.slice(0, link.indexOf('://')).toLowerCase()
  if (protocol === 'vmess') return parseVmess(link)
  if (protocol === 'vless') return parseVless(link)
  if (protocol === 'trojan') return parseTrojan(link)
  if (protocol === 'ss') return parseShadowsocks(link)
  if (protocol === 'ssr') return parseShadowsocksR(link)
  if (protocol === 'socks' || protocol === 'socks5') return parseSocks(link)
  if (protocol === 'hysteria') return parseHysteria(link)
  if (protocol === 'hysteria2' || protocol === 'hy2') return parseHysteria2(link)
  if (protocol === 'tuic') return parseTuic(link)
  if (protocol === 'wireguard') return parseWireGuard(link)
  return null
}

function parseVmess(link) {
  const raw = link.replace(/^vmess:\/\//i, '').trim()
  const decoded = tryBase64Decode(raw)
  if (!decoded) throw new Error('VMess payload is not valid base64')

  let data
  try {
    data = JSON.parse(decoded)
  } catch {
    throw new Error('VMess payload is not valid JSON')
  }

  const proxy = compact({
    name: cleanName(data.ps || data.add || 'vmess'),
    type: 'vmess',
    server: required(data.add, 'server'),
    port: toPort(data.port),
    uuid: required(data.id, 'uuid'),
    alterId: Number(data.aid || 0),
    cipher: data.scy || 'auto',
    tls: data.tls === 'tls',
    servername: data.sni || (data.host && !data.host.includes(',') ? data.host : undefined),
    network: normalizeTransport(data.net),
  })

  applyTransport(proxy, {
    type: data.net,
    host: data.host,
    path: data.path,
    serviceName: data.path,
  })

  finalizeProxyTransport(proxy)
  return proxy
}

function parseVless(link) {
  const url = toUrl(link)
  const params = url.searchParams
  const proxy = compact({
    name: cleanName(url.hash ? decodeText(url.hash.slice(1)) : url.hostname || 'vless'),
    type: 'vless',
    server: required(url.hostname, 'server'),
    port: toPort(url.port || defaultPort('vless', params)),
    uuid: required(url.username, 'uuid'),
    flow: params.get('flow') || undefined,
    tls: params.get('security') === 'tls' || params.get('security') === 'reality',
    servername: params.get('sni') || params.get('peer') || undefined,
    alpn: params.get('alpn')?.split(',') || undefined,
    encryption: params.has('encryption') ? params.get('encryption') : undefined,
    'client-fingerprint': params.get('fp') || undefined,
    'skip-cert-verify': boolParam(params.get('allowInsecure')),
    network: normalizeTransport(params.get('type')),
  })

  if (params.get('security') === 'reality') {
    proxy.reality = true
    proxy['reality-opts'] = compact({
      'public-key': params.get('pbk') || undefined,
      'short-id': params.get('sid') || undefined,
      'spider-x': params.get('spx') ? decodeText(params.get('spx')) : undefined,
    })
  }

  applyTransport(proxy, {
    type: params.get('type'),
    host: params.get('host'),
    path: params.get('path'),
    serviceName: params.get('serviceName'),
    mode: params.get('mode'),
    method: params.get('method'),
    extra: params,
  })

  finalizeProxyTransport(proxy)
  return proxy
}

function parseTrojan(link) {
  const url = toUrl(link)
  const params = url.searchParams
  const proxy = compact({
    name: cleanName(url.hash ? decodeText(url.hash.slice(1)) : url.hostname || 'trojan'),
    type: 'trojan',
    server: required(url.hostname, 'server'),
    port: toPort(url.port || defaultPort('trojan', params)),
    password: required(decodeText(url.username), 'password'),
    sni: params.get('sni') || params.get('peer') || undefined,
    alpn: params.get('alpn')?.split(',') || undefined,
    'skip-cert-verify': boolParam(params.get('allowInsecure')),
    network: normalizeTransport(params.get('type')),
  })

  applyTransport(proxy, {
    type: params.get('type'),
    host: params.get('host'),
    path: params.get('path'),
    serviceName: params.get('serviceName'),
    mode: params.get('mode'),
    method: params.get('method'),
    extra: params,
  })

  finalizeProxyTransport(proxy)
  return proxy
}

function parseShadowsocks(link) {
  const raw = link.replace(/^ss:\/\//i, '')
  const [withoutHash, hash = ''] = raw.split('#')
  const name = cleanName(hash || 'ss')
  const [mainPart, queryPart = ''] = withoutHash.split('?')

  const decodedMain = tryBase64Decode(decodeText(mainPart))
  const candidate = decodedMain && decodedMain.includes('@') ? decodedMain : mainPart
  const url = toUrl(`ss://${candidate}${queryPart ? `?${queryPart}` : ''}`)
  const params = url.searchParams

  let cipher = decodeText(url.username)
  let password = decodeText(url.password)

  if (!password) {
    const userInfo = tryBase64Decode(decodeText(url.username))
    if (userInfo && userInfo.includes(':')) {
      const splitAt = userInfo.indexOf(':')
      cipher = userInfo.slice(0, splitAt)
      password = userInfo.slice(splitAt + 1)
    }
  }

  const proxy = compact({
    name,
    type: 'ss',
    server: required(url.hostname, 'server'),
    port: toPort(url.port || 8388),
    cipher: required(cipher, 'cipher'),
    password: required(password, 'password'),
    udp: true,
  })

  const pluginStr = params.get('plugin')
  if (pluginStr) {
    const parts = decodeText(pluginStr).split(';')
    proxy.plugin = parts[0]
    const opts = {}
    for (let i = 1; i < parts.length; i++) {
      const [key, ...valueParts] = parts[i].split('=')
      if (key) {
        opts[key] = valueParts.length ? decodeText(valueParts.join('=')) : true
      }
    }
    proxy['plugin-opts'] = opts
  }

  return proxy
}

function parseShadowsocksR(link) {
  const payload = tryBase64Decode(link.replace(/^ssr:\/\//i, ''))
  if (!payload) throw new Error('SSR payload is not valid base64')

  const [main, rawParams = ''] = payload.split('/?')
  const parts = main.split(':')
  if (parts.length < 6) throw new Error('SSR format is incomplete')

  const server = parts.slice(0, parts.length - 5).join(':')
  const port = parts[parts.length - 5]
  const protocol = parts[parts.length - 4]
  const cipher = parts[parts.length - 3]
  const obfs = parts[parts.length - 2]
  const passwordB64 = parts[parts.length - 1]

  const params = new URLSearchParams(rawParams)
  return compact({
    name: cleanName(base64Param(params, 'remarks') || server || 'ssr'),
    type: 'ssr',
    server: required(server.replace(/^\[|\]$/g, ''), 'server'),
    port: toPort(port),
    cipher: required(cipher, 'cipher'),
    password: required(tryBase64Decode(passwordB64), 'password'),
    protocol: required(protocol, 'protocol'),
    obfs: required(obfs, 'obfs'),
    'protocol-param': base64Param(params, 'protoparam') || undefined,
    'obfs-param': base64Param(params, 'obfsparam') || undefined,
  })
}

function parseSocks(link) {
  const url = toUrl(link.replace(/^socks:\/\//i, 'socks5://'))
  const params = url.searchParams

  return compact({
    name: cleanName(url.hash ? decodeText(url.hash.slice(1)) : url.hostname || 'socks5'),
    type: 'socks5',
    server: required(url.hostname, 'server'),
    port: toPort(url.port || 1080),
    username: url.username ? decodeText(url.username) : undefined,
    password: url.password ? decodeText(url.password) : undefined,
    udp: boolParam(params.get('udp')),
    tls: boolParam(params.get('tls')),
    sni: params.get('sni') || undefined,
    'skip-cert-verify': boolParam(params.get('allowInsecure') || params.get('insecure')),
  })
}

function parseHysteria(link) {
  const url = toUrl(link)
  const params = url.searchParams

  return compact({
    name: cleanName(url.hash ? decodeText(url.hash.slice(1)) : url.hostname || 'hysteria'),
    type: 'hysteria',
    server: required(url.hostname, 'server'),
    port: toPort(url.port),
    'auth-str': required(decodeText(url.username || params.get('auth-str') || params.get('auth_str') || params.get('auth') || ''), 'auth-str'),
    alpn: params.get('alpn')?.split(',') || undefined,
    protocol: params.get('protocol') || undefined,
    up: params.get('up') || undefined,
    down: params.get('down') || undefined,
    sni: params.get('sni') || undefined,
    'skip-cert-verify': boolParam(params.get('allowInsecure') || params.get('insecure')),
    obfs: params.get('obfs') || undefined,
    'obfs-password': params.get('obfs-password') || params.get('obfsPassword') || undefined,
  })
}

function parseHysteria2(link) {
  const url = toUrl(link.replace(/^hy2:\/\//i, 'hysteria2://'))
  const params = url.searchParams

  return compact({
    name: cleanName(url.hash ? decodeText(url.hash.slice(1)) : url.hostname || 'hysteria2'),
    type: 'hysteria2',
    server: required(url.hostname, 'server'),
    port: toPort(url.port),
    password: required(decodeText(url.username), 'password'),
    up: params.get('up') || undefined,
    down: params.get('down') || undefined,
    sni: params.get('sni') || undefined,
    'skip-cert-verify': boolParam(params.get('insecure')),
    obfs: params.get('obfs') || undefined,
    'obfs-password': params.get('obfs-password') || params.get('obfsPassword') || undefined,
  })
}

function parseTuic(link) {
  const url = toUrl(link)
  const params = url.searchParams

  return compact({
    name: cleanName(url.hash ? decodeText(url.hash.slice(1)) : url.hostname || 'tuic'),
    type: 'tuic',
    server: required(url.hostname, 'server'),
    port: toPort(url.port),
    uuid: required(decodeText(url.username), 'uuid'),
    password: required(decodeText(url.password), 'password'),
    sni: params.get('sni') || undefined,
    alpn: params.get('alpn')?.split(',') || undefined,
    'skip-cert-verify': boolParam(params.get('allow_insecure') || params.get('insecure')),
    'congestion-controller': params.get('congestion_control') || params.get('congestion-controller') || undefined,
    udp: true,
  })
}

function parseWireGuard(link) {
  const url = toUrl(link)
  const params = url.searchParams

  return compact({
    name: cleanName(url.hash ? decodeText(url.hash.slice(1)) : url.hostname || 'wireguard'),
    type: 'wireguard',
    server: required(url.hostname, 'server'),
    port: toPort(url.port || 51820),
    ip: params.get('address') || undefined,
    ipv6: params.get('ipv6') || params.get('address6') || undefined,
    'private-key': required(decodeText(url.username), 'private-key'),
    'public-key': required(params.get('publickey'), 'public-key'),
    'pre-shared-key': params.get('presharedkey') || undefined,
    reserved: parseReserved(params.get('reserved')),
    mtu: numberParam(params.get('mtu')),
    'persistent-keepalive': numberParam(params.get('keepalive') || params.get('persistent-keepalive')),
    'remote-dns-resolve': boolParam(params.get('remote-dns-resolve')),
    dns: params.get('dns')?.split(',').map((s) => s.trim()).filter(Boolean) || undefined,
    udp: true,
    peers: [{
      server: url.hostname,
      port: toPort(url.port || 51820),
      'public-key': params.get('publickey'),
      'pre-shared-key': params.get('presharedkey') || undefined,
      reserved: parseReserved(params.get('reserved')),
      'allowed-ips': params.get('allowedips')?.split(',') || undefined,
    }]
  })
}

function applyTransport(proxy, options) {
  const type = String(options.type || '').toLowerCase()

  if (type === 'ws') {
    proxy.network = 'ws'
    proxy['ws-opts'] = compact({
      path: options.path ? decodeText(options.path) : '/',
      headers: options.host ? { Host: decodeText(options.host) } : undefined,
      'max-early-data': numberParam(options.extra?.get('ed') || options.extra?.get('max-early-data')),
      'early-data-header-name': options.extra?.get('eh') || options.extra?.get('early-data-header-name') || undefined,
      'v2ray-http-upgrade': boolParam(options.extra?.get('v2ray-http-upgrade')),
      'v2ray-http-upgrade-fast-open': boolParam(options.extra?.get('v2ray-http-upgrade-fast-open')),
    })
  }

  if (type === 'grpc') {
    proxy.network = 'grpc'
    proxy['grpc-opts'] = compact({
      'grpc-service-name': options.serviceName ? decodeText(options.serviceName) : undefined,
      'grpc-user-agent': options.extra?.get('grpc-user-agent') || undefined,
      'ping-interval': numberParam(options.extra?.get('ping-interval')),
      'max-connections': numberParam(options.extra?.get('max-connections')),
      'min-streams': numberParam(options.extra?.get('min-streams')),
      'max-streams': numberParam(options.extra?.get('max-streams')),
    })
  }

  if (type === 'h2') {
    proxy.network = 'h2'
    proxy['h2-opts'] = compact({
      host: normalizeList(options.host, []),
      path: options.path ? decodeText(options.path) : undefined,
    })
  }

  if (type === 'http') {
    proxy.network = 'http'
    proxy['http-opts'] = compact({
      method: options.method || undefined,
      path: options.path ? normalizeList(decodeText(options.path), []) : undefined,
      headers: options.host ? { Host: normalizeList(decodeText(options.host), []) } : undefined,
    })
  }

  if (type === 'xhttp') {
    proxy.network = type
    proxy['xhttp-opts'] = compact({
      path: options.path ? decodeText(options.path) : '/',
      host: options.host ? decodeText(options.host) : undefined,
      mode: options.mode || undefined,
      'no-grpc-header': boolParam(options.extra?.get('no-grpc-header')),
      'x-padding-bytes': options.extra?.get('x-padding-bytes') || undefined,
      'x-padding-obfs-mode': boolParam(options.extra?.get('x-padding-obfs-mode')),
      'x-padding-key': options.extra?.get('x-padding-key') || undefined,
      'x-padding-header': options.extra?.get('x-padding-header') || undefined,
      'x-padding-placement': options.extra?.get('x-padding-placement') || undefined,
      'x-padding-method': options.extra?.get('x-padding-method') || undefined,
      'uplink-http-method': options.extra?.get('uplink-http-method') || undefined,
      'session-placement': options.extra?.get('session-placement') || undefined,
      'session-key': options.extra?.get('session-key') || undefined,
      'seq-placement': options.extra?.get('seq-placement') || undefined,
      'seq-key': options.extra?.get('seq-key') || undefined,
      'uplink-data-placement': options.extra?.get('uplink-data-placement') || undefined,
      'uplink-data-key': options.extra?.get('uplink-data-key') || undefined,
      'uplink-chunk-size': numberParam(options.extra?.get('uplink-chunk-size')),
      'sc-max-each-post-bytes': numberParam(options.extra?.get('sc-max-each-post-bytes')),
      'sc-min-posts-interval-ms': numberParam(options.extra?.get('sc-min-posts-interval-ms')),
    })
  }
}
