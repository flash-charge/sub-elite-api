type ProxyNode = Record<string, any>

const PROTOCOL_RE = /^(vmess|vless|trojan|ss|ssr|socks|socks5|hysteria|hysteria2|hy2|tuic|wireguard):\/\//i
const TRANSPORT_TYPES = ['http', 'h2', 'grpc', 'ws', 'xhttp']
const TRANSPORT_TYPES_BY_PROXY: Record<string, string[]> = {
  vmess: ['ws', 'http', 'h2', 'grpc'],
  vless: ['ws', 'http', 'h2', 'grpc', 'xhttp'],
  trojan: ['ws', 'grpc'],
}
const TLS_FIELDS_BY_PROXY: Record<string, string[]> = {
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
const TLS_FLAG_PROXY_TYPES = new Set(['vmess', 'vless', 'trojan', 'socks5', 'http'])
const PROXY_PRIVATE_KEY_TYPES = new Set(['wireguard', 'masque'])
const REQUIRED_PROXY_FIELDS: Record<string, string[]> = {
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

export function convertToClashMeta(input: string, options: any = {}) {
  const normalizedOptions = normalizeOptions(options)
  const lines = extractLinks(input)
  const warnings: any[] = []
  const proxies: ProxyNode[] = []

  lines.forEach((line, index) => {
    const protocol = getProtocol(line)
    try {
      const proxy = parseLink(line) as ProxyNode
      if (!proxy) {
        warnings.push({
          index,
          type: 'unsupported',
          protocol,
          snippet: snippet(line),
          message: `Line ${index + 1}${protocol ? ` (${protocol})` : ''} was skipped because the protocol is not supported yet.`,
        })
        return
      }
      // Internal UI key only; never emit it into generated YAML.
      proxy.id = typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2, 11)
      proxies.push(proxy)
    } catch (error: any) {
      warnings.push({
        index,
        type: 'invalid',
        protocol,
        snippet: snippet(line),
        message: `Line ${index + 1}${protocol ? ` (${protocol})` : ''}: ${error.message}`,
      })
    }
  })

  applyNamePattern(proxies, normalizedOptions.namePattern)
  makeUniqueNames(proxies)
  const model = createConfigModel(proxies, normalizedOptions)

  return {
    yaml: buildYamlFromModel(model),
    model,
    stats: {
      total: lines.length,
      converted: proxies.length,
      skipped: warnings.length,
    },
    warnings,
  }
}

export const outputTemplates = ['full', 'proxies', 'provider']
export const rulesPresets = ['proxy', 'lan-direct', 'direct']
export const groupTypes = ['select', 'url-test', 'fallback', 'load-balance', 'relay']

export function createConfigModel(proxies: ProxyNode[], options: any = {}) {
  const normalizedOptions = normalizeOptions(options)
  const proxyNames = proxies.map((proxy) => proxy.name)

  return {
    template: normalizedOptions.template,
    rulesPreset: normalizedOptions.rulesPreset,
    general: createGeneral(),
    profile: createProfile(),
    dns: {
      enable: true,
      listen: '0.0.0.0:1053',
      ipv6: false,
      cacheAlgorithm: '',
      preferH3: false,
      useHosts: false,
      useSystemHosts: false,
      respectRules: false,
      enhancedMode: 'redir-host',
      fakeIpRange: '198.18.0.1/16',
      fakeIpRange6: '',
      fakeIpFilterMode: '',
      fakeIpTtl: 0,
      fakeIpFilter: ['*.lan', '*.local', '+.msftconnecttest.com', '+.msftncsi.com'],
      defaultNameserver: ['1.1.1.1', '8.8.8.8'],
      nameserver: ['https://dns.google/dns-query', 'https://cloudflare-dns.com/dns-query'],
      fallback: [],
      fallbackFilter: {},
      directNameserver: [],
      directNameserverFollowPolicy: false,
      proxyServerNameserver: [],
      proxyServerNameserverPolicy: {},
      nameserverPolicy: {},
    },
    sniffer: createSniffer(),
    tun: createTun(),
    ntp: createNtp(),
    experimental: {},
    geo: createGeo(),
    ruleProviders: [],
    proxyProviders: [],
    listeners: [],
    subRules: {},
    tunnels: [],
    extraTopLevel: {},
    rawSections: {},
    proxies: proxies.map((proxy) => ({ ...proxy, enabled: true })),
    groups: buildDefaultGroups(proxyNames),
    rules: buildRules(normalizedOptions.rulesPreset),
  }
}

export function buildYamlFromModel(model: any) {
  const normalizedModel = normalizeModel(model)
  const proxies = (normalizedModel.proxies as ProxyNode[]).filter((proxy) => proxy.enabled !== false).map(stripUiProxyFields)

  if (normalizedModel.template === 'proxies') {
    return `${spaceTopLevelSections(dumpYaml({ proxies }))}\n`
  }

  if (normalizedModel.template === 'provider') {
    return `${spaceTopLevelSections(dumpYaml({
      'proxy-providers': {
        converted: {
          type: 'inline',
          payload: proxies,
        },
      },
    }))}\n`
  }

  const generalConfig = {
    ...normalizedModel.extraTopLevel,
    'mixed-port': normalizedModel.general.mixedPort,
    'allow-lan': normalizedModel.general.allowLan,
    mode: normalizedModel.general.mode,
    'log-level': normalizedModel.general.logLevel,
    ipv6: normalizedModel.general.ipv6,
    ...buildGeneralAdvanced(normalizedModel),
    ...normalizeRawSection(normalizedModel.rawSections.general),
  }

  const config = {
    ...generalConfig,
    ...buildProfile(normalizedModel.profile),
    ...buildGeo(normalizedModel.geo),
    dns: normalizeRawSection(normalizedModel.rawSections.dns) || buildDns(normalizedModel.dns),
    ...buildSniffer(normalizedModel.sniffer, normalizedModel.rawSections.sniffer),
    ...buildTun(normalizedModel.tun, normalizedModel.rawSections.tun),
    ...buildNtp(normalizedModel.ntp, normalizedModel.rawSections.ntp),
    ...buildExperimental(normalizedModel.experimental, normalizedModel.rawSections.experimental),
    proxies,
    ...buildProxyProviders(normalizedModel.proxyProviders),
    'proxy-groups': buildProxyGroups(normalizedModel, proxies),
    ...buildListeners(normalizedModel.listeners),
    ...buildRuleProviders(normalizedModel.ruleProviders),
    ...buildSubRules(normalizedModel.subRules),
    ...buildTunnels(normalizedModel.tunnels),
    rules: normalizedModel.rules.length ? normalizedModel.rules : ['MATCH,PROXY'],
  }

  return `${spaceTopLevelSections(dumpYaml(config))}\n`
}

export function validateConfigModel(model) {
  const normalizedModel = normalizeModel(model)
  const enabledProxies = normalizedModel.proxies.filter((proxy) => proxy.enabled !== false)
  const names = enabledProxies.map((proxy) => proxy.name).filter(Boolean)
  const duplicateNames = names.filter((name, index) => names.indexOf(name) !== index)
  const proxyNames = new Set(names)
  const groupNames = new Set(normalizedModel.groups.map((group) => group.name).filter(Boolean))
  const groupNameList = normalizedModel.groups.map((group) => group.name).filter(Boolean)
  const duplicateGroups = groupNameList.filter((name, index) => groupNameList.indexOf(name) !== index)
  const providerNames = normalizedModel.ruleProviders.map((provider) => provider.name).filter(Boolean)
  const proxyProviderNames = normalizedModel.proxyProviders.map((provider) => provider.name).filter(Boolean)
  const duplicateProviders = providerNames.filter((name, index) => providerNames.indexOf(name) !== index)
  const duplicateProxyProviders = proxyProviderNames.filter((name, index) => proxyProviderNames.indexOf(name) !== index)
  const errors: string[] = []
  const warnings: string[] = []
  const issues: ProxyNode[] = []

  const addIssue = (severity, location, message, code) => {
    issues.push({ severity, location, message, code })
    if (severity === 'error') errors.push(`${location}: ${message}`)
    else warnings.push(`${location}: ${message}`)
  }

  if (enabledProxies.length === 0) addIssue('warning', 'Nodes', 'No active nodes yet. YAML can still be generated and nodes can be added manually.', 'no-enabled-proxy')
  if (duplicateNames.length) addIssue('error', 'Nodes', `Duplicate node names: ${[...new Set(duplicateNames)].join(', ')}`, 'duplicate-proxy-name')
  if (duplicateGroups.length) addIssue('error', 'Groups', `Duplicate group names: ${[...new Set(duplicateGroups)].join(', ')}`, 'duplicate-group-name')
  if (normalizedModel.template === 'full' && normalizedModel.groups.length === 0) addIssue('error', 'Groups', 'At least one proxy group is required.', 'no-group')
  if (normalizedModel.template === 'full' && normalizedModel.rules.length === 0) addIssue('warning', 'Rules', 'Rules are empty; MATCH,PROXY will be used as fallback.', 'empty-rules')
  if (!normalizedModel.dns.listen) addIssue('warning', 'DNS', 'DNS listen is empty.', 'empty-dns-listen')
  if (normalizedModel.tun.enable && !normalizedModel.tun.stack) addIssue('error', 'TUN', 'TUN stack is required when TUN is enabled.', 'empty-tun-stack')
  if (normalizedModel.sniffer.enable && !hasSniffProtocols(normalizedModel.sniffer.sniff)) addIssue('warning', 'Sniffer', 'Sniffer is enabled without sniff protocols.', 'empty-sniff')

  enabledProxies.forEach((proxy, index) => {
    if (['direct', 'dns'].includes(proxy.type)) return
    const location = `Node ${index + 1}`
    const type = String(proxy.type || '').toLowerCase()
    if (!type) addIssue('error', location, `Node type ${proxy.name || index + 1} is empty.`, 'empty-proxy-type')
    for (const field of REQUIRED_PROXY_FIELDS[type] || ['server', 'port']) {
      if (isEmptyProxyField(proxy[field])) {
        addIssue('error', location, `${proxy.name || type || index + 1} must have field "${field}".`, 'missing-proxy-field')
      }
    }
    if (proxy.network) {
      if (!TRANSPORT_TYPES.includes(proxy.network)) {
        addIssue('error', location, `Network "${proxy.network}" is not recognized by the Mihomo transport editor.`, 'invalid-network')
      } else if (!isTransportSupportedByProxy(proxy, proxy.network)) {
        addIssue('error', location, `Network "${proxy.network}" is not valid for ${type}.`, 'invalid-network-for-proxy')
      }
      if (proxy.network === 'xhttp' && type !== 'vless') {
        addIssue('error', location, 'Transport xhttp is only valid for VLESS.', 'xhttp-non-vless')
      }
    }
    const port = Number(proxy.port)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      addIssue('error', `Node ${index + 1}`, `Node port ${proxy.name || proxy.server || index + 1} is invalid.`, 'invalid-port')
    }
  })

  normalizedModel.groups.forEach((group, index) => {
    if (!group.name) addIssue('error', `Group ${index + 1}`, 'Group name is empty.', 'empty-group-name')
    if (!groupTypes.includes(group.type)) addIssue('error', `Group ${group.name || index + 1}`, `Group type "${group.type}" is invalid.`, 'invalid-group-type')
    if (!group.proxies.length) addIssue('warning', `Group ${group.name || index + 1}`, 'Proxy list is empty.', 'empty-group-proxies')
    group.proxies.forEach((name) => {
      if (!proxyNames.has(name) && !groupNames.has(name) && !['DIRECT', 'REJECT'].includes(name)) {
        addIssue('warning', `Group ${group.name || index + 1}`, `Proxy/group reference "${name}" was not found.`, 'missing-group-reference')
      }
    })
    group.use.forEach((name) => {
      if (!proxyProviderNames.includes(name)) {
        addIssue('warning', `Group ${group.name || index + 1}`, `Proxy provider "${name}" was not found.`, 'missing-proxy-provider')
      }
    })
  })

  normalizedModel.ruleProviders.forEach((provider, index) => {
    const location = `Provider ${provider.name || index + 1}`
    if (!provider.name) addIssue('error', location, 'Provider name is empty.', 'empty-provider-name')
    if (!provider.url) addIssue('warning', location, 'Provider URL is empty.', 'empty-provider-url')
    if (!provider.path) addIssue('warning', location, 'Provider path is empty.', 'empty-provider-path')
    if (!['classical', 'domain', 'ipcidr'].includes(provider.behavior)) {
      addIssue('warning', location, `Behavior "${provider.behavior}" is uncommon for Mihomo.`, 'invalid-provider-behavior')
    }
  })

  if (duplicateProviders.length) {
    addIssue('error', 'Providers', `Duplicate rule provider names: ${[...new Set(duplicateProviders)].join(', ')}`, 'duplicate-provider-name')
  }

  normalizedModel.proxyProviders.forEach((provider, index) => {
    const location = `Proxy Provider ${provider.name || index + 1}`
    if (!provider.name) addIssue('error', location, 'Proxy provider name is empty.', 'empty-proxy-provider-name')
    if (provider.type === 'http' && !provider.url) addIssue('warning', location, 'Proxy provider URL is empty.', 'empty-proxy-provider-url')
    if (!provider.path) addIssue('warning', location, 'Proxy provider path is empty.', 'empty-proxy-provider-path')
  })

  if (duplicateProxyProviders.length) {
    addIssue('error', 'Proxy Providers', `Duplicate proxy provider names: ${[...new Set(duplicateProxyProviders)].join(', ')}`, 'duplicate-proxy-provider-name')
  }

  normalizedModel.rules.forEach((rule, index) => {
    const [type, name, target] = String(rule).split(',').map((part) => part.trim())
    if (type === 'MATCH' && index !== normalizedModel.rules.length - 1) {
      addIssue('warning', `Rule ${index + 1}`, 'MATCH should be the last rule so later rules remain reachable.', 'match-not-last')
    }
    if (type === 'RULE-SET' && name && !providerNames.includes(name)) {
      addIssue('warning', `Rule ${index + 1}`, `RULE-SET "${name}" has no rule provider.`, 'missing-rule-provider')
    }
    if (target && !groupNames.has(target) && !['DIRECT', 'REJECT', 'GLOBAL'].includes(target)) {
      addIssue('warning', `Rule ${index + 1}`, `Target policy "${target}" was not found.`, 'missing-rule-target')
    }
  })

  normalizedModel.tunnels.forEach((tunnel, index) => {
    if (!tunnel.address || !tunnel.target) addIssue('warning', `Tunnel ${index + 1}`, 'Tunnel address and target should be filled.', 'invalid-tunnel')
  })

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    issues,
  }
}

export function autoFixConfigModel(model) {
  const fixed = normalizeModel(model)
  const fixes: string[] = []

  fixed.proxies.forEach((proxy) => {
    const port = Number(proxy.port)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      proxy.port = defaultProxyPort(proxy.type)
      fixes.push(`Node port ${proxy.name || proxy.server || proxy.type} was set to ${proxy.port}.`)
    }
    if (!proxy.name) {
      proxy.name = `${proxy.type || 'proxy'}-${proxy.server || 'node'}`
      fixes.push('Empty node name was generated automatically.')
    }
  })
  makeUniqueNames(fixed.proxies)

  const enabledProxyNames = fixed.proxies.filter((proxy) => proxy.enabled !== false).map((proxy) => proxy.name)
  if (fixed.template === 'full' && fixed.groups.length === 0) {
    fixed.groups = buildDefaultGroups(enabledProxyNames)
    fixes.push('Default proxy group was rebuilt.')
  }

  const groupNames = () => fixed.groups.map((group) => group.name).filter(Boolean)
  fixed.groups.forEach((group) => {
    group.proxies = group.proxies.filter((name) =>
      enabledProxyNames.includes(name) || groupNames().includes(name) || ['DIRECT', 'REJECT'].includes(name),
    )
    if (!group.proxies.length) {
      group.proxies = enabledProxyNames.length ? [...enabledProxyNames] : ['DIRECT']
      fixes.push(`Proxy list for group ${group.name || 'PROXY'} was refilled.`)
    }
  })

  if (!fixed.rules.length) {
    fixed.rules = ['MATCH,PROXY']
    fixes.push('Empty rules were filled with MATCH,PROXY.')
  }

  fixed.ruleProviders.forEach((provider) => {
    if (!provider.path && provider.name) {
      provider.path = `./rules/${provider.name}.yaml`
      fixes.push(`Provider path ${provider.name} was generated automatically.`)
    }
  })
  makeUniqueProviderNames(fixed.ruleProviders)

  fixed.proxyProviders.forEach((provider) => {
    if (!provider.path && provider.name) {
      provider.path = `./proxy_providers/${provider.name}.yaml`
      fixes.push(`Proxy provider path ${provider.name} was generated automatically.`)
    }
  })
  makeUniqueProviderNames(fixed.proxyProviders, './proxy_providers')

  return { model: fixed, fixes }
}

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
    servername: data.sni || data.host,
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
  const name = cleanName(hash ? decodeText(hash) : 'ss')
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
      const [key, value] = parts[i].split('=')
      if (key) {
        opts[key] = value !== undefined ? decodeText(value) : true
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

  const params = new URLSearchParams(rawParams)
  return compact({
    name: cleanName(base64Param(params, 'remarks') || parts[0] || 'ssr'),
    type: 'ssr',
    server: required(parts[0], 'server'),
    port: toPort(parts[1]),
    cipher: required(parts[3], 'cipher'),
    password: required(tryBase64Decode(parts.slice(5).join(':')), 'password'),
    protocol: required(parts[2], 'protocol'),
    obfs: required(parts[4], 'obfs'),
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
    'auth-str': decodeText(url.username || params.get('auth-str') || params.get('auth_str') || params.get('auth') || ''),
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
    'private-key': required(decodeText(url.username), 'private-key'),
    'public-key': required(params.get('publickey'), 'public-key'),
    presharedKey: params.get('presharedkey') || undefined,
    mtu: numberParam(params.get('mtu')),
    udp: true,
    peers: [{
      server: url.hostname,
      port: toPort(url.port || 51820),
      'public-key': params.get('publickey'),
      presharedKey: params.get('presharedkey') || undefined,
      allowedIPs: params.get('allowedips')?.split(',') || undefined,
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

function buildRules(rulesPreset) {
  if (rulesPreset === 'lan-direct') {
    return [
      'IP-CIDR,10.0.0.0/8,DIRECT',
      'IP-CIDR,172.16.0.0/12,DIRECT',
      'IP-CIDR,192.168.0.0/16,DIRECT',
      'IP-CIDR,127.0.0.0/8,DIRECT',
      'IP-CIDR,169.254.0.0/16,DIRECT',
      'MATCH,PROXY',
    ]
  }

  if (rulesPreset === 'direct') return ['MATCH,DIRECT']
  return ['MATCH,PROXY']
}

function buildDefaultGroups(proxyNames) {
  return [
    {
      name: 'PROXY',
      type: 'select',
      proxies: ['DIRECT', ...proxyNames],
      url: '',
      interval: 300,
    },
  ]
}

function createGeneral() {
  return {
    port: 0,
    socksPort: 0,
    redirPort: 0,
    tproxyPort: 0,
    mixedPort: 7890,
    allowLan: false,
    bindAddress: '*',
    lanAllowedIps: [],
    lanDisallowedIps: [],
    authentication: [],
    skipAuthPrefixes: [],
    interfaceName: '',
    routingMark: 0,
    mode: 'rule',
    logLevel: 'info',
    ipv6: false,
    keepAliveIdle: 0,
    keepAliveInterval: 0,
    disableKeepAlive: false,
    findProcessMode: '',
    unifiedDelay: false,
    tcpConcurrent: false,
    externalController: '',
    externalControllerTls: '',
    externalControllerUnix: '',
    externalControllerPipe: '',
    externalControllerCors: '',
    externalUi: '',
    externalUiName: '',
    externalUiUrl: '',
    secret: '',
    globalClientFingerprint: '',
    globalUa: '',
    etagSupport: false,
    tlsCertificate: '',
    tlsPrivateKey: '',
    tlsCustom: {},
  }
}

function createProfile() {
  return {
    storeSelected: false,
    storeFakeIp: false,
  }
}

function createSniffer() {
  return {
    enable: false,
    overrideDestination: true,
    parsePureIp: false,
    forceDnsMapping: false,
    sniff: {
      TLS: { ports: [443, 8443] },
      HTTP: { ports: [80, '8080-8880'] },
      QUIC: { ports: [443, 8443] },
    },
    forceDomain: ['+.netflix.com', '+.youtube.com'],
    skipDomain: ['+.apple.com'],
    skipSrcAddress: [],
    skipDstAddress: [],
  }
}

function createTun() {
  return {
    enable: false,
    stack: 'mixed',
    device: '',
    autoRoute: true,
    autoRedirect: false,
    autoDetectInterface: true,
    strictRoute: false,
    dnsHijack: ['any:53'],
    mtu: 0,
    gso: false,
    gsoMaxSize: 0,
    udpTimeout: 0,
    iproute2TableIndex: 0,
    iproute2RuleIndex: 0,
    endpointIndependentNat: false,
    routeAddressSet: [],
    routeExcludeAddressSet: [],
    routeAddress: [],
    routeExcludeAddress: [],
    includeInterface: [],
    excludeInterface: [],
    includeUid: [],
    includeUidRange: [],
    excludeUid: [],
    excludeUidRange: [],
    includeAndroidUser: [],
    includePackage: [],
    excludePackage: [],
  }
}

function createNtp() {
  return {
    enable: false,
    writeToSystem: false,
    server: 'time.apple.com',
    port: 123,
    interval: 30,
  }
}

function createGeo() {
  return {
    geodataMode: false,
    geoAutoUpdate: false,
    geoUpdateInterval: 24,
    geoxUrl: {
      geoip: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat',
      geosite: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat',
      mmdb: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb',
      asn: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb',
    },
  }
}

function buildGeneralAdvanced(model) {
  const general = model.general
  const tls = compact({
    certificate: general.tlsCertificate || undefined,
    'private-key': general.tlsPrivateKey || undefined,
    ...normalizeObject(general.tlsCustom),
  })
  return compact({
    port: general.port || undefined,
    'socks-port': general.socksPort || undefined,
    'redir-port': general.redirPort || undefined,
    'tproxy-port': general.tproxyPort || undefined,
    'bind-address': general.allowLan ? general.bindAddress : undefined,
    'lan-allowed-ips': general.allowLan && general.lanAllowedIps.length ? general.lanAllowedIps : undefined,
    'lan-disallowed-ips': general.allowLan && general.lanDisallowedIps.length ? general.lanDisallowedIps : undefined,
    authentication: general.authentication.length ? general.authentication : undefined,
    'skip-auth-prefixes': general.skipAuthPrefixes.length ? general.skipAuthPrefixes : undefined,
    'keep-alive-idle': general.keepAliveIdle || undefined,
    'keep-alive-interval': general.keepAliveInterval || undefined,
    'disable-keep-alive': general.disableKeepAlive || undefined,
    'find-process-mode': general.findProcessMode || undefined,
    'interface-name': general.interfaceName || undefined,
    'routing-mark': general.routingMark || undefined,
    'unified-delay': general.unifiedDelay,
    'tcp-concurrent': general.tcpConcurrent,
    'external-controller': general.externalController || undefined,
    'external-controller-tls': general.externalControllerTls || undefined,
    'external-controller-unix': general.externalControllerUnix || undefined,
    'external-controller-pipe': general.externalControllerPipe || undefined,
    'external-controller-cors': general.externalControllerCors || undefined,
    'external-ui': general.externalUi || undefined,
    'external-ui-name': general.externalUiName || undefined,
    'external-ui-url': general.externalUiUrl || undefined,
    secret: general.secret || undefined,
    tls: Object.keys(tls).length ? tls : undefined,
    'global-client-fingerprint': general.globalClientFingerprint || undefined,
    'global-ua': general.globalUa || undefined,
    'etag-support': general.etagSupport || undefined,
  })
}

function buildProfile(profile) {
  if (!profile.storeSelected && !profile.storeFakeIp) return {}
  return {
    profile: {
      'store-selected': profile.storeSelected,
      'store-fake-ip': profile.storeFakeIp,
    },
  }
}

function buildGeo(geo) {
  return compact({
    'geodata-mode': geo.geodataMode,
    'geo-auto-update': geo.geoAutoUpdate,
    'geo-update-interval': geo.geoUpdateInterval,
    'geox-url': geo.geodataMode || geo.geoAutoUpdate ? geo.geoxUrl : undefined,
  })
}

function buildDns(dns) {
  return compact({
    enable: dns.enable,
    'cache-algorithm': dns.cacheAlgorithm || undefined,
    'prefer-h3': dns.preferH3 || undefined,
    'use-hosts': dns.useHosts || undefined,
    'use-system-hosts': dns.useSystemHosts || undefined,
    'respect-rules': dns.respectRules || undefined,
    listen: dns.listen,
    ipv6: dns.ipv6 || false,
    'enhanced-mode': dns.enhancedMode,
    'fake-ip-range': dns.enhancedMode === 'fake-ip' ? dns.fakeIpRange : undefined,
    'fake-ip-range6': dns.enhancedMode === 'fake-ip' ? dns.fakeIpRange6 : undefined,
    'fake-ip-filter-mode': dns.enhancedMode === 'fake-ip' ? dns.fakeIpFilterMode : undefined,
    'fake-ip-filter': dns.enhancedMode === 'fake-ip' ? dns.fakeIpFilter : undefined,
    'fake-ip-ttl': dns.enhancedMode === 'fake-ip' && dns.fakeIpTtl ? dns.fakeIpTtl : undefined,
    'default-nameserver': dns.defaultNameserver,
    nameserver: dns.nameserver,
    fallback: dns.fallback,
    'fallback-filter': dns.fallbackFilter,
    'direct-nameserver': dns.directNameserver.length ? dns.directNameserver : undefined,
    'direct-nameserver-follow-policy': dns.directNameserverFollowPolicy || undefined,
    'proxy-server-nameserver': dns.proxyServerNameserver,
    'proxy-server-nameserver-policy': dns.proxyServerNameserverPolicy,
    'nameserver-policy': dns.nameserverPolicy,
  })
}

function buildSniffer(sniffer, rawSniffer) {
  const raw = normalizeRawSection(rawSniffer)
  if (raw) return { sniffer: raw }
  if (!sniffer.enable) return {}
  return {
    sniffer: compact({
      enable: true,
      'override-destination': sniffer.overrideDestination,
      'parse-pure-ip': sniffer.parsePureIp,
      'force-dns-mapping': sniffer.forceDnsMapping,
      sniff: normalizeSniffConfig(sniffer.sniff),
      'force-domain': sniffer.forceDomain,
      'skip-domain': sniffer.skipDomain,
      'skip-src-address': sniffer.skipSrcAddress,
      'skip-dst-address': sniffer.skipDstAddress,
    }),
  }
}

function buildTun(tun, rawTun) {
  const raw = normalizeRawSection(rawTun)
  if (raw) return { tun: raw }
  if (!tun.enable) return {}
  return {
    tun: compact({
      enable: true,
      stack: tun.stack,
      device: tun.device || undefined,
      'auto-route': tun.autoRoute,
      'auto-redirect': tun.autoRedirect || undefined,
      'auto-detect-interface': tun.autoDetectInterface,
      'strict-route': tun.strictRoute,
      'dns-hijack': tun.dnsHijack,
      mtu: tun.mtu || undefined,
      gso: tun.gso || undefined,
      'gso-max-size': tun.gsoMaxSize || undefined,
      'udp-timeout': tun.udpTimeout || undefined,
      'iproute2-table-index': tun.iproute2TableIndex || undefined,
      'iproute2-rule-index': tun.iproute2RuleIndex || undefined,
      'endpoint-independent-nat': tun.endpointIndependentNat || undefined,
      'route-address-set': tun.routeAddressSet.length ? tun.routeAddressSet : undefined,
      'route-exclude-address-set': tun.routeExcludeAddressSet.length ? tun.routeExcludeAddressSet : undefined,
      'route-address': tun.routeAddress.length ? tun.routeAddress : undefined,
      'route-exclude-address': tun.routeExcludeAddress.length ? tun.routeExcludeAddress : undefined,
      'include-interface': tun.includeInterface.length ? tun.includeInterface : undefined,
      'exclude-interface': tun.excludeInterface.length ? tun.excludeInterface : undefined,
      'include-uid': tun.includeUid.length ? tun.includeUid : undefined,
      'include-uid-range': tun.includeUidRange.length ? tun.includeUidRange : undefined,
      'exclude-uid': tun.excludeUid.length ? tun.excludeUid : undefined,
      'exclude-uid-range': tun.excludeUidRange.length ? tun.excludeUidRange : undefined,
      'include-android-user': tun.includeAndroidUser.length ? tun.includeAndroidUser : undefined,
      'include-package': tun.includePackage.length ? tun.includePackage : undefined,
      'exclude-package': tun.excludePackage.length ? tun.excludePackage : undefined,
    }),
  }
}

function buildNtp(ntp, rawNtp) {
  const raw = normalizeRawSection(rawNtp)
  if (raw) return { ntp: raw }
  if (!ntp.enable) return {}
  const config = compact({
    enable: true,
    server: ntp.server || undefined,
    port: ntp.port || undefined,
    interval: ntp.interval || undefined,
    'write-to-system': ntp.writeToSystem || undefined,
  })
  return Object.keys(config).length ? { ntp: config } : {}
}

function buildExperimental(experimental, rawExperimental) {
  const raw = normalizeRawSection(rawExperimental)
  if (raw) return { experimental: raw }
  return Object.keys(experimental).length ? { experimental } : {}
}

function buildRuleProviders(ruleProviders) {
  const providers = Object.fromEntries(
    ruleProviders
      .filter((provider) => provider.name)
      .map((provider) => [
        provider.name,
        compact({
          type: provider.type,
          behavior: provider.behavior,
          path: provider.path,
          url: provider.url,
          interval: provider.interval,
          proxy: provider.proxy || undefined,
          format: provider.format || undefined,
          'size-limit': provider.sizeLimit || undefined,
          header: provider.header,
          payload: provider.payload,
        }),
      ]),
  )
  return Object.keys(providers).length ? { 'rule-providers': providers } : {}
}

function buildProxyProviders(proxyProviders) {
  const providers = Object.fromEntries(
    proxyProviders
      .filter((provider) => provider.name)
      .map((provider) => [
        provider.name,
        compact({
          type: provider.type,
          url: provider.url,
          path: provider.path,
          interval: provider.interval,
          proxy: provider.proxy || undefined,
          'size-limit': provider.sizeLimit || undefined,
          header: provider.header,
          'health-check': provider.healthCheck.enable ? compact({
            enable: true,
            url: provider.healthCheck.url,
            interval: provider.healthCheck.interval,
            timeout: provider.healthCheck.timeout,
            lazy: provider.healthCheck.lazy,
            'expected-status': provider.healthCheck.expectedStatus || undefined,
          }) : undefined,
          override: provider.override,
          filter: provider.filter || undefined,
          'exclude-filter': provider.excludeFilter || undefined,
          'exclude-type': provider.excludeType || undefined,
          payload: provider.payload,
        }),
      ]),
  )
  return Object.keys(providers).length ? { 'proxy-providers': providers } : {}
}

function buildListeners(listeners) {
  return listeners.length ? { listeners } : {}
}

function buildSubRules(subRules) {
  return Object.keys(subRules).length ? { 'sub-rules': subRules } : {}
}

function buildTunnels(tunnels) {
  return tunnels.length ? { tunnels } : {}
}

function parseSniffList(items) {
  return Object.fromEntries(
    normalizeList(items, []).map((item) => {
      const [protocol, ports = ''] = item.split(':')
      return [protocol, normalizeSniffProtocol({ ports })]
    }).filter(([protocol, config]) => protocol && (config as any).ports?.length),
  )
}

function normalizeSniffConfig(value, fallback = {}) {
  if (Array.isArray(value) || typeof value === 'string') return parseSniffList(value)
  if (!value || typeof value !== 'object') return fallback
  return Object.fromEntries(
    Object.entries(value)
      .map(([protocol, config]) => [String(protocol).toUpperCase(), normalizeSniffProtocol(config)])
      .filter(([protocol, config]) => protocol && (config as any).ports?.length),
  )
}

function normalizeSniffProtocol(value) {
  const config = value && typeof value === 'object' && !Array.isArray(value) ? value : { ports: value }
  return compact({
    ports: normalizePorts(config.ports),
    'override-destination': config.overrideDestination ?? config['override-destination'],
  })
}

function hasSniffProtocols(value) {
  return Object.keys(normalizeSniffConfig(value)).length > 0
}

function normalizePorts(value) {
  const items = Array.isArray(value) ? value : String(value || '').split(',')
  return items
    .map((item) => String(item).trim())
    .filter(Boolean)
    .map((item) => (item.includes('-') ? item : Number(item) || item))
}

function buildProxyGroups(model, proxies) {
  const proxyNames = proxies.map((proxy) => proxy.name)
  const groupNames = model.groups.map((group) => group.name)
  const specialNames = ['DIRECT', 'REJECT', ...groupNames]

  return model.groups.map((group) => {
    const type = groupTypes.includes(group.type) ? group.type : 'select'
    const names = Array.isArray(group.proxies) && group.proxies.length > 0 ? group.proxies : proxyNames
    const filteredNames = names.filter((name) => proxyNames.includes(name) || specialNames.includes(name) || name === 'AUTO')
    const normalizedGroup: ProxyNode = {
      name: group.name || 'PROXY',
      type,
      proxies: filteredNames.length ? filteredNames : ['DIRECT'],
      use: group.use.length ? group.use : undefined,
      'include-all': group.includeAll || undefined,
      'include-all-proxies': group.includeAllProxies || undefined,
      'include-all-providers': group.includeAllProviders || undefined,
      lazy: group.lazy || undefined,
      timeout: group.timeout || undefined,
      'max-failed-times': group.maxFailedTimes || undefined,
      'disable-udp': group.disableUdp || undefined,
      'interface-name': group.interfaceName || undefined,
      'routing-mark': group.routingMark || undefined,
      filter: group.filter || undefined,
      'exclude-filter': group.excludeFilter || undefined,
      'exclude-type': group.excludeType || undefined,
      'expected-status': group.expectedStatus || undefined,
      hidden: group.hidden || undefined,
      icon: group.icon || undefined,
    }

    if (type !== 'select') {
      normalizedGroup.url = group.url || 'http://www.gstatic.com/generate_204'
      normalizedGroup.interval = Number(group.interval) || 300
    }

    return normalizedGroup
  })
}

function dumpYaml(value, indent = 0) {
  const pad = ' '.repeat(indent)

  if (Array.isArray(value)) {
    if (value.length === 0) return `${pad}[]`
    return value
      .map((item) => {
        if (isScalar(item)) return `${pad}- ${formatScalar(item, indent)}`
        return `${pad}-\n${dumpYaml(item, indent + 2)}`
      })
      .join('\n')
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value).filter(([, entryValue]) => entryValue !== undefined)
    if (entries.length === 0) return `${pad}{}`
    return entries
      .map(([key, entryValue]) => {
        const formattedKey = formatKey(key)
        if (isScalar(entryValue)) return `${pad}${formattedKey}: ${formatScalar(entryValue, indent)}`
        return `${pad}${formattedKey}:\n${dumpYaml(entryValue, indent + 2)}`
      })
      .join('\n')
  }

  return `${pad}${formatScalar(value, indent)}`
}

function spaceTopLevelSections(yaml) {
  const sectionKeys = new Set(['dns', 'sniffer', 'tun', 'ntp', 'experimental', 'proxies', 'proxy-providers', 'proxy-groups', 'listeners', 'rule-providers', 'sub-rules', 'tunnels', 'rules'])
  const lines = String(yaml).split('\n')
  const spaced: string[] = []

  lines.forEach((line, index) => {
    const key = line.match(/^([A-Za-z0-9_-]+):/)?.[1]
    if (index > 0 && key && sectionKeys.has(key) && spaced.at(-1) !== '') spaced.push('')
    spaced.push(line)
  })

  return spaced.join('\n')
}

function formatKey(key) {
  if (/^[a-zA-Z0-9_-]+$/.test(key)) return key
  return JSON.stringify(key)
}

function formatScalar(value, indent = 0) {
  if (value === null) return 'null'
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  const str = String(value)
  if (str.includes('\n')) {
    const scalarPad = ' '.repeat(indent + 2)
    return '|\n' + str.split(/\r?\n/).map(line => scalarPad + line).join('\n')
  }
  return JSON.stringify(str)
}

function isScalar(value) {
  return value === null || ['string', 'number', 'boolean'].includes(typeof value)
}

function isEmptyProxyField(value) {
  if (value === undefined || value === null) return true
  if (typeof value === 'string' && value.trim() === '') return true
  if (Array.isArray(value) && value.length === 0) return true
  return false
}

function makeUniqueNames(proxies) {
  const seen = new Map()
  for (const proxy of proxies) {
    const base = proxy.name || `${proxy.type}-${proxy.server}`
    const count = seen.get(base) || 0
    seen.set(base, count + 1)
    proxy.name = count === 0 ? base : `${base} ${count + 1}`
  }
}

function applyNamePattern(proxies, namePattern) {
  if (!namePattern || namePattern === '{name}') return

  proxies.forEach((proxy, index) => {
    const originalName = proxy.name || proxy.server || proxy.type
    const number = String(index + 1)
    const paddedNumber = number.padStart(2, '0')
    const formatted = namePattern
      .replaceAll('{name}', originalName)
      .replaceAll('{type}', proxy.type || '')
      .replaceAll('{server}', proxy.server || '')
      .replaceAll('{port}', proxy.port ? String(proxy.port) : '')
      .replaceAll('{n}', number)
      .replaceAll('{nn}', paddedNumber)
      .replace(/\s+/g, ' ')
      .trim()

    proxy.name = formatted || originalName
  })
}

function legacyNamePattern(options) {
  const namePrefix = String(options.namePrefix || '').trim()
  if (!namePrefix) return ''
  return `${namePrefix} - {name}`
}

function normalizeNamePattern(value) {
  const pattern = String(value || '').trim()
  if (!pattern) return '{name}'
  const hasKnownPlaceholder = ['{name}', '{type}', '{server}', '{port}', '{n}', '{nn}'].some((placeholder) =>
    pattern.includes(placeholder),
  )
  if (hasKnownPlaceholder) return pattern
  return `${pattern} - {name}`
}

function normalizeOptions(options) {
  const template = outputTemplates.includes(options.template) ? options.template : 'full'
  const rulesPreset = rulesPresets.includes(options.rulesPreset) ? options.rulesPreset : 'proxy'
  const namePattern = normalizeNamePattern(options.namePattern || legacyNamePattern(options))

  return {
    template,
    rulesPreset,
    namePattern,
  }
}

function normalizeModel(model) {
  const normalizedOptions = normalizeOptions(model || {})
  return {
    template: normalizedOptions.template,
    rulesPreset: normalizedOptions.rulesPreset,
    general: normalizeGeneral(model?.general),
    profile: normalizeProfile(model?.profile),
    dns: normalizeDns(model?.dns),
    sniffer: normalizeSniffer(model?.sniffer),
    tun: normalizeTun(model?.tun),
    ntp: normalizeNtp(model?.ntp),
    experimental: normalizeObject(model?.experimental),
    geo: normalizeGeo(model?.geo),
    ruleProviders: Array.isArray(model?.ruleProviders) ? model.ruleProviders.map(normalizeRuleProvider) : [],
    proxyProviders: Array.isArray(model?.proxyProviders) ? model.proxyProviders.map(normalizeProxyProvider) : [],
    listeners: Array.isArray(model?.listeners) ? model.listeners.filter((listener) => listener && typeof listener === 'object') : [],
    subRules: normalizeSubRules(model?.subRules || model?.['sub-rules']),
    tunnels: Array.isArray(model?.tunnels) ? model.tunnels.map(normalizeTunnel) : [],
    extraTopLevel: model?.extraTopLevel && typeof model.extraTopLevel === 'object' && !Array.isArray(model.extraTopLevel) ? model.extraTopLevel : {},
    rawSections: normalizeRawSections(model?.rawSections),
    proxies: Array.isArray(model?.proxies) ? model.proxies.map((proxy) => ({ ...proxy })) : [],
    groups: Array.isArray(model?.groups) ? model.groups.map(normalizeGroup) : [],
    rules: Array.isArray(model?.rules) ? model.rules.map((rule) => String(rule).trim()).filter(Boolean) : [],
  }
}

function normalizeDns(dns: ProxyNode = {}) {
  const defaults = createConfigModel([]).dns
  return {
    enable: dns.enable !== false,
    listen: String(dns.listen || '0.0.0.0:1053').trim(),
    ipv6: Boolean(dns.ipv6),
    cacheAlgorithm: ['lru', 'arc'].includes(dns.cacheAlgorithm || dns['cache-algorithm']) ? dns.cacheAlgorithm || dns['cache-algorithm'] : '',
    preferH3: Boolean(dns.preferH3 ?? dns['prefer-h3']),
    useHosts: Boolean(dns.useHosts ?? dns['use-hosts']),
    useSystemHosts: Boolean(dns.useSystemHosts ?? dns['use-system-hosts']),
    respectRules: Boolean(dns.respectRules ?? dns['respect-rules']),
    enhancedMode: ['fake-ip', 'redir-host'].includes(dns.enhancedMode) ? dns.enhancedMode : 'redir-host',
    fakeIpRange: String(dns.fakeIpRange || '198.18.0.1/16').trim(),
    fakeIpRange6: String(dns.fakeIpRange6 || dns['fake-ip-range6'] || '').trim(),
    fakeIpFilterMode: ['blacklist', 'whitelist', 'rule'].includes(dns.fakeIpFilterMode || dns['fake-ip-filter-mode']) ? dns.fakeIpFilterMode || dns['fake-ip-filter-mode'] : '',
    fakeIpTtl: Number(dns.fakeIpTtl || dns['fake-ip-ttl']) || 0,
    fakeIpFilter: normalizeList(dns.fakeIpFilter, defaults.fakeIpFilter),
    defaultNameserver: normalizeList(dns.defaultNameserver || dns['default-nameserver'], ['1.1.1.1', '8.8.8.8']),
    nameserver: normalizeList(dns.nameserver, ['https://dns.google/dns-query', 'https://cloudflare-dns.com/dns-query']),
    fallback: normalizeList(dns.fallback, []),
    fallbackFilter: normalizePolicy(dns.fallbackFilter || dns['fallback-filter']),
    directNameserver: normalizeList(dns.directNameserver || dns['direct-nameserver'], []),
    directNameserverFollowPolicy: Boolean(dns.directNameserverFollowPolicy ?? dns['direct-nameserver-follow-policy']),
    proxyServerNameserver: normalizeList(dns.proxyServerNameserver || dns['proxy-server-nameserver'], []),
    proxyServerNameserverPolicy: normalizePolicy(dns.proxyServerNameserverPolicy || dns['proxy-server-nameserver-policy']),
    nameserverPolicy: normalizePolicy(dns.nameserverPolicy || dns['nameserver-policy']),
  }
}

function normalizeGeneral(general: ProxyNode = {}) {
  const defaults = createGeneral()
  return {
    ...defaults,
    ...general,
    port: Number(general.port) || 0,
    socksPort: Number(general.socksPort || general['socks-port']) || 0,
    redirPort: Number(general.redirPort || general['redir-port']) || 0,
    tproxyPort: Number(general.tproxyPort || general['tproxy-port']) || 0,
    mixedPort: Number(general.mixedPort || general['mixed-port']) || 7890,
    allowLan: Boolean(general.allowLan ?? general['allow-lan'] ?? defaults.allowLan),
    bindAddress: String(general.bindAddress || general['bind-address'] || '*').trim(),
    lanAllowedIps: normalizeList(general.lanAllowedIps || general['lan-allowed-ips'], []),
    lanDisallowedIps: normalizeList(general.lanDisallowedIps || general['lan-disallowed-ips'], []),
    authentication: normalizeList(general.authentication, []),
    skipAuthPrefixes: normalizeList(general.skipAuthPrefixes || general['skip-auth-prefixes'], []),
    interfaceName: String(general.interfaceName || general['interface-name'] || '').trim(),
    routingMark: Number(general.routingMark || general['routing-mark']) || 0,
    mode: String(general.mode || 'rule').trim(),
    logLevel: String(general.logLevel || general['log-level'] || 'info').trim(),
    ipv6: Boolean(general.ipv6),
    keepAliveIdle: Number(general.keepAliveIdle || general['keep-alive-idle']) || 0,
    keepAliveInterval: Number(general.keepAliveInterval || general['keep-alive-interval']) || 0,
    disableKeepAlive: Boolean(general.disableKeepAlive ?? general['disable-keep-alive']),
    findProcessMode: ['always', 'strict', 'off'].includes(general.findProcessMode || general['find-process-mode']) ? general.findProcessMode || general['find-process-mode'] : '',
    unifiedDelay: Boolean(general.unifiedDelay ?? general['unified-delay'] ?? defaults.unifiedDelay),
    tcpConcurrent: Boolean(general.tcpConcurrent ?? general['tcp-concurrent'] ?? defaults.tcpConcurrent),
    externalController: String(general.externalController || general['external-controller'] || '').trim(),
    externalControllerTls: String(general.externalControllerTls || general['external-controller-tls'] || '').trim(),
    externalControllerUnix: String(general.externalControllerUnix || general['external-controller-unix'] || '').trim(),
    externalControllerPipe: String(general.externalControllerPipe || general['external-controller-pipe'] || '').trim(),
    externalControllerCors: String(general.externalControllerCors || general['external-controller-cors'] || '').trim(),
    externalUi: String(general.externalUi || general['external-ui'] || '').trim(),
    externalUiName: String(general.externalUiName || general['external-ui-name'] || '').trim(),
    externalUiUrl: String(general.externalUiUrl || general['external-ui-url'] || '').trim(),
    secret: String(general.secret || '').trim(),
    globalClientFingerprint: String(general.globalClientFingerprint || general['global-client-fingerprint'] || '').trim(),
    globalUa: String(general.globalUa || general['global-ua'] || '').trim(),
    etagSupport: Boolean(general.etagSupport ?? general['etag-support']),
    tlsCertificate: String(general.tlsCertificate || general.tls?.certificate || '').trim(),
    tlsPrivateKey: String(general.tlsPrivateKey || general.tls?.['private-key'] || '').trim(),
    tlsCustom: normalizeObject(general.tlsCustom || {}),
  }
}

function normalizeProfile(profile: ProxyNode = {}) {
  return {
    storeSelected: Boolean(profile.storeSelected ?? profile['store-selected'] ?? createProfile().storeSelected),
    storeFakeIp: Boolean(profile.storeFakeIp ?? profile['store-fake-ip'] ?? createProfile().storeFakeIp),
  }
}

function normalizeSniffer(sniffer: ProxyNode = {}) {
  const defaults = createSniffer()
  return {
    enable: Boolean(sniffer.enable),
    overrideDestination: sniffer.overrideDestination ?? sniffer['override-destination'] ?? defaults.overrideDestination,
    parsePureIp: Boolean(sniffer.parsePureIp ?? sniffer['parse-pure-ip']),
    forceDnsMapping: Boolean(sniffer.forceDnsMapping ?? sniffer['force-dns-mapping']),
    sniff: normalizeSniffConfig(sniffer.sniff, defaults.sniff),
    forceDomain: normalizeList(sniffer.forceDomain || sniffer['force-domain'], defaults.forceDomain),
    skipDomain: normalizeList(sniffer.skipDomain || sniffer['skip-domain'], defaults.skipDomain),
    skipSrcAddress: normalizeList(sniffer.skipSrcAddress || sniffer['skip-src-address'], []),
    skipDstAddress: normalizeList(sniffer.skipDstAddress || sniffer['skip-dst-address'], []),
  }
}

function normalizeTun(tun: ProxyNode = {}) {
  const defaults = createTun()
  return {
    enable: Boolean(tun.enable),
    stack: String(tun.stack || defaults.stack).trim(),
    device: String(tun.device || '').trim(),
    autoRoute: tun.autoRoute ?? tun['auto-route'] ?? defaults.autoRoute,
    autoRedirect: Boolean(tun.autoRedirect ?? tun['auto-redirect']),
    autoDetectInterface: tun.autoDetectInterface ?? tun['auto-detect-interface'] ?? defaults.autoDetectInterface,
    strictRoute: Boolean(tun.strictRoute ?? tun['strict-route']),
    dnsHijack: normalizeList(tun.dnsHijack || tun['dns-hijack'], defaults.dnsHijack),
    mtu: Number(tun.mtu) || 0,
    gso: Boolean(tun.gso),
    gsoMaxSize: Number(tun.gsoMaxSize || tun['gso-max-size']) || 0,
    udpTimeout: Number(tun.udpTimeout || tun['udp-timeout']) || 0,
    iproute2TableIndex: Number(tun.iproute2TableIndex || tun['iproute2-table-index']) || 0,
    iproute2RuleIndex: Number(tun.iproute2RuleIndex || tun['iproute2-rule-index']) || 0,
    endpointIndependentNat: Boolean(tun.endpointIndependentNat ?? tun['endpoint-independent-nat']),
    routeAddressSet: normalizeList(tun.routeAddressSet || tun['route-address-set'], []),
    routeExcludeAddressSet: normalizeList(tun.routeExcludeAddressSet || tun['route-exclude-address-set'], []),
    routeAddress: normalizeList(tun.routeAddress || tun['route-address'], []),
    routeExcludeAddress: normalizeList(tun.routeExcludeAddress || tun['route-exclude-address'], []),
    includeInterface: normalizeList(tun.includeInterface || tun['include-interface'], []),
    excludeInterface: normalizeList(tun.excludeInterface || tun['exclude-interface'], []),
    includeUid: normalizeList(tun.includeUid || tun['include-uid'], []),
    includeUidRange: normalizeList(tun.includeUidRange || tun['include-uid-range'], []),
    excludeUid: normalizeList(tun.excludeUid || tun['exclude-uid'], []),
    excludeUidRange: normalizeList(tun.excludeUidRange || tun['exclude-uid-range'], []),
    includeAndroidUser: normalizeList(tun.includeAndroidUser || tun['include-android-user'], []),
    includePackage: normalizeList(tun.includePackage || tun['include-package'], []),
    excludePackage: normalizeList(tun.excludePackage || tun['exclude-package'], []),
  }
}

function normalizeNtp(ntp: ProxyNode = {}) {
  const defaults = createNtp()
  return {
    enable: Boolean(ntp.enable),
    writeToSystem: Boolean(ntp.writeToSystem ?? ntp['write-to-system']),
    server: String(ntp.server || defaults.server).trim(),
    port: Number(ntp.port) || defaults.port,
    interval: Number(ntp.interval) || defaults.interval,
  }
}

function normalizeObject(value: ProxyNode = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  return { ...value }
}

function normalizeRawSections(value: ProxyNode = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  return Object.fromEntries(
    Object.entries(value)
      .map(([key, section]) => [key, normalizeRawSection(section)])
      .filter(([, section]) => section),
  )
}

function normalizeRawSection(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined
  const normalized = { ...value }
  return Object.keys(normalized).length ? normalized : undefined
}

function normalizeGeo(geo: ProxyNode = {}) {
  return {
    ...createGeo(),
    ...geo,
    geodataMode: Boolean(geo.geodataMode ?? geo['geodata-mode'] ?? createGeo().geodataMode),
    geoAutoUpdate: Boolean(geo.geoAutoUpdate ?? geo['geo-auto-update'] ?? createGeo().geoAutoUpdate),
    geoUpdateInterval: Number(geo.geoUpdateInterval || geo['geo-update-interval']) || 24,
    geoxUrl: {
      ...createGeo().geoxUrl,
      ...(geo.geoxUrl || geo['geox-url'] || {}),
    },
  }
}

function normalizeRuleProvider(provider: ProxyNode = {}) {
  return {
    name: String(provider.name || '').trim(),
    type: String(provider.type || 'http').trim(),
    behavior: String(provider.behavior || 'classical').trim(),
    path: String(provider.path || '').trim(),
    url: String(provider.url || '').trim(),
    target: String(provider.target || 'PROXY').trim(),
    interval: Number(provider.interval) || 86400,
    proxy: String(provider.proxy || '').trim(),
    format: ['yaml', 'text', 'mrs'].includes(provider.format) ? provider.format : '',
    sizeLimit: Number(provider.sizeLimit || provider['size-limit']) || 0,
    header: normalizePolicy(provider.header),
    payload: normalizeList(provider.payload, []),
  }
}

function normalizeProxyProvider(provider: ProxyNode = {}) {
  return {
    name: String(provider.name || '').trim(),
    type: ['http', 'file', 'inline'].includes(provider.type) ? provider.type : 'http',
    url: String(provider.url || '').trim(),
    path: String(provider.path || '').trim(),
    interval: Number(provider.interval) || 3600,
    proxy: String(provider.proxy || '').trim(),
    sizeLimit: Number(provider.sizeLimit || provider['size-limit']) || 0,
    header: normalizePolicy(provider.header),
    healthCheck: {
      enable: Boolean(provider.healthCheck?.enable || provider['health-check']?.enable),
      url: String(provider.healthCheck?.url || provider['health-check']?.url || 'https://www.gstatic.com/generate_204').trim(),
      interval: Number(provider.healthCheck?.interval || provider['health-check']?.interval) || 300,
      timeout: Number(provider.healthCheck?.timeout || provider['health-check']?.timeout) || 5000,
      lazy: provider.healthCheck?.lazy ?? provider['health-check']?.lazy ?? true,
      expectedStatus: String(provider.healthCheck?.expectedStatus || provider['health-check']?.['expected-status'] || '').trim(),
    },
    override: normalizePolicy(provider.override),
    filter: String(provider.filter || '').trim(),
    excludeFilter: String(provider.excludeFilter || provider['exclude-filter'] || '').trim(),
    excludeType: String(provider.excludeType || provider['exclude-type'] || '').trim(),
    payload: Array.isArray(provider.payload) ? provider.payload : [],
  }
}

function normalizeGroup(group: ProxyNode = {}) {
  return {
    name: String(group.name || 'PROXY').trim(),
    type: groupTypes.includes(group.type) ? group.type : 'select',
    proxies: normalizeList(group.proxies, []),
    use: normalizeList(group.use, []),
    url: String(group.url || '').trim(),
    interval: Number(group.interval) || 300,
    includeAll: Boolean(group.includeAll || group['include-all']),
    includeAllProxies: Boolean(group.includeAllProxies || group['include-all-proxies']),
    includeAllProviders: Boolean(group.includeAllProviders || group['include-all-providers']),
    lazy: group.lazy === undefined ? undefined : Boolean(group.lazy),
    timeout: Number(group.timeout) || 0,
    maxFailedTimes: Number(group.maxFailedTimes || group['max-failed-times']) || 0,
    disableUdp: Boolean(group.disableUdp || group['disable-udp']),
    interfaceName: String(group.interfaceName || group['interface-name'] || '').trim(),
    routingMark: Number(group.routingMark || group['routing-mark']) || 0,
    filter: String(group.filter || '').trim(),
    excludeFilter: String(group.excludeFilter || group['exclude-filter'] || '').trim(),
    excludeType: String(group.excludeType || group['exclude-type'] || '').trim(),
    expectedStatus: String(group.expectedStatus || group['expected-status'] || '').trim(),
    hidden: Boolean(group.hidden),
    icon: String(group.icon || '').trim(),
  }
}

function normalizeTunnel(tunnel: ProxyNode = {}) {
  return compact({
    network: normalizeList(tunnel.network, ['tcp', 'udp']),
    address: String(tunnel.address || '').trim(),
    target: String(tunnel.target || '').trim(),
    proxy: String(tunnel.proxy || '').trim() || undefined,
  })
}

function normalizeSubRules(value = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  return Object.fromEntries(
    Object.entries(value)
      .map(([key, rules]) => [String(key).trim(), normalizeList(rules, [])])
      .filter(([key, rules]) => key && rules.length),
  )
}

function normalizeList(value, fallback) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean)
  if (typeof value === 'string') return value.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean)
  return fallback
}

function normalizePolicy(value = {}) {
  if (typeof value === 'string') {
    return Object.fromEntries(
      value
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
          const [key, ...rest] = line.split('=')
          return [key.trim(), rest.join('=').split(',').map((item) => item.trim()).filter(Boolean)]
        }),
    )
  }
  return value && typeof value === 'object' ? value : {}
}

function stripUiProxyFields(proxy) {
  const cleanProxy = { ...proxy }
  delete cleanProxy.id
  delete cleanProxy.enabled
  delete cleanProxy.rawJson

  if (cleanProxy.network && !TRANSPORT_TYPES.includes(cleanProxy.network)) delete cleanProxy.network
  if (cleanProxy.network && !isTransportSupportedByProxy(cleanProxy, cleanProxy.network)) delete cleanProxy.network

  if (cleanProxy.network !== 'ws') delete cleanProxy['ws-opts']
  if (cleanProxy.network !== 'grpc') delete cleanProxy['grpc-opts']
  if (cleanProxy.network !== 'h2') delete cleanProxy['h2-opts']
  if (cleanProxy.network !== 'http') delete cleanProxy['http-opts']
  delete cleanProxy['httpupgrade-opts']
  if (cleanProxy.network !== 'xhttp') delete cleanProxy['xhttp-opts']
  if (cleanProxy.network === 'ws') {
    cleanProxy['ws-opts'] = {
      ...(cleanProxy['ws-opts'] || {}),
      'v2ray-http-upgrade': Boolean(cleanProxy['ws-opts']?.['v2ray-http-upgrade']),
      'v2ray-http-upgrade-fast-open': Boolean(cleanProxy['ws-opts']?.['v2ray-http-upgrade-fast-open']),
    }
  }
  if (cleanProxy.network === 'xhttp') applyXhttpDefaults(cleanProxy)
  cleanupUnsupportedTlsOptions(cleanProxy)

  return cleanProxy
}

function cleanupUnsupportedTlsOptions(proxy) {
  const type = String(proxy.type || '').toLowerCase()
  const fields = new Set(TLS_FIELDS_BY_PROXY[type] || [])
  if (!TLS_FLAG_PROXY_TYPES.has(type)) delete proxy.tls
  if (!fields.has('sni')) {
    delete proxy.sni
    delete proxy.servername
  }
  if (!fields.has('alpn') && proxy.network !== 'xhttp') delete proxy.alpn
  if (!fields.has('client-fingerprint')) delete proxy['client-fingerprint']
  if (!fields.has('fingerprint')) delete proxy.fingerprint
  if (!fields.has('skip-cert-verify')) delete proxy['skip-cert-verify']
  if (!fields.has('certificate')) delete proxy.certificate
  if (!fields.has('private-key') && !PROXY_PRIVATE_KEY_TYPES.has(type)) delete proxy['private-key']
  if (!fields.has('reality')) delete proxy['reality-opts']
  if (!fields.has('ech')) delete proxy['ech-opts']
}

function finalizeProxyTransport(proxy) {
  if (proxy.network && !isTransportSupportedByProxy(proxy, proxy.network)) {
    delete proxy.network
    cleanupProxyTransportOptions(proxy)
    return proxy
  }

  if (proxy.network === 'xhttp') applyXhttpDefaults(proxy)
  return proxy
}

function isTransportSupportedByProxy(proxy, network) {
  if (!network) return true
  const proxyType = String(proxy.type || '').toLowerCase()
  const supported = TRANSPORT_TYPES_BY_PROXY[proxyType]
  return Array.isArray(supported) ? supported.includes(network) : false
}

function cleanupProxyTransportOptions(proxy) {
  delete proxy['ws-opts']
  delete proxy['grpc-opts']
  delete proxy['h2-opts']
  delete proxy['http-opts']
  delete proxy['httpupgrade-opts']
  delete proxy['xhttp-opts']
}

function applyXhttpDefaults(proxy) {
  if (!Array.isArray(proxy.alpn) || !proxy.alpn.length) proxy.alpn = ['h2']
  if (proxy.encryption === undefined) proxy.encryption = ''
  proxy['xhttp-opts'] = {
    path: '/',
    ...(proxy['xhttp-opts'] || {}),
    'no-grpc-header': booleanValue(proxy['xhttp-opts']?.['no-grpc-header']),
    'x-padding-obfs-mode': booleanValue(proxy['xhttp-opts']?.['x-padding-obfs-mode']),
  }
}

function booleanValue(value) {
  if (value === true || value === false) return value
  return ['1', 'true', 'yes'].includes(String(value || '').toLowerCase())
}

function normalizeTransport(value) {
  const transport = String(value || '').toLowerCase()
  if (!transport || transport === 'tcp') return undefined
  return TRANSPORT_TYPES.includes(transport) ? transport : undefined
}

function makeUniqueProviderNames(providers, basePath = './rules') {
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

function compact(object) {
  return Object.fromEntries(
    Object.entries(object).filter(([, value]) => {
      if (value === undefined || value === null || value === '') return false
      if (typeof value === 'number' && Number.isNaN(value)) return false
      if (value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0) return false
      return true
    }),
  )
}

function defaultPort(protocol, params) {
  if (protocol === 'trojan') return 443
  return params.get('security') === 'tls' || params.get('security') === 'reality' ? 443 : 80
}

function defaultProxyPort(protocol) {
  if (protocol === 'ss' || protocol === 'ssr') return 8388
  return 443
}

function getProtocol(line) {
  const match = String(line || '').match(/^([a-z0-9+.-]+):\/\//i)
  return match ? match[1].toLowerCase() : ''
}

function snippet(value) {
  const text = String(value || '').trim()
  return text.length > 96 ? `${text.slice(0, 96)}...` : text
}

function required(value, field) {
  if (value === undefined || value === null || value === '') throw new Error(`${field} is required`)
  return value
}

function toPort(value) {
  const port = Number(value)
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('port is invalid')
  return port
}

function toUrl(link) {
  try {
    return new URL(link)
  } catch {
    throw new Error('URL is invalid')
  }
}

function boolParam(value) {
  if (value === null || value === undefined || value === '') return undefined
  return ['1', 'true', 'yes'].includes(String(value).toLowerCase())
}

function numberParam(value) {
  if (value === null || value === undefined || value === '') return undefined
  const number = Number(value)
  return Number.isFinite(number) ? number : undefined
}

function cleanName(value) {
  const decoded = decodeText(String(value || '')).trim()
  return decoded || 'proxy'
}

function decodeText(value) {
  try {
    return decodeURIComponent(String(value).replace(/\+/g, '%20'))
  } catch {
    return String(value)
  }
}

function base64Param(params, key) {
  const value = params.get(key)
  return value ? tryBase64Decode(value) : undefined
}

function tryBase64Decode(value) {
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
