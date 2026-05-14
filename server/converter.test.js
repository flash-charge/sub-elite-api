import assert from 'node:assert/strict'
import test from 'node:test'
import { autoFixConfigModel, buildYamlFromModel, convertToClashMeta, extractLinks, parseLink, validateConfigModel } from '../lib/converter.ts'

test('extractLinks decodes base64 subscription text', () => {
  const source = [
    'vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#A',
    'trojan://pass@example.com:443#B',
  ].join('\n')
  const encoded = Buffer.from(source).toString('base64')

  assert.deepEqual(extractLinks(encoded), source.split('\n'))
})

test('extractLinks supports comma-separated config links', () => {
  const links = [
    'vmess://eyJwcyI6IkNvbW1hIFZNZXNzIiwiYWRkIjoiZXhhbXBsZS5jb20iLCJwb3J0IjoiNDQzIiwiaWQiOiIxMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTEiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwidGxzIjoidGxzIn0=',
    'vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&alpn=h2,http/1.1#Comma%20VLESS',
    'trojan://secret@example.com:443?sni=example.com#Comma%20Trojan',
  ]

  assert.deepEqual(extractLinks(links.join(',')), links)
  assert.equal(convertToClashMeta(links.join(',')).stats.converted, 3)
})

test('parseLink converts vmess json payload', () => {
  const payload = Buffer.from(
    JSON.stringify({
      ps: 'Sample VMess',
      add: 'example.com',
      port: '443',
      id: '11111111-1111-1111-1111-111111111111',
      aid: '0',
      scy: 'auto',
      net: 'ws',
      tls: 'tls',
      sni: 'example.com',
      host: 'example.com',
      path: '/path',
    }),
  ).toString('base64')

  const proxy = parseLink(`vmess://${payload}`)

  assert.equal(proxy.name, 'Sample VMess')
  assert.equal(proxy.type, 'vmess')
  assert.equal(proxy.server, 'example.com')
  assert.equal(proxy.port, 443)
  assert.equal(proxy.network, 'ws')
  assert.equal(proxy['ws-opts'].headers.Host, 'example.com')
})

test('parseLink converts common url protocols', () => {
  const vless = parseLink(
    'vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=ws&host=example.com&path=%2Fws&sni=example.com#Node%20A',
  )
  const trojan = parseLink('trojan://secret@example.com:443?sni=example.com#Node%20B')
  const ss = parseLink(`ss://${Buffer.from('aes-128-gcm:secret').toString('base64')}@example.com:8388#Node%20C`)
  const hy2 = parseLink('hy2://secret@example.com:443?sni=example.com#Node%20D')
  const tuic = parseLink('tuic://11111111-1111-1111-1111-111111111111:secret@example.com:443?sni=example.com#Node%20E')

  assert.equal(vless.type, 'vless')
  assert.equal(vless.tls, true)
  assert.equal(trojan.password, 'secret')
  assert.equal(ss.cipher, 'aes-128-gcm')
  assert.equal(hy2.type, 'hysteria2')
  assert.equal(tuic.type, 'tuic')
})

test('convertToClashMeta returns yaml, stats, and warnings', () => {
  const result = convertToClashMeta(
    [
      'vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#Same',
      'trojan://secret@example.com:443#Same',
      'unknown://value',
    ].join('\n'),
  )

  assert.equal(result.stats.total, 3)
  assert.equal(result.stats.converted, 2)
  assert.equal(result.stats.skipped, 1)
  assert.match(result.yaml, /mixed-port: 7890/)
  assert.match(result.yaml, /"Same 2"/)
  assert.equal(result.warnings[0].type, 'unsupported')
})

test('convertToClashMeta supports output templates', () => {
  const input = 'trojan://secret@example.com:443#Template'

  const proxiesOnly = convertToClashMeta(input, { template: 'proxies' })
  const provider = convertToClashMeta(input, { template: 'provider' })

  assert.match(proxiesOnly.yaml, /^proxies:\n/)
  assert.doesNotMatch(proxiesOnly.yaml, /proxy-groups:/)
  assert.match(provider.yaml, /^proxy-providers:\n/)
  assert.match(provider.yaml, /type: "inline"/)
  assert.match(provider.yaml, /payload:/)
  assert.doesNotMatch(provider.yaml, /rules:/)
})

test('convertToClashMeta supports rules presets', () => {
  const input = 'trojan://secret@example.com:443#Rules'

  const lanDirect = convertToClashMeta(input, { rulesPreset: 'lan-direct' })
  const direct = convertToClashMeta(input, { rulesPreset: 'direct' })

  assert.match(lanDirect.yaml, /"IP-CIDR,192\.168\.0\.0\/16,DIRECT"/)
  assert.match(lanDirect.yaml, /"MATCH,PROXY"/)
  assert.match(direct.yaml, /"MATCH,DIRECT"/)
  assert.doesNotMatch(direct.yaml, /"MATCH,PROXY"/)
})

test('parseLink supports alpn and bandwidth parameters', () => {
  const vless = parseLink('vless://uuid@example.com:443?security=tls&alpn=h2,http/1.1#V')
  const tuic = parseLink('tuic://uuid:pass@example.com:443?alpn=h3#T')
  const hy2 = parseLink('hy2://pass@example.com:443?up=100&down=100#H')

  assert.deepEqual(vless.alpn, ['h2', 'http/1.1'])
  assert.deepEqual(tuic.alpn, ['h3'])
  assert.equal(hy2.up, '100')
  assert.equal(hy2.down, '100')
})

test('parseLink supports advanced transports', () => {
  const h2 = parseLink('vless://uuid@example.com:443?security=tls&type=h2&host=a.example,b.example&path=%2Fh2#H2')
  const http = parseLink('vless://uuid@example.com:443?security=tls&type=http&host=edge.example&path=%2Fone,%2Ftwo&method=GET#HTTP')
  const grpc = parseLink('vless://uuid@example.com:443?security=tls&type=grpc&serviceName=svc&grpc-user-agent=mihomo&ping-interval=10#GRPC')
  const xhttp = parseLink('vless://uuid@example.com:443?security=tls&type=xhttp&host=x.example&path=%2Fx&mode=packet-up#XHTTP')

  assert.equal(h2.network, 'h2')
  assert.deepEqual(h2['h2-opts'].host, ['a.example', 'b.example'])
  assert.equal(http.network, 'http')
  assert.deepEqual(http['http-opts'].path, ['/one', '/two'])
  assert.equal(grpc['grpc-opts']['grpc-user-agent'], 'mihomo')
  assert.equal(grpc['grpc-opts']['ping-interval'], 10)
  assert.equal(xhttp.network, 'xhttp')
  assert.deepEqual(xhttp.alpn, ['h2'])
  assert.equal(xhttp.encryption, '')
  assert.equal(xhttp['xhttp-opts'].mode, 'packet-up')
  assert.equal(xhttp['xhttp-opts']['no-grpc-header'], false)
  assert.equal(xhttp['xhttp-opts']['x-padding-obfs-mode'], false)
})

test('transport support follows protocol pages', () => {
  const vmessPayload = Buffer.from(JSON.stringify({
    ps: 'VMess XHTTP',
    add: 'example.com',
    port: '443',
    id: 'uuid',
    aid: '0',
    scy: 'auto',
    net: 'xhttp',
    tls: 'tls',
    path: '/',
  })).toString('base64')
  const vmess = parseLink(`vmess://${vmessPayload}`)
  const trojan = parseLink('trojan://secret@example.com:443?type=http&host=edge.example&path=%2F#TrojanHTTP')

  assert.equal(vmess.network, undefined)
  assert.equal(vmess['xhttp-opts'], undefined)
  assert.equal(trojan.network, undefined)
  assert.equal(trojan['http-opts'], undefined)
})

test('transport output follows mihomo wiki transport list', () => {
  const unsupportedLink = parseLink('vless://uuid@example.com:443?security=tls&type=httpupgrade&host=edge.example&path=%2Fupgrade#Unsupported')
  assert.equal(unsupportedLink.network, undefined)
  assert.equal(unsupportedLink['httpupgrade-opts'], undefined)

  const yaml = buildYamlFromModel({
    template: 'full',
    proxies: [{
      name: 'Raw',
      type: 'vless',
      server: 'example.com',
      port: 443,
      uuid: 'uuid',
      network: 'splithttp',
      'xhttp-opts': { path: '/' },
      enabled: true,
    }],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['Raw'] }],
    rules: ['MATCH,PROXY'],
  })

  assert.doesNotMatch(yaml, /network: "splithttp"/)
  assert.doesNotMatch(yaml, /xhttp-opts:/)
})

test('xhttp transport is emitted only for vless proxies', () => {
  const yaml = buildYamlFromModel({
    template: 'full',
    proxies: [{
      name: 'Trojan XHTTP',
      type: 'trojan',
      server: 'example.com',
      port: 443,
      password: 'secret',
      network: 'xhttp',
      'xhttp-opts': { path: '/', 'sc-min-posts-interval-ms': 0 },
      enabled: true,
    }],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['Trojan XHTTP'] }],
    rules: ['MATCH,PROXY'],
  })

  assert.doesNotMatch(yaml, /network: "xhttp"/)
  assert.doesNotMatch(yaml, /xhttp-opts:/)
})

test('xhttp boolean options are emitted as booleans', () => {
  const yaml = buildYamlFromModel({
    template: 'full',
    proxies: [{
      name: 'XHTTP',
      type: 'vless',
      server: 'example.com',
      port: 443,
      uuid: 'uuid',
      network: 'xhttp',
      'xhttp-opts': { path: '/' },
      enabled: true,
    }],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['XHTTP'] }],
    rules: ['MATCH,PROXY'],
  })

  assert.match(yaml, /no-grpc-header: false/)
  assert.match(yaml, /x-padding-obfs-mode: false/)
})

test('xhttp keeps explicit alpn selection', () => {
  const yaml = buildYamlFromModel({
    template: 'full',
    proxies: [{
      name: 'XHTTP H3',
      type: 'vless',
      server: 'example.com',
      port: 443,
      uuid: 'uuid',
      tls: true,
      network: 'xhttp',
      alpn: ['http/1.1', 'h2'],
      'xhttp-opts': { path: '/' },
      enabled: true,
    }],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['XHTTP H3'] }],
    rules: ['MATCH,PROXY'],
  })

  assert.match(yaml, /alpn:\n\s+- "http\/1\.1"\n\s+- "h2"/)
})

test('manual-only mihomo proxy types can be emitted', () => {
  const yaml = buildYamlFromModel({
    template: 'full',
    proxies: [
      { name: 'Snell', type: 'snell', server: 'example.com', port: 44046, psk: 'psk', version: 3, enabled: true },
      {
        name: 'AnyTLS',
        type: 'anytls',
        server: 'example.com',
        port: 443,
        password: 'pass',
        tls: true,
        udp: true,
        sni: 'example.com',
        alpn: ['h2', 'http/1.1'],
        'idle-session-check-interval': 30,
        'idle-session-timeout': 30,
        'min-idle-session': 0,
        enabled: true,
      },
      { name: 'Mieru', type: 'mieru', server: 'example.com', port: 2999, username: 'user', password: 'pass', transport: 'TCP', enabled: true },
      { name: 'Sudoku', type: 'sudoku', server: 'example.com', port: 443, key: 'key', 'aead-method': 'chacha20-poly1305', enabled: true },
      { name: 'SS', type: 'ss', server: 'example.com', port: 443, cipher: 'aes-128-gcm', password: 'pass', udp: true, enabled: true },
      { name: 'SSR', type: 'ssr', server: 'example.com', port: 443, cipher: 'chacha20-ietf', password: 'pass', obfs: 'tls1.2_ticket_auth', protocol: 'auth_sha1_v4', enabled: true },
      { name: 'Hysteria', type: 'hysteria', server: 'example.com', port: 443, 'auth-str': 'pass', protocol: 'udp', alpn: ['h3'], enabled: true },
      { name: 'Hysteria2', type: 'hysteria2', server: 'example.com', port: 443, password: 'pass', alpn: ['h3'], enabled: true },
      { name: 'TUIC', type: 'tuic', server: 'example.com', port: 443, uuid: 'uuid', password: 'pass', alpn: ['h3'], 'udp-relay-mode': 'native', udp: true, enabled: true },
      { name: 'MASQUE', type: 'masque', server: 'example.com', port: 443, 'private-key': 'private', 'public-key': 'public', ip: '172.16.0.2/32', mtu: 1280, udp: true, enabled: true },
      { name: 'TrustTunnel', type: 'trusttunnel', server: 'example.com', port: 443, username: 'user', password: 'pass', udp: true, enabled: true },
      { name: 'DirectOut', type: 'direct', enabled: true },
      { name: 'DnsOut', type: 'dns', enabled: true },
    ],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['Snell', 'AnyTLS', 'Mieru', 'Sudoku', 'SS', 'SSR', 'Hysteria', 'Hysteria2', 'TUIC', 'MASQUE', 'TrustTunnel', 'DirectOut', 'DnsOut'] }],
    rules: ['MATCH,PROXY'],
  })

  for (const type of ['snell', 'anytls', 'mieru', 'sudoku', 'ss', 'ssr', 'hysteria', 'hysteria2', 'tuic', 'masque', 'trusttunnel', 'direct', 'dns']) {
    assert.match(yaml, new RegExp(`type: "${type}"`))
  }
  const anytlsStart = yaml.indexOf('name: "AnyTLS"')
  const mieruStart = yaml.indexOf('name: "Mieru"', anytlsStart)
  const anytlsBlock = yaml.slice(anytlsStart, mieruStart)
  assert.equal(anytlsBlock.includes('\n    tls:'), false)
  assert.equal(anytlsBlock.includes('idle-session-check-interval: 30'), true)
  assert.equal(anytlsBlock.includes('idle-session-timeout: 30'), true)
  assert.equal(anytlsBlock.includes('min-idle-session: 0'), true)
  const masqueStart = yaml.indexOf('name: "MASQUE"')
  const trustTunnelStart = yaml.indexOf('name: "TrustTunnel"', masqueStart)
  const masqueBlock = yaml.slice(masqueStart, trustTunnelStart)
  assert.equal(masqueBlock.includes('private-key: "private"'), true)
})

test('blank builder config is exportable with warnings only', () => {
  const model = {
    template: 'full',
    proxies: [],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['DIRECT'] }],
    rules: ['MATCH,PROXY'],
  }
  const validation = validateConfigModel(model)
  const yaml = buildYamlFromModel(model)

  assert.equal(validation.valid, true)
  assert.match(validation.warnings.join(' '), /No active nodes yet/)
  assert.match(yaml, /proxies:\n\s+\[\]/)
  assert.match(yaml, /MATCH,PROXY/)
})

test('buildYamlFromModel ignores malformed array entries in model sections', () => {
  const yaml = buildYamlFromModel({
    template: 'full',
    proxies: [
      'bad-proxy',
      { name: 'A', type: 'trojan', server: 'a.example', port: 443, password: 'x', enabled: true },
    ],
    groups: [
      123,
      { name: 'PROXY', type: 'select', proxies: ['A'] },
    ],
    proxyProviders: ['bad-provider'],
    ruleProviders: ['bad-rule-provider'],
    listeners: ['bad-listener'],
    tunnels: ['bad-tunnel'],
    rules: ['MATCH,PROXY'],
  })

  assert.match(yaml, /name: "A"/)
  assert.doesNotMatch(yaml, /bad-proxy/)
  assert.doesNotMatch(yaml, /bad-provider/)
  assert.doesNotMatch(yaml, /bad-listener/)
  assert.doesNotMatch(yaml, /bad-tunnel/)
})

test('extra top-level config is preserved when building yaml', () => {
  const yaml = buildYamlFromModel({
    template: 'full',
    extraTopLevel: {
      ntp: { enable: true, server: 'time.apple.com' },
    },
    proxies: [{ name: 'DnsOut', type: 'dns', enabled: true }],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['DnsOut'] }],
    rules: ['MATCH,PROXY'],
  })

  assert.match(yaml, /ntp:/)
  assert.match(yaml, /server: "time\.apple\.com"/)
  assert.match(yaml, /type: "dns"/)
})

test('ws http upgrade options are emitted as booleans', () => {
  const yaml = buildYamlFromModel({
    template: 'full',
    proxies: [{
      name: 'WS',
      type: 'vless',
      server: 'example.com',
      port: 443,
      uuid: 'uuid',
      network: 'ws',
      'ws-opts': { path: '/ws' },
      enabled: true,
    }],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['WS'] }],
    rules: ['MATCH,PROXY'],
  })

  assert.doesNotMatch(yaml, /v2ray-http-upgrade:/)
  assert.doesNotMatch(yaml, /v2ray-http-upgrade-fast-open:/)
})

test('parseLink supports socks and hysteria links', () => {
  const socks = parseLink('socks5://user:pass@example.com:1080?udp=true#Socks')
  const hysteria = parseLink('hysteria://auth@example.com:443?protocol=udp&up=50&down=100&sni=example.com#Hy')

  assert.equal(socks.type, 'socks5')
  assert.equal(socks.udp, true)
  assert.equal(hysteria.type, 'hysteria')
  assert.equal(hysteria.protocol, 'udp')
  assert.equal(hysteria['auth-str'], 'auth')
  assert.equal(hysteria.auth, undefined)
})

test('dumpYaml uses block scalars for multi-line strings', () => {
  const model = {
    template: 'full',
    general: { mixedPort: 7890 },
    proxies: [],
    groups: [],
    rules: ['DOMAIN,example.com,DIRECT\nDOMAIN,test.com,PROXY']
  }
  const yaml = buildYamlFromModel(model)
  assert.match(yaml, /rules:\n\s+-\s+\|\n\s+DOMAIN,example\.com,DIRECT/)
})

test('convertToClashMeta supports optional legacy name prefix and unique names', () => {
  const result = convertToClashMeta(
    [
      'trojan://secret@example.com:443#Same',
      'trojan://secret@example.org:443#Same',
    ].join('\n'),
    { namePrefix: 'ID' },
  )

  assert.match(result.yaml, /"ID - Same"/)
  assert.match(result.yaml, /"ID - Same 2"/)
})

test('convertToClashMeta supports name pattern placeholders', () => {
  const result = convertToClashMeta(
    [
      'trojan://secret@example.com:443#Alpha',
      'vless://11111111-1111-1111-1111-111111111111=edge.example:443?security=tls#Beta'.replace('=', '@'),
    ].join('\n'),
    { namePattern: '{nn} - {type} - {server} - {name}' },
  )

  assert.match(result.yaml, /"01 - trojan - example\.com - Alpha"/)
  assert.match(result.yaml, /"02 - vless - edge\.example - Beta"/)
})

test('convertToClashMeta default config stays simple', () => {
  const result = convertToClashMeta('trojan://secret@example.com:443#Simple')

  assert.doesNotMatch(result.yaml, /profile:/)
  assert.doesNotMatch(result.yaml, /\n\s+id: /)
  assert.doesNotMatch(result.yaml, /geodata-mode: true/)
  assert.match(result.yaml, /enhanced-mode: "redir-host"/)
  assert.doesNotMatch(result.yaml, /name: "FALLBACK"/)
  assert.doesNotMatch(result.yaml, /name: "LOAD-BALANCE"/)
  assert.doesNotMatch(result.yaml, /name: "AUTO"/)
  assert.doesNotMatch(result.yaml, /type: "url-test"/)
  assert.doesNotMatch(result.yaml, /"GEOSITE,category-ads-all,REJECT"/)
  assert.equal(result.model.sniffer.enable, false)
  assert.equal(result.model.tun.enable, false)
})

test('buildYamlFromModel adds readable spacing between top-level sections', () => {
  const result = convertToClashMeta('trojan://secret@example.com:443#Spacing')

  assert.match(result.yaml, /geo-update-interval: 24\n\ndns:/)
  assert.doesNotMatch(result.yaml, /proxy-server-nameserver:/)
  assert.match(result.yaml, /password: "secret"\n\nproxy-groups:/)
  assert.match(result.yaml, /- "Spacing"\n\nrules:/)
})

test('dumpYaml correctly escapes keys with special characters', () => {
  const model = {
    template: 'full',
    general: { mixedPort: 7890 },
    ruleProviders: [{ name: 'ads:gaming', type: 'http', behavior: 'classical', url: 'http://example.com' }],
    proxies: [],
    groups: [],
    rules: []
  }
  const yaml = buildYamlFromModel(model)
  assert.match(yaml, /"ads:gaming":/)
})

test('validateConfigModel returns structured issues for advanced checks', () => {
  const model = {
    template: 'full',
    proxies: [
      { name: 'Same', type: 'trojan', server: 'a.example', port: 443, password: 'x', enabled: true },
      { name: 'Same', type: 'trojan', server: 'b.example', port: 'bad', password: 'x', enabled: true },
    ],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['Missing'] }],
    ruleProviders: [{ name: 'ads', behavior: 'domain', path: '', url: '' }],
    rules: ['RULE-SET,missing,REJECT', 'MATCH,PROXY'],
  }

  const result = validateConfigModel(model)

  assert.equal(result.valid, false)
  assert.ok(result.issues.some((issue) => issue.code === 'duplicate-proxy-name'))
  assert.ok(result.issues.some((issue) => issue.code === 'invalid-port'))
  assert.ok(result.issues.some((issue) => issue.code === 'missing-group-reference'))
  assert.ok(result.issues.some((issue) => issue.code === 'missing-rule-provider'))
})

test('validateConfigModel reports Mihomo structure mistakes more precisely', () => {
  const model = {
    template: 'full',
    proxies: [
      { name: 'No UUID', type: 'vless', server: 'a.example', port: 443, enabled: true },
      { name: 'Bad XHTTP', type: 'trojan', server: 'b.example', port: 443, password: 'secret', network: 'xhttp', enabled: true },
    ],
    groups: [
      { name: 'PROXY', type: 'select', proxies: ['No UUID'] },
      { name: 'PROXY', type: 'select', proxies: ['Bad XHTTP'] },
    ],
    rules: ['MATCH,PROXY', 'DOMAIN,example.com,PROXY'],
  }

  const result = validateConfigModel(model)

  assert.equal(result.valid, false)
  assert.ok(result.issues.some((issue) => issue.code === 'missing-proxy-field'))
  assert.ok(result.issues.some((issue) => issue.code === 'duplicate-group-name'))
  assert.ok(result.issues.some((issue) => issue.code === 'invalid-network-for-proxy'))
  assert.ok(result.issues.some((issue) => issue.code === 'match-not-last'))
})

test('autoFixConfigModel applies safe fixes without removing user config', () => {
  const model = {
    template: 'full',
    proxies: [
      { name: 'Same', type: 'trojan', server: 'a.example', port: 443, password: 'x', enabled: true },
      { name: 'Same', type: 'trojan', server: 'b.example', port: 'bad', password: 'x', enabled: true },
    ],
    groups: [],
    ruleProviders: [{ name: 'ads', behavior: 'domain', path: '', url: 'https://example.com/ads.yaml' }],
    rules: [],
  }

  const result = autoFixConfigModel(model)
  const yaml = buildYamlFromModel(result.model)

  assert.equal(result.model.proxies[1].name, 'Same 2')
  assert.equal(result.model.proxies[1].port, 443)
  assert.equal(result.model.groups.length > 0, true)
  assert.equal(result.model.ruleProviders[0].path, './rules/ads.yaml')
  assert.match(yaml, /MATCH,PROXY/)
})

test('rule provider model supports target metadata without leaking it to yaml', () => {
  const yaml = buildYamlFromModel({
    template: 'full',
    proxies: [{ name: 'A', type: 'trojan', server: 'a.example', port: 443, password: 'x', enabled: true }],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['A'] }],
    ruleProviders: [{
      name: 'ads',
      type: 'http',
      behavior: 'domain',
      path: './rules/ads.yaml',
      url: 'https://example.com/ads.yaml',
      target: 'REJECT',
    }],
    rules: ['RULE-SET,ads,REJECT', 'MATCH,PROXY'],
  })

  assert.match(yaml, /rule-providers:/)
  assert.match(yaml, /RULE-SET,ads,REJECT/)
  assert.doesNotMatch(yaml, /target:/)
})

test('buildYamlFromModel supports advanced mihomo sections', () => {
  const yaml = buildYamlFromModel({
    template: 'full',
    dns: {
      enhancedMode: 'fake-ip',
      fakeIpRange: '198.18.0.1/16',
      preferH3: true,
      fallbackFilter: { geoip: true, 'geoip-code': 'CN' },
      directNameserver: ['https://doh.pub/dns-query'],
    },
    general: {
      mixedPort: 7890,
      interfaceName: 'rmnet_data0',
      routingMark: 6666,
      externalUiName: 'zashboard',
      externalUiUrl: 'https://example.com/ui.zip',
    },
    sniffer: {
      enable: true,
      overrideDestination: true,
      parsePureIp: false,
      forceDnsMapping: true,
      sniff: { TLS: { ports: [443], 'override-destination': true } },
      forceDomain: ['+.example.com'],
      skipDomain: ['+.skip.example'],
      skipSrcAddress: ['192.168.0.0/16'],
      skipDstAddress: ['10.0.0.0/8'],
    },
    proxies: [{ name: 'A', type: 'trojan', server: 'a.example', port: 443, password: 'x', enabled: true }],
    proxyProviders: [{
      name: 'remote',
      type: 'http',
      url: 'https://example.com/sub.yaml',
      path: './proxy_providers/remote.yaml',
      healthCheck: { enable: true, url: 'https://www.gstatic.com/generate_204', interval: 300, timeout: 5000, lazy: true, expectedStatus: '204' },
    }],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['A'], use: ['remote'], filter: '(?i)sg', includeAllProviders: true, routingMark: 6666 }],
    ruleProviders: [],
    subRules: { directOnly: ['DOMAIN-SUFFIX,example.com,DIRECT', 'MATCH,PROXY'] },
    tunnels: [{ network: ['tcp', 'udp'], address: '127.0.0.1:6553', target: '8.8.8.8:53', proxy: 'PROXY' }],
    rules: ['SUB-RULE,(DOMAIN,example.com),directOnly', 'MATCH,PROXY'],
  })

  assert.match(yaml, /prefer-h3: true/)
  assert.match(yaml, /interface-name: "rmnet_data0"/)
  assert.match(yaml, /external-ui-url: "https:\/\/example\.com\/ui\.zip"/)
  assert.match(yaml, /force-dns-mapping: true/)
  assert.match(yaml, /TLS:\n\s+ports:\n\s+- 443\n\s+override-destination: true/)
  assert.match(yaml, /skip-src-address:/)
  assert.match(yaml, /proxy-providers:/)
  assert.match(yaml, /use:\n\s+- "remote"/)
  assert.match(yaml, /include-all-providers: true/)
  assert.match(yaml, /sub-rules:/)
  assert.match(yaml, /tunnels:/)
})

test('buildYamlFromModel supports ntp, experimental, and raw section overrides', () => {
  const yaml = buildYamlFromModel({
    template: 'full',
    general: { mixedPort: 7890 },
    dns: { nameserver: ['8.8.8.8'] },
    ntp: { enable: true, writeToSystem: true, server: 'time.apple.com', port: 123, interval: 30 },
    experimental: { 'quic-go-disable-gso': true, 'dialer-ip4p-convert': true },
    rawSections: {
      general: { 'mixed-port': 9090, 'global-client-fingerprint': 'chrome' },
      dns: { enable: false, nameserver: ['https://dns.example/dns-query'], 'enhanced-mode': 'fake-ip' },
    },
    proxies: [{ name: 'A', type: 'trojan', server: 'a.example', port: 443, password: 'x', enabled: true }],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['A'] }],
    listeners: [{ name: 'mixed-in', type: 'mixed', port: 7890, listen: '0.0.0.0' }],
    rules: ['MATCH,PROXY'],
  })

  assert.match(yaml, /mixed-port: 9090/)
  assert.match(yaml, /global-client-fingerprint: "chrome"/)
  assert.match(yaml, /dns:\n\s+enable: false/)
  assert.match(yaml, /enhanced-mode: "fake-ip"/)
  assert.doesNotMatch(yaml, /default-nameserver:/)
  assert.match(yaml, /ntp:\n\s+enable: true/)
  assert.match(yaml, /write-to-system: true/)
  assert.match(yaml, /experimental:/)
  assert.match(yaml, /quic-go-disable-gso: true/)
  assert.match(yaml, /dialer-ip4p-convert: true/)
})

test('buildYamlFromModel supports visual Mihomo wiki fields for general, tun, and common proxies', () => {
  const yaml = buildYamlFromModel({
    template: 'full',
    general: {
      port: 7891,
      socksPort: 7892,
      redirPort: 7893,
      tproxyPort: 7894,
      mixedPort: 7890,
      allowLan: true,
      bindAddress: '*',
      lanAllowedIps: ['0.0.0.0/0', '::/0'],
      lanDisallowedIps: ['192.168.0.3/32'],
      authentication: ['user:pass'],
      skipAuthPrefixes: ['127.0.0.1/8'],
      keepAliveIdle: 15,
      keepAliveInterval: 15,
      disableKeepAlive: true,
      findProcessMode: 'strict',
      externalControllerTls: '127.0.0.1:9443',
      externalControllerUnix: 'mihomo.sock',
      externalControllerPipe: '\\\\.\\pipe\\mihomo',
      globalClientFingerprint: 'chrome',
      globalUa: 'mihomo-test',
      etagSupport: true,
      tlsCertificate: 'cert.pem',
      tlsPrivateKey: 'key.pem',
    },
    tun: {
      enable: true,
      stack: 'mixed',
      device: 'utun0',
      autoRoute: true,
      autoRedirect: true,
      autoDetectInterface: true,
      strictRoute: true,
      dnsHijack: ['any:53'],
      mtu: 9000,
      gso: true,
      gsoMaxSize: 65536,
      udpTimeout: 300,
      iproute2TableIndex: 2022,
      iproute2RuleIndex: 9000,
      endpointIndependentNat: true,
      routeAddressSet: ['geoip-cn'],
      routeExcludeAddressSet: ['private'],
      routeAddress: ['0.0.0.0/1'],
      routeExcludeAddress: ['192.168.0.0/16'],
      includeInterface: ['rmnet_data0'],
      excludeInterface: ['wlan0'],
      includeUid: ['1000'],
      includeUidRange: ['1000-2000'],
      excludeUid: ['0'],
      excludeUidRange: ['3000-4000'],
      includeAndroidUser: ['0'],
      includePackage: ['com.termux'],
      excludePackage: ['com.android.vending'],
    },
    proxies: [{
      name: 'A',
      type: 'trojan',
      server: 'a.example',
      port: 443,
      password: 'x',
      enabled: true,
      udp: true,
      tfo: true,
      mptcp: true,
      'dialer-proxy': 'DIRECT',
      'interface-name': 'rmnet_data0',
      'routing-mark': 6666,
      'ip-version': 'ipv4-prefer',
    }],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['A'] }],
    listeners: [{ name: 'mixed-in', type: 'mixed', port: 7890, listen: '0.0.0.0' }],
    rules: ['MATCH,PROXY'],
  })

  assert.match(yaml, /port: 7891/)
  assert.match(yaml, /socks-port: 7892/)
  assert.match(yaml, /lan-allowed-ips:/)
  assert.match(yaml, /skip-auth-prefixes:/)
  assert.match(yaml, /external-controller-tls: "127\.0\.0\.1:9443"/)
  assert.match(yaml, /global-client-fingerprint: "chrome"/)
  assert.match(yaml, /tls:\n\s+certificate: "cert\.pem"/)
  assert.match(yaml, /tun:\n\s+enable: true/)
  assert.match(yaml, /device: "utun0"/)
  assert.match(yaml, /auto-redirect: true/)
  assert.match(yaml, /route-exclude-address:/)
  assert.match(yaml, /include-package:/)
  assert.match(yaml, /listeners:/)
  assert.match(yaml, /name: "mixed-in"/)
  assert.match(yaml, /dialer-proxy: "DIRECT"/)
  assert.match(yaml, /ip-version: "ipv4-prefer"/)
  assert.match(yaml, /mptcp: true/)
})

test('buildYamlFromModel accepts object-shaped sniffer sniff config', () => {
  const yaml = buildYamlFromModel({
    template: 'full',
    sniffer: {
      enable: true,
      sniff: {
        TLS: { ports: [443, 8443] },
        HTTP: { ports: ['80', '8080-8880'] },
        QUIC: { ports: 443 },
      },
    },
    proxies: [],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['DIRECT'] }],
    rules: ['MATCH,DIRECT'],
  })

  assert.match(yaml, /sniffer:/)
  assert.match(yaml, /TLS:/)
  assert.match(yaml, /- 8443/)
  assert.match(yaml, /8080-8880/)
})

test('convert warnings include protocol and input snippet', () => {
  const result = convertToClashMeta('trojan://missing-port')

  assert.equal(result.stats.skipped, 1)
  assert.equal(result.warnings[0].protocol, 'trojan')
  assert.match(result.warnings[0].snippet, /trojan:\/\//)
})

test('buildYamlFromModel preserves protocol-specific node fields from the editor', () => {
  const yaml = buildYamlFromModel({
    template: 'full',
    general: { mixedPort: 7890 },
    dns: {},
    proxies: [
      {
        name: 'vmess advanced',
        type: 'vmess',
        server: 'vmess.example',
        port: 443,
        uuid: '11111111-1111-1111-1111-111111111111',
        cipher: 'auto',
        alterId: 0,
        'packet-encoding': 'packetaddr',
        'global-padding': true,
        'authenticated-length': true,
        enabled: true,
      },
      {
        name: 'vless xhttp',
        type: 'vless',
        server: 'vless.example',
        port: 443,
        uuid: '22222222-2222-2222-2222-222222222222',
        network: 'xhttp',
        alpn: ['h2'],
        encryption: '',
        'packet-encoding': 'xudp',
        'xhttp-opts': {
          path: '/',
          'uplink-data-placement': 'body',
        },
        enabled: true,
      },
      {
        name: 'trojan ss opts',
        type: 'trojan',
        server: 'trojan.example',
        port: 443,
        password: 'secret',
        'ss-opts': {
          enabled: true,
          method: 'aes-128-gcm',
          password: 'ss-secret',
        },
        enabled: true,
      },
      {
        name: 'ss udp over tcp',
        type: 'ss',
        server: 'ss.example',
        port: 443,
        cipher: 'aes-128-gcm',
        password: 'secret',
        'udp-over-tcp': true,
        'udp-over-tcp-version': 2,
        enabled: true,
      },
    ],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['vmess advanced', 'vless xhttp', 'trojan ss opts', 'ss udp over tcp'] }],
    rules: ['MATCH,PROXY'],
  })

  assert.match(yaml, /packet-encoding: "packetaddr"/)
  assert.match(yaml, /global-padding: true/)
  assert.match(yaml, /authenticated-length: true/)
  assert.match(yaml, /uplink-data-placement: "body"/)
  assert.match(yaml, /ss-opts:/)
  assert.match(yaml, /method: "aes-128-gcm"/)
  assert.match(yaml, /udp-over-tcp: true/)
  assert.match(yaml, /udp-over-tcp-version: 2/)
})

test('buildYamlFromModel strips unsupported tls option groups by protocol', () => {
  const yaml = buildYamlFromModel({
    template: 'full',
    general: { mixedPort: 7890 },
    dns: {},
    proxies: [
      {
        name: 'http basic tls',
        type: 'http',
        server: 'http.example',
        port: 443,
        tls: true,
        sni: 'http.example',
        'skip-cert-verify': true,
        'reality-opts': { 'public-key': 'must-not-emit' },
        'ech-opts': { enable: true },
        enabled: true,
      },
      {
        name: 'hy2 tls subset',
        type: 'hysteria2',
        server: 'hy2.example',
        port: 443,
        password: 'secret',
        sni: 'hy2.example',
        alpn: ['h3'],
        'skip-cert-verify': true,
        'reality-opts': { 'public-key': 'must-not-emit' },
        enabled: true,
      },
      {
        name: 'vless reality',
        type: 'vless',
        server: 'vless.example',
        port: 443,
        uuid: '22222222-2222-2222-2222-222222222222',
        tls: true,
        'reality-opts': { 'public-key': 'allowed' },
        enabled: true,
      },
    ],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['http basic tls', 'hy2 tls subset', 'vless reality'] }],
    rules: ['MATCH,PROXY'],
  })

  assert.doesNotMatch(yaml, /must-not-emit/)
  assert.doesNotMatch(yaml, /ech-opts:\n\s+enable: true/)
  assert.match(yaml, /public-key: "allowed"/)
  assert.match(yaml, /skip-cert-verify: true/)
})

test('parseLink converts shadowsocks link with plugin (SIP003)', () => {
  const link = 'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@example.com:443/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#PluginNode'
  const proxy = parseLink(link)

  assert.equal(proxy.type, 'ss')
  assert.equal(proxy.name, 'PluginNode')
  assert.equal(proxy.plugin, 'obfs-local')
  assert.deepEqual(proxy['plugin-opts'], {
    obfs: 'http',
    'obfs-host': 'example.com'
  })
})

test('parseLink keeps equals signs inside shadowsocks plugin option values', () => {
  const link = 'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@example.com:443/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Da%3Db.example.com#PluginEquals'
  const proxy = parseLink(link)

  assert.equal(proxy.plugin, 'obfs-local')
  assert.equal(proxy['plugin-opts']['obfs-host'], 'a=b.example.com')
})

test('parseLink converts shadowsocks link with v2ray-plugin', () => {
  const link = 'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@example.com:443/?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bpath%3D%2Fv2ray%3Bhost%3Dexample.com%3Btls#V2Ray'
  const proxy = parseLink(link)

  assert.equal(proxy.plugin, 'v2ray-plugin')
  assert.deepEqual(proxy['plugin-opts'], {
    mode: 'websocket',
    path: '/v2ray',
    host: 'example.com',
    tls: true
  })
})

test('convertToClashMeta includes plugin in yaml', () => {
  const link = 'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@example.com:443/?plugin=obfs-local%3Bobfs%3Dhttp#PluginNode'
  const result = convertToClashMeta(link)

  assert.match(result.yaml, /plugin: "obfs-local"/)
  assert.match(result.yaml, /plugin-opts:/)
  assert.match(result.yaml, /obfs: "http"/)
})

test('parseLink handles SIP002 with base64 encoded host and plugins', () => {
  // chacha20-ietf-poly1305:password@example.com:443
  const main = Buffer.from('chacha20-ietf-poly1305:password@example.com:443').toString('base64')
  const link = `ss://${main}?plugin=obfs-local%3Bobfs%3Dhttp#SIP002`
  const proxy = parseLink(link)

  assert.equal(proxy.server, 'example.com')
  assert.equal(proxy.plugin, 'obfs-local')
})

test('parseLink converts wireguard link', () => {
  const link = 'wireguard://private_key@example.com:51820/?publickey=public_key&address=10.0.0.2/32&mtu=1420#WireGuardNode'
  const proxy = parseLink(link)

  assert.equal(proxy.type, 'wireguard')
  assert.equal(proxy.name, 'WireGuardNode')
  assert.equal(proxy.server, 'example.com')
  assert.equal(proxy.port, 51820)
  assert.equal(proxy['private-key'], 'private_key')
  assert.equal(proxy['public-key'], 'public_key')
  assert.equal(proxy.ip, '10.0.0.2/32')
  assert.equal(proxy.mtu, 1420)
  assert.equal(proxy.peers[0]['public-key'], 'public_key')
})

test('buildYamlFromModel keeps proxy private keys outside TLS', () => {
  const wireguardYaml = buildYamlFromModel({
    template: 'full',
    proxies: [{
      name: 'WireGuard',
      type: 'wireguard',
      server: 'example.com',
      port: 51820,
      'private-key': 'private_key',
      'public-key': 'public_key',
      enabled: true,
    }],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['WireGuard'] }],
    rules: ['MATCH,PROXY'],
  })
  const masqueYaml = buildYamlFromModel({
    template: 'full',
    proxies: [{
      name: 'MASQUE',
      type: 'masque',
      server: 'example.com',
      port: 443,
      'private-key': 'private_key',
      'public-key': 'public_key',
      enabled: true,
    }],
    groups: [{ name: 'PROXY', type: 'select', proxies: ['MASQUE'] }],
    rules: ['MATCH,PROXY'],
  })

  assert.match(wireguardYaml, /private-key: "private_key"/)
  assert.match(masqueYaml, /private-key: "private_key"/)
})
