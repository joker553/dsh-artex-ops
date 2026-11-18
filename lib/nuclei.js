// nuclei 结果 → 类型矩阵映射。
//
// 目的：模板扫一遍，把「命中」变成 candidate/覆盖记录，把「扫过但没命中」也能标成 tested，
// 人只处理剩下的空白类目。映射以 tags 为主、模板 id/名称为辅——因为 nuclei 的 tags 比
// 路径更稳定，而 id 里常带产品名（如 CVE-2021-41773）无法直接对应我们的 64 类。
import fs from 'node:fs'

const TAG_TO_CLASS = {
  sqli: 'sqli',
  nosqli: 'nosqli',
  xss: 'xss-reflected',
  csrf: 'csrf',
  ssrf: 'ssrf',
  xxe: 'xxe',
  ssti: 'ssti',
  lfi: 'lfi',
  'path-traversal': 'path-traversal',
  'file-upload': 'upload-bypass',
  upload: 'upload-bypass',
  'open-redirect': 'open-redirect',
  redirect: 'open-redirect',
  crlf: 'header-injection',
  'crlf-injection': 'header-injection',
  'default-login': 'default-creds',
  'default-credentials': 'default-creds',
  jwt: 'jwt-attacks',
  cors: 'cors-misconfig',
  graphql: 'graphql-abuse',
  ldap: 'ldap-injection',
  'ldap-injection': 'ldap-injection',
  'header-injection': 'header-injection',
  'http-smuggling': 'http-smuggling',
  smuggling: 'http-smuggling',
  'cache-poisoning': 'cache-poisoning',
  'host-header': 'host-header',
  'deserialization': 'deserialization',
  rce: 'cmdi',
  'command-injection': 'cmdi',
  cmdi: 'cmdi',
  'os-command-injection': 'cmdi',
  'log4j': 'jndi-injection',
  jndi: 'jndi-injection',
  'aws-metadata': 'cloud-metadata',
  'cloud-metadata': 'cloud-metadata',
  'exposed-redis': 'open-datastore',
  'exposed-mongo': 'open-datastore',
  'exposed-elastic': 'open-datastore',
  'docker-api': 'container-api',
  'k8s': 'container-api',
  mqtt: 'mqtt-anon',
}

// 模板 id / 名称关键词 → 类目（顺序即优先级）
const PATH_RULES = [
  [/exposures\/configs\/git/i, 'vcs-exposure'],
  [/exposures\/configs\/svn/i, 'vcs-exposure'],
  [/exposures\/backups/i, 'backup-file'],
  [/exposures\/files/i, 'secrets-in-js'],
  [/exposures\/tokens|exposures\/tokens|exposures\/logs/i, 'verbose-error'],
  [/exposed-panels/i, 'exposed-panel'],
  [/swagger|openapi|api-docs/i, 'swagger-exposure'],
  [/http-missing-security-headers/i, 'security-headers'],
  [/cookie/i, 'cookie-flags'],
  [/directory-listing|listing/i, 'directory-listing'],
  [/cors/i, 'cors-misconfig'],
  [/graphql/i, 'graphql-abuse'],
  [/jwt/i, 'jwt-attacks'],
  [/default-login|default-credentials/i, 'default-creds'],
  [/sql-injection|\bsqli\b/i, 'sqli'],
  [/nosql/i, 'nosqli'],
  [/xss/i, 'xss-reflected'],
  [/ssrf/i, 'ssrf'],
  [/xxe/i, 'xxe'],
  [/ssti|template-injection/i, 'ssti'],
  [/path-traversal|traversal/i, 'path-traversal'],
  [/lfi|file-inclusion/i, 'lfi'],
  [/upload/i, 'upload-bypass'],
  [/open-redirect/i, 'open-redirect'],
  [/crlf/i, 'header-injection'],
  [/rce|command-injection|cmdi/i, 'cmdi'],
  [/deserial/i, 'deserialization'],
  [/smuggling/i, 'http-smuggling'],
  [/cache/i, 'cache-poisoning'],
  [/host-header/i, 'host-header'],
]

const NAME_HINTS = [
  [/sql injection/i, 'sqli'],
  [/cross.site scripting|\bxss\b/i, 'xss-reflected'],
  [/server.side request forgery|\bssrf\b/i, 'ssrf'],
  [/xml external entit|\bxxe\b/i, 'xxe'],
  [/template injection|\bssti\b/i, 'ssti'],
  [/path traversal|directory traversal/i, 'path-traversal'],
  [/local file inclusion|\blfi\b/i, 'lfi'],
  [/remote code execution|\brce\b|command injection/i, 'cmdi'],
  [/default (credentials|login|password)/i, 'default-creds'],
  [/open redirect/i, 'open-redirect'],
  [/\.git|git config/i, 'vcs-exposure'],
  [/backup file/i, 'backup-file'],
  [/directory listing/i, 'directory-listing'],
  [/missing.*security header/i, 'security-headers'],
  [/deserializ/i, 'deserialization'],
]

/** 从一条 nuclei 结果推断类目；推断不出返回 ''（只当 candidate，不动矩阵）。 */
export function classForTemplate(result) {
  const info = result?.info ?? {}
  const tags = (Array.isArray(info.tags) ? info.tags : String(info.tags ?? '').split(','))
    .map((tag) => String(tag).trim().toLowerCase())
    .filter(Boolean)
  // CVE 类模板：没有稳定的类型归属，只生成 candidate
  if (tags.includes('cve') && !tags.some((tag) => TAG_TO_CLASS[tag])) return ''
  for (const tag of tags) {
    if (TAG_TO_CLASS[tag]) {
      if (tag === 'xss') {
        const name = String(info.name ?? '').toLowerCase()
        if (name.includes('stored')) return 'xss-stored'
        if (name.includes('dom')) return 'xss-dom'
      }
      return TAG_TO_CLASS[tag]
    }
  }
  const haystack = `${result['template-id'] ?? ''} ${info.name ?? ''} ${info['template-id'] ?? ''}`
  for (const [re, classId] of PATH_RULES) if (re.test(haystack)) return classId
  for (const [re, classId] of NAME_HINTS) if (re.test(String(info.name ?? ''))) return classId
  return ''
}

/** 解析 nuclei -json 输出：支持 jsonl、单个 JSON 数组或对象。 */
export function parseNuclei(text) {
  const raw = String(text ?? '').trim()
  if (raw === '') return []
  if (raw.startsWith('[')) {
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : []
  }
  if (raw.startsWith('{')) {
    // 可能是单行对象，也可能是 jsonl：逐行试
    const lines = raw.split(/\r?\n/).filter((line) => line.trim() !== '')
    const out = []
    for (const line of lines) {
      try {
        out.push(JSON.parse(line))
      } catch {
        // 整段是一个 pretty-printed 对象
        try {
          return [JSON.parse(raw)]
        } catch {
          return out
        }
      }
    }
    return out
  }
  return []
}

export function readNucleiFile(file) {
  return parseNuclei(fs.readFileSync(file, 'utf8'))
}

/** 结果里取主机（用于匹配资产）：优先 host，其次 matched-at / url。 */
export function hostOf(result) {
  const candidates = [result?.host, result?.['matched-at'], result?.url, result?.ip]
  for (const value of candidates) {
    if (!value) continue
    try {
      return new URL(String(value)).host
    } catch {
      return String(value)
    }
  }
  return ''
}

export function urlOf(result) {
  return String(result?.['matched-at'] ?? result?.url ?? result?.host ?? '')
}
