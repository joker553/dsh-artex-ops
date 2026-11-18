// Static asset discovery: pull the hidden surface out of HTML + JS bundles.
//
// Modern apps hide their API behind a SPA: the HTML is a shell, and every route,
// endpoint and feature flag lives in JavaScript. This module fetches the page, the
// same-origin bundles it references — **plus dynamically imported chunks and the
// contents of sourcemaps when they are exposed** — and mines them for
//
//   endpoints  (/api/v2/orders, graphql, admin paths, method hints)
//   params     (query keys used by those endpoints)
//   features   (links, forms, buttons, client-side routes)
//   hints      (auth headers, token storage, api keys, sourcemaps)
//
// It also imports HAR exports (browser DevTools → Network → Save all as HAR), which
// is how authenticated, runtime-only traffic gets into the asset graph.
//
// It is the ONLY place in this package that makes outbound requests, and it only
// talks to the URL you pass plus same-origin scripts it finds there.
import { URL } from 'node:url'

const STATIC_EXT = /\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|mp4|webm|pdf|zip|gz|br)$/i
const IGNORE_PREFIX = /^(?:data:|blob:|mailto:|javascript:|tel:|#|about:)/i

const RE = {
  scriptSrc: /<script[^>]+src=["']([^"']+)["']/gi,
  inlineScript: /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi,
  linkHref: /<link[^>]+href=["']([^"']+)["']/gi,
  anchor: /<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi,
  form: /<form\b[^>]*action=["']([^"']*)["'][^>]*>/gi,
  button: /<button\b[^>]*>([\s\S]*?)<\/button>/gi,
  title: /<title[^>]*>([\s\S]*?)<\/title>/i,
  // JS string literals that look like paths
  pathLiteral: /["'`]((?:\/[A-Za-z0-9_\-{}$:.~?=&%]+){1,8}\/?)["'`]/g,
  // explicit call sites
  callSite: /(?:fetch|axios\.(?:get|post|put|delete|patch)|\.open|\.ajax)\s*\(\s*["'`]([^"'`]+)["'`]/g,
  // route tables / config objects
  routePath: /(?:path|url|endpoint|href|to)\s*:\s*["'`]([^"'`]{2,200})["'`]/gi,
  method: /(?:method|type)\s*:\s*["'`](GET|POST|PUT|DELETE|PATCH|HEAD)["'`]/gi,
  absUrl: /https?:\/\/[^\s"'`<>)\\]+/g,
  sourcemap: /\/\/#\s*sourceMappingURL=([^\s]+)/g,
  param: /[?&]([A-Za-z_][A-Za-z0-9_]{0,40})=/g,
  hint: /(authorization|bearer\s+[a-z0-9._-]{8,}|x-api-key|api[_-]?key|secret|password|localStorage\.setItem\(\s*["']([^"']+)["'])/gi,
  routeHash: /#\/([A-Za-z0-9_\-/]{1,120})/g,
  // 动态 chunk：import('./chunk-abc.js') / import("./x.mjs")
  dynamicImport: /\bimport\s*\(\s*["'`]([^"'`]+)["'`]\s*\)/g,
  // 裸的 JS 文件名（webpack 的 chunk 映射表里也常以字符串出现）
  jsFileLiteral: /["'`]([A-Za-z0-9_\-./@]{1,160}\.m?js(?:\?[^"'`]*)?)["'`]/g,
}

function absolute(base, ref) {
  try {
    if (IGNORE_PREFIX.test(ref)) return ''
    return new URL(ref, base).href
  } catch {
    return ''
  }
}

async function fetchText(url, { timeoutMs = 10000, maxBytes = 1_500_000 } = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      redirect: 'follow',
      headers: { 'user-agent': 'artex-ops-recon/1.0', accept: '*/*' },
    })
    const type = response.headers.get('content-type') ?? ''
    const raw = await response.text()
    return {
      url,
      finalUrl: response.url || url,
      status: response.status,
      type,
      body: raw.length > maxBytes ? raw.slice(0, maxBytes) : raw,
      truncated: raw.length > maxBytes,
      headers: Object.fromEntries(response.headers.entries()),
    }
  } catch (error) {
    return { url, status: 0, type: '', body: '', error: String(error?.message ?? error), headers: {} }
  } finally {
    clearTimeout(timer)
  }
}

function cleanText(html) {
  return String(html ?? '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80)
}

function addEndpoint(map, path, meta) {
  const value = String(path ?? '').trim()
  if (value === '' || value.length > 300) return
  if (IGNORE_PREFIX.test(value)) return
  const noHash = value.split('#')[0].split('?')[0]
  if (noHash === '' || STATIC_EXT.test(noHash)) return
  if (!/^\//.test(noHash) && !/^https?:/.test(noHash)) return
  if (noHash === '/' || noHash === '//') return
  const key = noHash
  const row = map.get(key) ?? { path: noHash, methods: new Set(), sources: new Set(), samples: new Set() }
  if (meta?.method) row.methods.add(meta.method.toUpperCase())
  if (meta?.source) row.sources.add(meta.source)
  if (meta?.sample) row.samples.add(String(meta.sample).slice(0, 160))
  map.set(key, row)
}

/** 从一段 JS 里挑出「还可能藏着接口」的子资源（动态 chunk）。 */
function chunkRefs(body) {
  const refs = new Set()
  for (const match of body.matchAll(RE.dynamicImport)) refs.add(match[1])
  for (const match of body.matchAll(RE.jsFileLiteral)) {
    const value = match[1]
    if (/\.m?js(\?|$)/.test(value)) refs.add(value)
  }
  return [...refs]
}

/**
 * 抓一个页面 + 同源 bundle（含动态 chunk 与 sourcemap 里的源码）。
 *
 * @param {object} options
 * @param {string} options.url 入口页
 * @param {string[]} [options.extraJs] 额外脚本
 * @param {number} [options.maxScripts] 脚本上限（默认 40）
 * @param {number} [options.depth] 动态 chunk 递归层数（默认 2；0 = 不递归）
 * @param {boolean} [options.sourcemaps] 是否下载 .map 并解析 sourcesContent（默认 true）
 */
export async function discover({
  url,
  extraJs = [],
  maxScripts = 40,
  depth = 2,
  sourcemaps = true,
  timeoutMs = 10000,
  maxBytes = 1_500_000,
} = {}) {
  const start = absolute('http://invalid/', url) || url
  const origin = new URL(start).origin
  const errors = []
  const endpoints = new Map()
  const params = new Map()
  const features = []
  const hints = new Set()
  const pages = []
  const scripts = []
  const bodies = []
  const fetched = new Set()

  const page = await fetchText(start, { timeoutMs, maxBytes })
  if (page.error) errors.push(`${start}: ${page.error}`)
  pages.push({ url: start, status: page.status, type: page.type, title: cleanText(String(page.body).match(RE.title)?.[1] ?? ''), truncated: page.truncated })

  const html = page.body
  const queue = []
  const push = (raw, base, level) => {
    const resolved = absolute(base, raw)
    if (!resolved || !resolved.startsWith(origin)) return
    if (fetched.has(resolved)) return
    if (queue.some((item) => item.url === resolved)) return
    queue.push({ url: resolved, level })
  }

  for (const match of html.matchAll(RE.scriptSrc)) push(match[1], page.finalUrl || start, 0)
  for (const match of html.matchAll(RE.linkHref)) {
    if (/\.js(\?|$)/.test(match[1])) push(match[1], page.finalUrl || start, 0)
  }
  for (const extra of extraJs) push(extra, start, 0)

  const inline = []
  for (const match of html.matchAll(RE.inlineScript)) {
    if (match[1].trim() !== '') inline.push(match[1])
  }
  bodies.push({ name: `${start} (inline html)`, body: html })
  for (const code of inline) bodies.push({ name: `${start} (inline <script>)`, body: code })

  // 广度优先取脚本；level < depth 时继续展开动态 chunk
  let count = 0
  while (queue.length > 0 && count < maxScripts) {
    const item = queue.shift()
    if (fetched.has(item.url)) continue
    fetched.add(item.url)
    count += 1
    const file = await fetchText(item.url, { timeoutMs, maxBytes })
    scripts.push({ url: item.url, status: file.status, bytes: file.body.length, truncated: file.truncated, error: file.error, level: item.level })
    if (file.error) {
      errors.push(`${item.url}: ${file.error}`)
      continue
    }
    bodies.push({ name: item.url, body: file.body })
    if (item.level < depth) {
      for (const ref of chunkRefs(file.body)) push(ref, item.url, item.level + 1)
    }
  }

  // sourcemap：把 .map 里的 sourcesContent 当作源码再跑一遍提取器
  if (sourcemaps) {
    let maps = 0
    for (const entry of [...bodies]) {
      for (const match of String(entry.body).matchAll(RE.sourcemap)) {
        if (maps >= 10) break
        const mapUrl = absolute(entry.name.includes('://') ? entry.name : start, match[1])
        if (!mapUrl || !mapUrl.startsWith(origin) || fetched.has(mapUrl)) continue
        fetched.add(mapUrl)
        maps += 1
        const file = await fetchText(mapUrl, { timeoutMs, maxBytes: Math.max(maxBytes, 6_000_000) })
        if (file.error || file.status !== 200) {
          hints.add(`sourcemap unavailable: ${mapUrl}`)
          continue
        }
        try {
          const map = JSON.parse(file.body)
          const sources = Array.isArray(map.sources) ? map.sources : []
          const contents = Array.isArray(map.sourcesContent) ? map.sourcesContent : []
          hints.add(`sourcemap parsed: ${mapUrl} (${sources.length} 源文件)`)
          contents.forEach((code, index) => {
            if (typeof code !== 'string' || code.trim() === '') return
            bodies.push({ name: `${mapUrl}#${sources[index] ?? index}`, body: code })
          })
          for (const source of sources.slice(0, 50)) {
            if (source) hints.add(`sourcemap source: ${String(source).slice(0, 120)}`)
          }
        } catch {
          hints.add(`sourcemap parse failed: ${mapUrl}`)
        }
      }
    }
  }

  for (const { name, body } of bodies) {
    const source = /\.m?js(\?|#|$)/.test(name) ? `js:${name.split('/').pop().split('?')[0]}` : 'html'
    for (const match of body.matchAll(RE.callSite)) addEndpoint(endpoints, match[1], { source: `${source}:call`, sample: match[0] })
    for (const match of body.matchAll(RE.routePath)) addEndpoint(endpoints, match[1], { source: `${source}:route`, sample: match[0] })
    for (const match of body.matchAll(RE.pathLiteral)) {
      const value = match[1]
      if (!/^(?:\/(?:api|v\d|graphql|rest|internal|admin|auth|user|order|upload|file|search|config)\b)/i.test(value)) continue
      addEndpoint(endpoints, value, { source: `${source}:literal`, sample: match[0] })
    }
    for (const match of body.matchAll(RE.absUrl)) {
      if (match[0].startsWith(origin)) addEndpoint(endpoints, new URL(match[0]).pathname, { source: `${source}:abs` })
      else if (!STATIC_EXT.test(match[0])) hints.add(`external url: ${match[0].slice(0, 120)}`)
    }
    for (const match of body.matchAll(RE.method)) hints.add(`method hint: ${match[1].toUpperCase()}`)
    for (const match of body.matchAll(RE.sourcemap)) hints.add(`sourcemap: ${match[1]}`)
    for (const match of body.matchAll(RE.param)) params.set(match[1], { name: match[1], from: source })
    for (const match of body.matchAll(RE.hint)) hints.add(`secret-ish: ${String(match[0]).slice(0, 80)}`)
    for (const match of body.matchAll(RE.routeHash)) features.push({ kind: 'route-hash', label: `#/${match[1]}`, target: `#/${match[1]}`, source })
    if (source !== 'html') {
      for (const ref of chunkRefs(body)) features.push({ kind: 'chunk', label: ref, target: ref, source })
    }
  }

  // HTML 层的功能点（放在最后，保证 features 顺序稳定）
  for (const match of html.matchAll(RE.anchor)) {
    const href = match[1]
    const label = cleanText(match[2])
    const resolved = absolute(page.finalUrl || start, href)
    if (resolved) {
      features.push({ kind: 'link', label: label || href, target: href, source: start })
      addEndpoint(endpoints, resolved.startsWith(origin) ? new URL(resolved).pathname : resolved, { method: 'GET', source: 'html:a', sample: label })
    }
    for (const param of href.matchAll(RE.param)) params.set(param[1], { name: param[1], from: href })
  }
  for (const match of html.matchAll(RE.form)) {
    const action = match[1] || page.finalUrl || start
    features.push({ kind: 'form', label: cleanText(match[0]) || action, target: action, source: start })
    addEndpoint(endpoints, action, { method: 'POST', source: 'html:form', sample: 'form action' })
  }
  for (const match of html.matchAll(RE.button)) {
    const label = cleanText(match[1])
    if (label) features.push({ kind: 'button', label, target: '', source: start })
  }

  const endpointRows = [...endpoints.values()]
    .map((row) => ({ path: row.path, methods: [...row.methods], sources: [...row.sources].slice(0, 4), sample: [...row.samples][0] ?? '' }))
    .sort((a, b) => a.path.localeCompare(b.path))

  return {
    origin,
    pages,
    scripts,
    endpoints: endpointRows,
    params: [...params.values()],
    features: features.slice(0, 300),
    hints: [...hints].slice(0, 120),
    errors,
  }
}

/**
 * 导入浏览器 HAR（DevTools → Network → Save all as HAR）。
 * 这是把「登录后 / 运行时才出现」的请求一次性转成资产的正路。
 */
export function importHar(har, { maxEntries = 5000 } = {}) {
  const log = typeof har === 'string' ? JSON.parse(har) : har
  const entries = (log?.log?.entries ?? []).slice(0, maxEntries)
  const endpoints = new Map()
  const params = new Map()
  const features = []
  const hints = new Set()
  const pages = []
  const errors = []
  let origin = ''

  for (const entry of entries) {
    const request = entry?.request ?? {}
    const response = entry?.response ?? {}
    const rawUrl = String(request.url ?? '')
    if (rawUrl === '' || IGNORE_PREFIX.test(rawUrl)) continue
    let parsed
    try {
      parsed = new URL(rawUrl)
    } catch {
      continue
    }
    if (origin === '') origin = parsed.origin
    const sameOrigin = parsed.origin === origin
    const path = sameOrigin ? parsed.pathname : rawUrl.split('?')[0]
    addEndpoint(endpoints, path, {
      method: request.method,
      source: `har:${String(response.status ?? 0)}`,
      sample: `${request.method} ${path}`,
    })
    for (const query of request.queryString ?? []) {
      if (query?.name) params.set(query.name, { name: query.name, from: `har:${parsed.pathname}` })
    }
    // JSON / 表单 body 的字段也当参数收（这类参数最容易出逻辑洞）
    const postData = request.postData
    if (postData?.text) {
      const text = String(postData.text)
      try {
        const json = JSON.parse(text)
        if (json && typeof json === 'object' && !Array.isArray(json)) {
          for (const key of Object.keys(json)) params.set(key, { name: key, from: `har:${parsed.pathname}:body` })
        }
      } catch {
        for (const match of text.matchAll(/(?:^|&)([A-Za-z_][A-Za-z0-9_]{0,40})=/g)) {
          params.set(match[1], { name: match[1], from: `har:${parsed.pathname}:form` })
        }
      }
    }
    for (const header of request.headers ?? []) {
      const name = String(header?.name ?? '').toLowerCase()
      if (/^(authorization|x-api-key|cookie|x-csrf-token)$/.test(name)) {
        hints.add(`har header: ${name} on ${parsed.pathname}`)
      }
    }
    if (parsed.search === '' && !sameOrigin) hints.add(`har external: ${parsed.origin}`)
    if (features.length < 300) features.push({ kind: 'har', label: `${request.method} ${path}`, target: path, source: `status ${response.status ?? 0}` })
    if (response.status >= 400) hints.add(`har error ${response.status}: ${path}`)
  }

  if (origin === '') {
    errors.push('HAR 里没有可用请求（或全部被过滤）')
    return { origin: '', pages, scripts: [], endpoints: [], params: [], features, hints: [], errors }
  }

  pages.push({ url: origin, status: 200, type: 'har', title: `${entries.length} entries`, truncated: false })
  return {
    origin,
    pages,
    scripts: [],
    endpoints: [...endpoints.values()]
      .map((row) => ({ path: row.path, methods: [...row.methods], sources: [...row.sources].slice(0, 4), sample: [...row.samples][0] ?? '' }))
      .sort((a, b) => a.path.localeCompare(b.path)),
    params: [...params.values()],
    features: features.slice(0, 300),
    hints: [...hints].slice(0, 120),
    errors,
  }
}
