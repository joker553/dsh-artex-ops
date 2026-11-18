// Static asset discovery: pull the hidden surface out of HTML + JS bundles.
//
// Modern apps hide their API behind a SPA: the HTML is a shell, and every route,
// endpoint and feature flag lives in JavaScript. This module fetches the page, the
// same-origin bundles it references, and mines them for
//
//   endpoints  (/api/v2/orders, graphql, admin paths, method hints)
//   params     (query keys used by those endpoints)
//   features   (links, forms, buttons, client-side routes)
//   hints      (auth headers, token storage, api keys, sourcemaps)
//
// It is the ONLY place in this package that makes outbound requests, and it only
// talks to the URL you pass plus same-origin scripts it finds there. Runtime
// harvesting (XHR fired by the app after login) is a different path: drive the page
// with a browser and feed the observed requests back through `pt_asset`.
import { URL } from 'node:url'

const STATIC_EXT = /\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|map|mp4|webm|pdf|zip|gz|br)$/i
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

/**
 * Crawl one page + its same-origin bundles.
 * @returns {{origin:string, pages:object[], scripts:object[], endpoints:object[], params:object[], features:object[], hints:object[], errors:string[]}}
 */
export async function discover({ url, extraJs = [], maxScripts = 20, timeoutMs = 10000, maxBytes = 1_500_000 } = {}) {
  const start = absolute('http://invalid/', url) || url
  const origin = new URL(start).origin
  const errors = []
  const endpoints = new Map()
  const params = new Map()
  const features = []
  const hints = new Set()
  const pages = []
  const scripts = []

  const page = await fetchText(start, { timeoutMs, maxBytes })
  if (page.error) errors.push(`${start}: ${page.error}`)
  pages.push({ url: start, status: page.status, type: page.type, title: cleanText(String(page.body).match(RE.title)?.[1] ?? ''), truncated: page.truncated })

  const jsUrls = new Set()
  const inline = []
  const html = page.body

  for (const match of html.matchAll(RE.scriptSrc)) {
    const resolved = absolute(page.finalUrl || start, match[1])
    if (resolved) jsUrls.add(resolved)
  }
  for (const match of html.matchAll(RE.inlineScript)) {
    if (match[1].trim() !== '') inline.push(match[1])
  }
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
  for (const match of html.matchAll(RE.linkHref)) {
    const resolved = absolute(page.finalUrl || start, match[1])
    if (resolved && /\.js(\?|$)/.test(resolved)) jsUrls.add(resolved)
  }

  // Sourcemap hints straight from the page.
  for (const match of String(page.body).matchAll(RE.sourcemap)) hints.add(`sourcemap: ${match[1]}`)

  const bodies = [{ name: `${start} (inline html)`, body: html }]
  for (const code of inline) bodies.push({ name: `${start} (inline <script>)`, body: code })

  let count = 0
  for (const jsUrl of jsUrls) {
    if (count >= maxScripts) break
    if (!jsUrl.startsWith(origin)) continue // same-origin only
    count += 1
    const file = await fetchText(jsUrl, { timeoutMs, maxBytes })
    scripts.push({ url: jsUrl, status: file.status, bytes: file.body.length, truncated: file.truncated, error: file.error })
    if (file.error) {
      errors.push(`${jsUrl}: ${file.error}`)
      continue
    }
    bodies.push({ name: jsUrl, body: file.body })
  }
  for (const extra of extraJs) {
    const resolved = absolute(start, extra)
    if (!resolved) continue
    const file = await fetchText(resolved, { timeoutMs, maxBytes })
    scripts.push({ url: resolved, status: file.status, bytes: file.body.length, truncated: file.truncated, error: file.error })
    if (!file.error) bodies.push({ name: resolved, body: file.body })
  }

  for (const { name, body } of bodies) {
    const source = name.includes('.js') ? `js:${name.split('/').pop()}` : 'html'
    for (const match of body.matchAll(RE.callSite)) addEndpoint(endpoints, match[1], { source: `${source}:call`, sample: match[0] })
    for (const match of body.matchAll(RE.routePath)) addEndpoint(endpoints, match[1], { source: `${source}:route`, sample: match[0] })
    for (const match of body.matchAll(RE.pathLiteral)) {
      const value = match[1]
      if (!/^(?:\/(?:api|v\d|graphql|rest|internal|admin|auth|user|order|upload|upload|file|search|config)\b)/i.test(value)) continue
      addEndpoint(endpoints, value, { source: `${source}:literal`, sample: match[0] })
    }
    for (const match of body.matchAll(RE.absUrl)) {
      if (match[0].startsWith(origin)) addEndpoint(endpoints, new URL(match[0]).pathname, { source: `${source}:abs` })
      else if (!STATIC_EXT.test(match[0])) hints.add(`external url: ${match[0].slice(0, 120)}`)
    }
    for (const match of body.matchAll(RE.method)) {
      // 方法提示只记录，配对靠调用点顺序不可靠，交给人工/浏览器确认
      hints.add(`method hint: ${match[1].toUpperCase()}`)
    }
    for (const match of body.matchAll(RE.sourcemap)) hints.add(`sourcemap: ${match[1]}`)
    for (const match of body.matchAll(RE.param)) params.set(match[1], { name: match[1], from: source })
    for (const match of body.matchAll(RE.hint)) hints.add(`secret-ish: ${String(match[0]).slice(0, 80)}`)
    for (const match of body.matchAll(RE.routeHash)) features.push({ kind: 'route-hash', label: `#/${match[1]}`, target: `#/${match[1]}`, source })
  }

  const endpointRows = [...endpoints.values()]
    .map((row) => ({
      path: row.path,
      methods: [...row.methods],
      sources: [...row.sources].slice(0, 4),
      sample: [...row.samples][0] ?? '',
    }))
    .sort((a, b) => a.path.localeCompare(b.path))

  return {
    origin,
    pages,
    scripts,
    endpoints: endpointRows,
    params: [...params.values()],
    features: features.slice(0, 200),
    hints: [...hints].slice(0, 100),
    errors,
  }
}
