// ARTEX 本地靶场（lab only）— 一个刻意留洞的 Node 服务，用来把 pt_* 全链路跑通。
//
// 端口：18200（主站） / 18201（只监听回环的「内网元数据」服务，靠 SSRF 才能从主站触达）
// 所有"漏洞"都只为教学/验证：无外部依赖、无真实数据、破坏性动作仅作用于本目录。
import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const LAB = path.join(os.tmpdir(), 'artex-lab')
const UPLOADS = path.join(LAB, 'uploads')
const MAIN_PORT = Number(process.argv[2] ?? 18200)
const INTERNAL_PORT = Number(process.argv[3] ?? 18201)

fs.mkdirSync(UPLOADS, { recursive: true })
fs.writeFileSync(path.join(LAB, 'secret.txt'), 'LAB-ONLY secret: db_password=lab-db-pass\n')
fs.writeFileSync(path.join(LAB, 'uploads', 'readme.txt'), 'upload dir\n')

const users = [
  { id: 1, name: 'alice', role: 'admin', email: 'alice@lab.local' },
  { id: 2, name: 'bob', role: 'user', email: 'bob@lab.local' },
  { id: 3, name: 'carol', role: 'user', email: 'carol@lab.local' },
]
const orders = [
  { id: 1001, user: 'bob', item: 'keyboard', amount: 199 },
  { id: 1002, user: 'carol', item: 'monitor', amount: 1299 },
  { id: 1003, user: 'alice', item: 'dock', amount: 499 },
]
let couponUsed = 0
const COUPON_LIMIT = 1

const HTML = `<!doctype html><html><head><title>ARTEX Lab Shop</title>
<script src="/assets/app.js" defer></script></head>
<body><h1>Lab Shop</h1>
<div id="app"></div>
<form action="/api/v2/login" method="post"><input name="u"><input name="p" type="password"><button>登录</button></form>
<a href="/orders?id=1001">我的订单</a> <a href="/admin">管理后台</a>
</body></html>`

const APP_JS = `
const api = axios.create({ baseURL: '/api/v2' });
export const endpoints = {
  orders:  () => fetch('/api/v2/orders?id=1001'),
  search:  (q) => fetch('/api/v2/search?q=' + encodeURIComponent(q)),
  ping:    (h) => fetch('/api/v2/ping?host=' + encodeURIComponent(h)),
  fetchUrl:(u) => fetch('/api/v2/fetch?url=' + encodeURIComponent(u)),
  download:(f) => fetch('/api/v2/download?file=' + f),
  upload:  (n) => fetch('/api/v2/upload?name=' + n, { method: 'POST' }),
  run:     (n) => fetch('/api/v2/run?name=' + n),
  tmpl:    (n) => fetch('/api/v2/template?name=' + n),
  coupon:  (c) => fetch('/api/v2/coupon', { method: 'POST', body: JSON.stringify({ code: c }) }),
  price:   (p) => fetch('/api/v2/price', { method: 'POST', body: JSON.stringify({ price: p }) }),
  adminUsers: () => fetch('/api/v2/admin/users'),
};
export const token = localStorage.setItem('access_token', 'lab-token');
`

function send(res, status, body, type = 'application/json', extra = {}) {
  res.writeHead(status, { 'content-type': type, server: 'lab-shop/0.1', ...extra })
  res.end(typeof body === 'string' ? body : JSON.stringify(body))
}

function cookieRole(req) {
  const cookie = String(req.headers.cookie ?? '')
  const m = cookie.match(/role=([^;]+)/)
  return m ? decodeURIComponent(m[1]) : ''
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
  })
}

const main = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://127.0.0.1:${MAIN_PORT}`)
  const p = url.pathname
  try {
    if (p === '/') return send(res, 200, HTML, 'text/html; charset=utf-8')
    if (p === '/assets/app.js') return send(res, 200, APP_JS, 'application/javascript')
    if (p === '/.git/config') return send(res, 200, '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://git.lab.local/shop.git\n', 'text/plain')
    if (p === '/backup.zip') return send(res, 200, 'PK\u0003\u0004lab-backup', 'application/zip')
    if (p === '/robots.txt') return send(res, 200, 'User-agent: *\nDisallow: /admin\n', 'text/plain')

    if (p === '/admin') {
      if (cookieRole(req) !== 'admin') return send(res, 403, { error: 'forbidden' })
      return send(res, 200, '<html><body><h1>Admin</h1><ul><li>users</li><li>coupons</li></ul></body></html>', 'text/html; charset=utf-8')
    }

    if (p === '/api/v2/login') {
      const body = await readBody(req)
      const params = new URLSearchParams(body)
      const u = params.get('u') ?? (body.startsWith('{') ? JSON.parse(body).u : '')
      const pw = params.get('p') ?? (body.startsWith('{') ? JSON.parse(body).p : '')
      if (u === 'admin' && pw === 'admin123') return send(res, 200, { ok: true, role: 'admin' }, 'application/json', { 'set-cookie': 'role=admin; Path=/; SameSite=Lax' })
      if (u === 'user' && pw === 'user123') return send(res, 200, { ok: true, role: 'user' }, 'application/json', { 'set-cookie': 'role=user; Path=/; SameSite=Lax' })
      return send(res, 401, { error: 'bad credentials' })
    }

    // IDOR：不校验订单归属
    if (p === '/api/v2/orders') {
      const id = Number(url.searchParams.get('id') ?? 0)
      const order = orders.find((o) => o.id === id)
      return order ? send(res, 200, order) : send(res, 404, { error: 'not found' })
    }

    // 只信任 cookie 的 admin 面
    if (p === '/api/v2/admin/users') {
      if (cookieRole(req) !== 'admin') return send(res, 403, { error: 'forbidden' })
      return send(res, 200, users)
    }

    // 反射 XSS + 伪 SQL 拼接（错误回显整条语句）
    if (p === '/api/v2/search') {
      const q = url.searchParams.get('q') ?? ''
      const query = `SELECT * FROM products WHERE name LIKE '%${q}%'`
      if (q.includes("'") && !/OR\s+1\s*=\s*1/i.test(q)) {
        return send(res, 500, { error: `SQL syntax error near '${q}'`, query }, 'application/json')
      }
      const rows = /OR\s+1\s*=\s*1/i.test(q) ? orders : orders.filter((o) => o.item.includes(q) || q === '')
      return send(res, 200, `<html><body><h2>结果 for ${q}</h2><pre>${JSON.stringify(rows)}</pre></body></html>`, 'text/html; charset=utf-8')
    }

    // 命令注入（模拟 ping/curl）：分号后只允许 curl/echo，用于带外验证
    if (p === '/api/v2/ping') {
      const host = url.searchParams.get('host') ?? ''
      let out = `PING ${host}: 1 packets transmitted\n`
      const cmd = host.includes(';') ? host.split(';').slice(1).join(';').trim() : ''
      const target = cmd.startsWith('curl ') ? cmd.slice(5).trim() : (host.startsWith('http') ? host : '')
      if (target) {
        try {
          const r = await fetch(target, { signal: AbortSignal.timeout(4000) })
          out += `curl ${target} -> ${r.status}\n`
        } catch (error) {
          out += `curl ${target} -> error ${error.message}\n`
        }
      }
      return send(res, 200, out, 'text/plain', { 'x-lab-note': 'simulated shell; only curl/echo allowed' })
    }

    // SSRF：主站可被诱导访问内网 18201
    if (p === '/api/v2/fetch') {
      const target = url.searchParams.get('url') ?? ''
      try {
        const r = await fetch(target, { signal: AbortSignal.timeout(4000) })
        const text = await r.text()
        return send(res, 200, { status: r.status, body: text.slice(0, 800) })
      } catch (error) {
        return send(res, 502, { error: String(error?.message ?? error) })
      }
    }

    // 路径穿越：允许跳出 base
    if (p === '/api/v2/download') {
      const file = url.searchParams.get('file') ?? 'readme.txt'
      const full = path.resolve(UPLOADS, file)
      try {
        return send(res, 200, fs.readFileSync(full, 'utf8'), 'text/plain')
      } catch {
        return send(res, 404, { error: 'no such file', resolved: full })
      }
    }

    if (p === '/api/v2/upload' && req.method === 'POST') {
      const name = (url.searchParams.get('name') ?? 'shell.js').replace(/[^\w.-]/g, '')
      const body = await readBody(req)
      fs.writeFileSync(path.join(UPLOADS, name), body)
      return send(res, 200, { saved: `uploads/${name}`, bytes: body.length })
    }

    // 上传后执行（链式利用的最后一环）
    if (p === '/api/v2/run') {
      const name = (url.searchParams.get('name') ?? '').replace(/[^\w.-]/g, '')
      const full = path.join(UPLOADS, name)
      if (!fs.existsSync(full)) return send(res, 404, { error: 'no such script' })
      try {
        const code = fs.readFileSync(full, 'utf8')
        const value = eval(code) // lab only
        return send(res, 200, { ran: name, result: String(value) })
      } catch (error) {
        return send(res, 500, { error: String(error?.message ?? error) })
      }
    }

    // 模板注入：把 {{a*b}} 直接求值
    if (p === '/api/v2/template') {
      const name = url.searchParams.get('name') ?? ''
      const rendered = name.replace(/\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}/g, (_m, a, b) => String(Number(a) * Number(b)))
      return send(res, 200, rendered, 'text/plain')
    }

    // 竞态：读-写之间有 await，额度可被并发打穿
    if (p === '/api/v2/coupon' && req.method === 'POST') {
      const body = await readBody(req)
      let code = ''
      try {
        code = JSON.parse(body).code ?? ''
      } catch {}
      const used = couponUsed
      await new Promise((r) => setTimeout(r, 5))
      if (used < COUPON_LIMIT) {
        couponUsed = used + 1
        return send(res, 200, { ok: true, coupon: code, used: couponUsed })
      }
      return send(res, 409, { ok: false, error: 'coupon exhausted', used: couponUsed })
    }

    // 价格篡改：直接采信客户端金额
    if (p === '/api/v2/price' && req.method === 'POST') {
      const body = await readBody(req)
      let price = 0
      try {
        price = Number(JSON.parse(body).price)
      } catch {}
      return send(res, 200, { ok: true, charged: price, note: 'server trusts client price' })
    }

    return send(res, 404, { error: 'not found' })
  } catch (error) {
    return send(res, 500, { error: String(error?.message ?? error), stack: String(error?.stack ?? '').split('\n').slice(0, 4) })
  }
})

const internal = http.createServer((req, res) => {
  if (req.url?.startsWith('/metadata')) {
    return send(res, 200, { accessKeyId: 'AKIA-LAB-ONLY', secretAccessKey: 'lab-secret-key', token: 'lab-session-token' })
  }
  return send(res, 404, { error: 'internal only' })
})

main.listen(MAIN_PORT, '127.0.0.1', () => process.stdout.write(`lab main on http://127.0.0.1:${MAIN_PORT}\n`))
internal.listen(INTERNAL_PORT, '127.0.0.1', () => process.stdout.write(`lab internal on http://127.0.0.1:${INTERNAL_PORT} (loopback)\n`))
