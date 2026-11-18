// SPA-style fixture: the HTML is a shell, the surface lives in the JS bundle.
// Used to prove pt_recon mines hidden endpoints / params / feature points.
import http from 'node:http'

const PORT = Number(process.argv[2] ?? 18100)

const HTML = `<!doctype html>
<html><head>
  <title>Demo SPA</title>
  <script src="/assets/app.js" defer></script>
  <link rel="stylesheet" href="/assets/app.css">
</head><body>
  <a href="/orders?status=open&page=2">我的订单</a>
  <a href="/admin/users">用户管理</a>
  <form action="/api/v2/login" method="post"><input name="username"><button>登录</button></form>
  <button data-action="export">导出报表</button>
  <script>window.__BOOT__ = { apiBase: "/api/v2", graphql: "/graphql", featureFlags: ["betaConsole","bulkExport"] };</script>
</body></html>`

const APP_JS = `
const api = axios.create({ baseURL: '/api/v2' });
export async function listOrders(page) { return fetch('/api/v2/orders?page=' + page + '&size=20'); }
export function adminUsers() { return axios.get('/api/v2/admin/users'); }
export function deleteUser(id) { return axios.delete('/api/v2/admin/users/' + id); }
export function upload(file) { return fetch('/api/v2/files/upload', { method: 'POST' }); }
export function search(q) { return fetch('/api/v2/search?q=' + q + '&fuzzy=1'); }
export const routes = [
  { path: '/dashboard', component: 'Dashboard' },
  { path: '/orders/:id', component: 'OrderDetail' },
  { path: '/settings/billing', component: 'Billing' },
];
export function login(u, p) { return axios.post('/api/v2/login', { u, p }); }
export const token = localStorage.setItem('access_token', 'demo');
const internal = 'https://internal.corp.example/health';
const raw = '/api/v2/internal/debug?verbose=1';
document.querySelector('#app').innerHTML = location.hash;
`

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://127.0.0.1:${PORT}`)
  if (url.pathname === '/' ) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    return res.end(HTML)
  }
  if (url.pathname === '/assets/app.js') {
    res.writeHead(200, { 'content-type': 'application/javascript' })
    return res.end(APP_JS)
  }
  if (url.pathname === '/assets/app.css') {
    res.writeHead(200, { 'content-type': 'text/css' })
    return res.end('body{font-family:sans-serif}')
  }
  if (url.pathname.startsWith('/api/') || url.pathname === '/graphql') {
    res.writeHead(200, { 'content-type': 'application/json' })
    return res.end(JSON.stringify({ ok: true, path: url.pathname, query: Object.fromEntries(url.searchParams) }))
  }
  res.writeHead(404, { 'content-type': 'text/plain' })
  res.end('not found')
})

server.listen(PORT, '127.0.0.1', () => process.stdout.write(`spa fixture on http://127.0.0.1:${PORT}\n`))
