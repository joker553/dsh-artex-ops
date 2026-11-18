// Local fixture for the live ARTEX-loop demonstration (no real target involved).
// Vulnerabilities are deliberately planted so the loop has something honest to find:
//   /api/v1/users   → no auth check, dumps user rows (missing authentication)
//   /upload         → accepts any extension and reports a stored path (weak validation)
//   /u/*.php        → served as static text; NOT executed (so it must not be reported as RCE)
//   /admin          → 403 unless cookie role=admin
import http from 'node:http'

const PORT = Number(process.argv[2] ?? 18099)
const users = [
  { id: 1, email: 'alice@demo.test', role: 'admin' },
  { id: 2, email: 'bob@demo.test', role: 'user' },
]

const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://127.0.0.1:${PORT}`)
  const send = (status, body, type = 'application/json') => {
    res.writeHead(status, { 'content-type': type, server: 'demo-app/1.0' })
    res.end(body)
  }
  if (url.pathname === '/') return send(200, JSON.stringify({ app: 'demo-app', version: '1.0.0' }))
  if (url.pathname === '/api/v1/users') return send(200, JSON.stringify(users))
  if (url.pathname === '/api/health') return send(200, JSON.stringify({ ok: true }))
  if (url.pathname === '/admin') {
    const cookie = String(req.headers.cookie ?? '')
    return cookie.includes('role=admin') ? send(200, JSON.stringify({ ok: 'welcome admin' })) : send(403, JSON.stringify({ error: 'forbidden' }))
  }
  if (url.pathname === '/upload' && req.method === 'POST') {
    let size = 0
    req.on('data', (chunk) => (size += chunk.length))
    req.on('end', () => send(200, JSON.stringify({ path: '/u/shell.php', bytes: size })))
    return
  }
  if (url.pathname.startsWith('/u/')) {
    return send(200, '<?php echo "would-be-shell"; ?>', 'text/plain')
  }
  return send(404, JSON.stringify({ error: 'not found' }))
})

server.listen(PORT, '127.0.0.1', () => {
  process.stdout.write(`fixture listening on http://127.0.0.1:${PORT}\n`)
})
