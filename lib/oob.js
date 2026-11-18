// Out-of-band (OAST) callback listener.
//
// Blind SSRF / blind RCE / XXE / blind SQLi / JNDI produce no response on the
// request that triggers them — the only evidence is the target calling back. This
// module owns a tiny HTTP listener (and an optional DNS responder) plus a bounded
// in-memory hit log mirrored to ndjson, so a callback becomes an observable fact
// instead of a guess.
//
// Defaults are deliberately local-only: bind 127.0.0.1, port 18080 (fall back to an
// ephemeral port when taken). Point `oob.publicHost` at an address the target can
// reach (LAN IP or a tunnel host) before sending payloads at a remote target.
import fs from 'node:fs'
import http from 'node:http'
import dgram from 'node:dgram'
import { defaultPublicHost } from './paths.js'

const MAX_HITS = 500
const MAX_BODY = 4096
const TOKEN_RE = /[a-f0-9]{16,}/

function truncate(value, max) {
  const text = typeof value === 'string' ? value : String(value ?? '')
  return text.length <= max ? text : `${text.slice(0, max)}…(+${text.length - max}B)`
}

function pickHeaders(headers) {
  const out = {}
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (value === undefined) continue
    out[key] = truncate(Array.isArray(value) ? value.join(', ') : String(value), 300)
  }
  return out
}

/** Minimal DNS question-name decoder for a raw query packet. */
function decodeQName(buffer) {
  const labels = []
  let offset = 12
  while (offset < buffer.length) {
    const length = buffer[offset]
    if (length === 0) break
    if ((length & 0xc0) !== 0) {
      offset += 2
      break
    }
    labels.push(buffer.toString('ascii', offset + 1, offset + 1 + length))
    offset += length + 1
  }
  return labels.join('.')
}

/** Build an answer packet that resolves the queried name to 127.0.0.1 (A). */
function buildAnswer(query, ip = '127.0.0.1') {
  const answer = Buffer.alloc(query.length + 16)
  query.copy(answer, 0)
  answer.writeUInt16BE(0x8180, 2) // response + recursion available
  answer.writeUInt16BE(1, 6) // answer count
  let offset = 12
  while (offset < query.length && query[offset] !== 0) {
    if ((query[offset] & 0xc0) !== 0) {
      offset += 2
      break
    }
    offset += query[offset] + 1
  }
  offset += 1
  answer.writeUInt16BE(0xc00c, offset) // pointer to the question name
  answer.writeUInt16BE(1, offset + 2) // type A
  answer.writeUInt16BE(1, offset + 4) // class IN
  answer.writeUInt32BE(1, offset + 6) // TTL
  answer.writeUInt16BE(4, offset + 10) // RDLENGTH
  const octets = ip.split('.').map((part) => Number(part) & 0xff)
  for (let i = 0; i < 4; i++) answer[offset + 12 + i] = octets[i] ?? 0
  return answer.subarray(0, offset + 16)
}

export class OobServer {
  constructor({ store, paths, config = {}, log = () => {} }) {
    this.store = store
    this.paths = paths
    this.config = config?.oob ?? {}
    this.log = log
    this.hits = []
    this.httpServer = null
    this.dnsSocket = null
    this.bound = null
    this.dnsBound = null
    this.starting = null
  }

  get bindHost() {
    return typeof this.config.bindHost === 'string' && this.config.bindHost.trim() !== ''
      ? this.config.bindHost.trim()
      : '127.0.0.1'
  }

  get publicHost() {
    const configured = typeof this.config.publicHost === 'string' ? this.config.publicHost.trim() : ''
    if (configured !== '') return configured
    const bind = this.bindHost
    if (bind === '0.0.0.0' || bind === '::') return defaultPublicHost()
    return bind
  }

  get requestedPort() {
    const port = Number(this.config.port ?? 18080)
    if (!Number.isFinite(port) || port < 0 || port > 65535) return 18080
    return Math.trunc(port)
  }

  baseUrl() {
    if (!this.bound) return ''
    const portOverride = Number(this.config.publicPort)
    const port = Number.isFinite(portOverride) && portOverride > 0 ? portOverride : this.bound.port
    return `http://${this.publicHost}:${port}`
  }

  /** Start the HTTP listener on first use; idempotent and safe under concurrency. */
  async ensure() {
    if (this.bound) return this.info()
    if (this.starting) return this.starting
    this.starting = (async () => {
      const listen = (port) =>
        new Promise((resolve, reject) => {
          const server = http.createServer((req, res) => this.handleRequest(req, res))
          server.on('clientError', (_error, socket) => socket.destroy())
          const onError = (error) => {
            server.removeListener('listening', onListening)
            reject(error)
          }
          const onListening = () => {
            server.removeListener('error', onError)
            resolve(server)
          }
          server.once('error', onError)
          server.once('listening', onListening)
          server.listen(port, this.bindHost)
        })

      try {
        this.httpServer = await listen(this.requestedPort)
      } catch (error) {
        if (error?.code === 'EADDRINUSE' && this.requestedPort !== 0) {
          this.httpServer = await listen(0)
        } else if (error?.code === 'EACCES') {
          this.httpServer = await listen(0)
        } else {
          throw error
        }
      }
      const address = this.httpServer.address()
      this.bound = { port: typeof address === 'object' && address ? address.port : 0, host: this.bindHost }
      this.httpServer.unref?.()
      fs.mkdirSync(this.paths.oob, { recursive: true })
      this.log(`oob http listening on ${this.bindHost}:${this.bound.port} (public ${this.publicHost})`)
      await this.startDns()
      return this.info()
    })()
    try {
      return await this.starting
    } finally {
      this.starting = null
    }
  }

  async startDns() {
    const dnsConfig = this.config?.dns ?? {}
    if (dnsConfig.enabled !== true) return
    const port = Number(dnsConfig.port ?? 53)
    const bindHost = typeof dnsConfig.bindHost === 'string' ? dnsConfig.bindHost : '0.0.0.0'
    const socket = dgram.createSocket('udp4')
    await new Promise((resolve) => {
      socket.once('error', (error) => {
        this.dnsBound = { active: false, error: error?.code ?? String(error) }
        this.log(`oob dns disabled: ${this.dnsBound.error}`)
        try {
          socket.close()
        } catch {}
        resolve()
      })
      socket.on('message', (message, remote) => {
        try {
          const qname = decodeQName(message)
          this.recordHit({
            proto: 'dns',
            path: qname,
            method: 'QUERY',
            remote: `${remote.address}:${remote.port}`,
            headers: {},
            body: '',
          })
          const isQuery = message.length > 4 && (message[2] & 0x80) === 0
          if (isQuery) socket.send(buildAnswer(message), remote.port, remote.address, () => {})
        } catch (error) {
          this.log(`oob dns parse error: ${error?.message ?? error}`)
        }
      })
      socket.bind(port, bindHost, () => {
        socket.unref?.()
        this.dnsBound = { active: true, port, bindHost }
        this.log(`oob dns listening on ${bindHost}:${port}`)
        resolve()
      })
    })
    this.dnsSocket = socket
  }

  info() {
    return {
      listening: this.bound !== null,
      bindHost: this.bound?.host ?? this.bindHost,
      port: this.bound?.port ?? 0,
      publicHost: this.publicHost,
      baseUrl: this.baseUrl(),
      dns: this.dnsBound ?? { active: false },
      hits: this.hits.length,
    }
  }

  handleRequest(req, res) {
    const chunks = []
    let size = 0
    req.on('data', (chunk) => {
      if (size >= MAX_BODY) return
      size += chunk.length
      chunks.push(chunk)
    })
    req.on('end', () => {
      const body = truncate(Buffer.concat(chunks).toString('utf8'), MAX_BODY)
      this.recordHit({
        proto: 'http',
        path: truncate(req.url ?? '/', 2048),
        method: req.method ?? 'GET',
        remote: `${req.socket?.remoteAddress ?? '?'}:${req.socket?.remotePort ?? 0}`,
        headers: pickHeaders(req.headers),
        body,
      })
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
      res.end('ok\n')
    })
    req.on('error', () => {})
  }

  /** Append one hit, attribute it to a known probe by token, and persist it. */
  recordHit({ proto, path: hitPath, method, remote, headers, body }) {
    const haystack = `${hitPath} ${body} ${headers?.['x-forwarded-host'] ?? ''}`
    const match = haystack.match(TOKEN_RE)
    const token = match ? match[0] : ''
    const shot = token === '' ? undefined : this.store.oobShot(token)
    const hit = {
      ts: Date.now(),
      proto,
      token,
      oobId: shot?.id ?? '',
      method,
      path: truncate(hitPath, 2048),
      remote,
      headers,
      body,
    }
    this.hits.push(hit)
    if (this.hits.length > MAX_HITS) this.hits.splice(0, this.hits.length - MAX_HITS)
    if (shot) this.store.bumpHit(shot.id)
    try {
      fs.mkdirSync(this.paths.oob, { recursive: true })
      fs.appendFileSync(this.paths.oobLog, `${JSON.stringify(hit)}\n`, 'utf8')
    } catch (error) {
      this.log(`oob log append failed: ${error?.message ?? error}`)
    }
    return hit
  }

  /** Hits for one probe (by id or token), or the newest hits when no filter is given. */
  poll({ id = '', since = 0, limit = 20 } = {}) {
    let rows = this.hits
    if (id !== '') {
      const shot = this.store.oobShot(id)
      const token = shot?.token ?? id
      rows = rows.filter((hit) => hit.token === token)
    }
    if (since > 0) rows = rows.filter((hit) => hit.ts > since)
    const cap = Math.max(1, Math.min(100, Number(limit) || 20))
    return rows.slice(-cap)
  }

  async close() {
    const closers = []
    if (this.httpServer) {
      const server = this.httpServer
      this.httpServer = null
      this.bound = null
      closers.push(new Promise((resolve) => server.close(() => resolve())))
    }
    if (this.dnsSocket) {
      const socket = this.dnsSocket
      this.dnsSocket = null
      this.dnsBound = null
      closers.push(new Promise((resolve) => socket.close(() => resolve())))
    }
    await Promise.all(closers)
  }
}
