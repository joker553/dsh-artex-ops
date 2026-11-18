#!/usr/bin/env node
// ARTEX ops MCP server (stdio, newline-delimited JSON-RPC 2.0).
//
// Any MCP-capable client can mount this and get the same 17 tools the DSH plugin
// registers — that is the portable path: LibreChat / Claude Desktop / Codex / Cursor
// / DSH-via-dsh-mcp-client all speak this protocol.
//
//   { "mcpServers": { "artex-ops": { "command": "node",
//       "args": ["C:/path/to/dsh-artex-ops/bin/artex-ops-mcp.mjs"],
//       "env": { "ARTEX_OPS_HOME": "C:/Users/you/.dsh/artex-ops" } } } }
import process from 'node:process'
import { createEngine } from '../lib/engine.js'

const SERVER_INFO = { name: 'artex-ops', version: '1.0.0' }
const PROTOCOLS = ['2025-06-18', '2025-03-26', '2024-11-05']

const config = {}
if (process.env.ARTEX_OPS_HOME) config.dataDir = process.env.ARTEX_OPS_HOME
if (process.env.ARTEX_OPS_OOB_PORT) config.oob = { port: Number(process.env.ARTEX_OPS_OOB_PORT) }
if (process.env.ARTEX_OPS_OOB_HOST) config.oob = { ...(config.oob ?? {}), bindHost: process.env.ARTEX_OPS_OOB_HOST }
if (process.env.ARTEX_OPS_OOB_PUBLIC_HOST) config.oob = { ...(config.oob ?? {}), publicHost: process.env.ARTEX_OPS_OOB_PUBLIC_HOST }

const engine = createEngine(config)

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`)
}

function reply(id, result) {
  send({ jsonrpc: '2.0', id, result })
}

function fail(id, code, message) {
  send({ jsonrpc: '2.0', id, error: { code, message } })
}

const text = (value) => [
  { type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) },
]

async function handle(message) {
  const { id, method, params } = message
  const isNotification = id === undefined || id === null
  try {
    switch (method) {
      case 'initialize': {
        const requested = String(params?.protocolVersion ?? '')
        const protocolVersion = PROTOCOLS.includes(requested) ? requested : PROTOCOLS[0]
        if (!isNotification) {
          reply(id, {
            protocolVersion,
            capabilities: { tools: { listChanged: false }, logging: {} },
            serverInfo: SERVER_INFO,
            instructions:
              'ARTEX ops：对话式渗透的本地状态层。每轮先调 pt_next 拿「本轮该干什么」，再按 decision 执行；盲漏洞先 pt_oob_new 拿探测点，回连后用 pt_oob_poll 确认。数据目录 ' +
              engine.dataDir,
          })
        }
        return
      }
      case 'notifications/initialized':
      case 'initialized':
        return
      case 'ping':
        if (!isNotification) reply(id, {})
        return
      case 'tools/list':
        if (!isNotification) reply(id, { tools: engine.catalog() })
        return
      case 'tools/call': {
        const name = params?.name
        if (!name) throw new Error('tools/call requires params.name')
        const result = await engine.call(name, params?.arguments ?? {})
        if (!isNotification) reply(id, { content: text(result), isError: false })
        return
      }
      case 'resources/list':
        if (!isNotification) reply(id, { resources: [] })
        return
      case 'prompts/list':
        if (!isNotification) reply(id, { prompts: [] })
        return
      case 'shutdown':
        if (!isNotification) reply(id, null)
        await engine.close()
        process.exit(0)
        return
      default:
        if (!isNotification) fail(id, -32601, `method not found: ${method}`)
        return
    }
  } catch (error) {
    if (!isNotification) fail(id, -32000, String(error?.message ?? error))
  }
}

let buffer = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', (chunk) => {
  buffer += chunk
  let newline = buffer.indexOf('\n')
  while (newline >= 0) {
    const line = buffer.slice(0, newline).trim()
    buffer = buffer.slice(newline + 1)
    if (line !== '') {
      try {
        const message = JSON.parse(line)
        if (Array.isArray(message)) for (const item of message) void handle(item)
        else void handle(message)
      } catch (error) {
        fail(null, -32700, `parse error: ${error?.message ?? error}`)
      }
    }
    newline = buffer.indexOf('\n')
  }
})

process.stdin.on('end', async () => {
  await engine.close()
  process.exit(0)
})
process.on('SIGTERM', async () => {
  await engine.close()
  process.exit(0)
})
