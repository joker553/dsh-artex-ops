// Child process that owns the real implementation.
//
// Why a child: the host cannot unload an ES module, so any code shipped inside the
// plugin process is frozen until DeepSeekRuntime restarts. Running the implementation
// here lets the host kill and respawn this process when lib/ changes — the toolset
// (including brand-new tools) reloads without a restart.
//
// Protocol: newline-delimited JSON on stdio.
//   → {"id":1,"op":"catalog"}
//   ← {"id":1,"ok":true,"tools":[{name,description,inputSchema,noLock}]}
//   → {"id":2,"op":"call","tool":"pt_state","args":{}}
//   ← {"id":2,"ok":true,"result":{...}}  |  {"id":2,"ok":false,"error":"..."}
//   → {"id":3,"op":"shutdown"}
import process from 'node:process'
import { createEngine } from './engine.js'
import { SECTION_NAME, SECTION_ORDER, SECTION_TEXT } from './prompt.js'

const config = (() => {
  const raw = process.env.ARTEX_OPS_CONFIG
  if (raw) {
    try {
      const parsed = JSON.parse(raw)
      if (parsed && typeof parsed === 'object') return parsed
    } catch {}
  }
  const fallback = {}
  if (process.env.ARTEX_OPS_HOME) fallback.dataDir = process.env.ARTEX_OPS_HOME
  return fallback
})()

let engine = null
function getEngine() {
  if (!engine) engine = createEngine(config)
  return engine
}

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`)
}

async function handle(message) {
  const { id, op } = message ?? {}
  try {
    if (op === 'catalog') {
      const tools = getEngine().catalog().map((tool) => ({
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema,
        noLock: false,
      }))
      // noLock 只在宿主侧影响加锁策略，这里从引擎元数据补上
      for (const tool of tools) {
        const internal = getEngine().tools.find((item) => item.name === tool.name)
        if (internal?.noLock === true) tool.noLock = true
      }
      const prompt = { name: SECTION_NAME, order: SECTION_ORDER, text: SECTION_TEXT }
      return send({ id, ok: true, tools, prompt })
    }
    if (op === 'call') {
      const result = await getEngine().call(message.tool, message.args ?? {})
      return send({ id, ok: true, result })
    }
    if (op === 'ping') return send({ id, ok: true, pid: process.pid })
    if (op === 'shutdown') {
      send({ id, ok: true })
      await getEngine().close()
      process.exit(0)
    }
    send({ id, ok: false, error: `unknown op ${JSON.stringify(op)}` })
  } catch (error) {
    send({ id, ok: false, error: String(error?.message ?? error) })
  }
}

let buffer = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', (chunk) => {
  buffer += chunk
  let index = buffer.indexOf('\n')
  while (index >= 0) {
    const line = buffer.slice(0, index).trim()
    buffer = buffer.slice(index + 1)
    index = buffer.indexOf('\n')
    if (line !== '') {
      try {
        void handle(JSON.parse(line))
      } catch (error) {
        send({ id: null, ok: false, error: `parse: ${error?.message ?? error}` })
      }
    }
  }
})
process.stdin.on('end', () => process.exit(0))
