// dsh-artex-ops — 可热重载的宿主外壳（Cordis 插件入口）
//
// 为什么不再把实现直接 import 进这里：ESM 模块一旦被宿主加载就无法卸载，插件进程
// 里的代码会冻结到 DeepSeekRuntime 重启为止（这也是之前每次改代码都得重启、我只能
// 用 CLI 验证新工具的原因）。现在实现跑在子进程 lib/serve.mjs 里：
//
//   • 工具的 name/description/schema 由子进程的 catalog 提供，宿主只做注册与转发；
//   • lib/ 一改（新增工具、改提示词、改行为），宿主就杀掉子进程、重启、重新读 catalog，
//     并按名字差量注销/注册工具 —— 不重启宿主、不丢会话；
//   • 子进程崩了自动拉起；宿主卸载时一起回收。
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const name = 'dsh-artex-ops'
export const inject = ['tools']

const HERE = path.dirname(fileURLToPath(import.meta.url))
const LIB_DIR = path.join(HERE, 'lib')
const SERVE = path.join(LIB_DIR, 'serve.mjs')
const ANY_OBJECT = { type: 'object', additionalProperties: true }

class Rpc {
  constructor(log, config) {
    this.log = log
    this.config = config ?? {}
    this.child = null
    this.seq = 0
    this.pending = new Map()
    this.buffer = ''
    this.closed = false
  }

  start() {
    if (this.closed) return
    const child = spawn(process.execPath, [SERVE], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        ...(this.config?.dataDir ? { ARTEX_OPS_HOME: String(this.config.dataDir) } : {}),
        ARTEX_OPS_CONFIG: JSON.stringify(this.config ?? {}),
        ELECTRON_RUN_AS_NODE: '1',
      },
      windowsHide: true,
    })
    this.child = child
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (chunk) => this.onData(chunk))
    child.stderr.setEncoding('utf8')
    child.stderr.on('data', (chunk) => {
      const text = String(chunk).trim()
      if (text !== '') this.log(`impl: ${text}`)
    })
    child.on('error', (error) => this.log(`impl spawn error: ${error?.message ?? error}`))
    child.on('exit', (code, signal) => {
      if (this.child === child) this.child = null
      for (const [, entry] of this.pending) entry.reject(new Error(`artex-ops impl exited (code=${code}, signal=${signal})`))
      this.pending.clear()
    })
  }

  onData(chunk) {
    this.buffer += chunk
    let index = this.buffer.indexOf('\n')
    while (index >= 0) {
      const line = this.buffer.slice(0, index).trim()
      this.buffer = this.buffer.slice(index + 1)
      index = this.buffer.indexOf('\n')
      if (line === '') continue
      let message
      try {
        message = JSON.parse(line)
      } catch {
        this.log(`impl protocol: unparsable line ${line.slice(0, 120)}`)
        continue
      }
      const entry = this.pending.get(message.id)
      if (!entry) continue
      this.pending.delete(message.id)
      if (message.ok) entry.resolve(message)
      else entry.reject(new Error(message.error ?? 'impl error'))
    }
  }

  request(op, extra = {}, timeoutMs = 120000) {
    if (!this.child) {
      this.start()
      if (!this.child) return Promise.reject(new Error('artex-ops impl not running'))
    }
    const id = ++this.seq
    const payload = JSON.stringify({ id, op, ...extra })
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error(`artex-ops impl timeout after ${timeoutMs}ms (${op})`))
      }, timeoutMs)
      this.pending.set(id, {
        resolve: (value) => {
          clearTimeout(timer)
          resolve(value)
        },
        reject: (error) => {
          clearTimeout(timer)
          reject(error)
        },
      })
      try {
        this.child.stdin.write(`${payload}\n`)
      } catch (error) {
        clearTimeout(timer)
        this.pending.delete(id)
        reject(error)
      }
    })
  }

  async stop() {
    const child = this.child
    this.child = null
    if (!child) return
    try {
      child.stdin.write(`${JSON.stringify({ id: ++this.seq, op: 'shutdown' })}\n`)
    } catch {}
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        try {
          child.kill()
        } catch {}
        resolve()
      }, 800)
      child.once('exit', () => {
        clearTimeout(timer)
        resolve()
      })
    })
  }

  close() {
    this.closed = true
    return this.stop()
  }
}

function renderResult(_args, value) {
  return [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }]
}

export function apply(ctx, config = {}) {
  if (config?.enabled === false) return
  const debug = config?.debug === true
  const log = (message) => {
    try {
      if (typeof ctx.logger === 'function') {
        const logger = ctx.logger('artex-ops')
        if (typeof logger?.info === 'function') return logger.info(message)
      }
    } catch {}
    if (debug) console.log(`[artex-ops] ${message}`)
  }

  const rpc = new Rpc(log, config)
  rpc.start()

  /** name → {disposer, signature} */
  const registered = new Map()
  let sectionDisposer = null
  let latestPrompt = null
  let promptCtx = null

  const makeTool = (definition) => ({
    name: definition.name,
    description: definition.description,
    parameters: definition.inputSchema ?? { type: 'object', properties: {} },
    output: { schema: ANY_OBJECT, render: renderResult },
    async execute(args = {}) {
      const reply = await rpc.request('call', { tool: definition.name, args })
      return reply.result
    },
  })

  const disposeTool = (toolName) => {
    const entry = registered.get(toolName)
    if (!entry) return
    registered.delete(toolName)
    try {
      entry.disposer()
    } catch {}
  }

  const registerSection = () => {
    if (latestPrompt === null || promptCtx === null) return
    try {
      sectionDisposer?.()
    } catch {}
    sectionDisposer = promptCtx.systemPrompt.section({
      name: latestPrompt.name,
      order: latestPrompt.order,
      text: latestPrompt.text,
    })
  }

  const sync = async (reason) => {
    const catalog = await rpc.request('catalog', {}, 20000)
    const definitions = catalog.tools ?? []
    const incoming = new Set(definitions.map((definition) => definition.name))
    for (const toolName of [...registered.keys()]) {
      if (!incoming.has(toolName)) disposeTool(toolName)
    }
    for (const definition of definitions) {
      const signature = JSON.stringify([definition.description, definition.inputSchema])
      const existing = registered.get(definition.name)
      if (existing && existing.signature === signature) continue
      disposeTool(definition.name)
      const disposer = ctx.tools.register(makeTool(definition))
      registered.set(definition.name, { disposer, signature })
    }
    latestPrompt = catalog.prompt ?? latestPrompt
    registerSection()
    log(`tools synced (${reason}): ${registered.size} registered`)
  }

  void sync('boot').catch((error) => log(`initial sync failed: ${error?.message ?? error}`))

  // 可选服务：提示词段按 catalog 里的最新文本注册（重载后会重挂）。
  ctx.inject(['systemPrompt'], (sub) => {
    promptCtx = sub
    registerSection()
    return () => {
      try {
        sectionDisposer?.()
      } catch {}
    }
  })

  // lib/ 变动 → 重启实现子进程 → 差量重注册。这就是"不再需要重启 DeepSeekRuntime"。
  let timer = null
  let reloads = 0
  const reload = () => {
    reloads += 1
    void (async () => {
      log(`lib changed, reloading impl (#${reloads})`)
      await rpc.stop()
      rpc.start()
      await sync(`reload#${reloads}`)
    })().catch((error) => log(`reload failed: ${error?.message ?? error}`))
  }
  let watcher = null
  try {
    watcher = fs.watch(LIB_DIR, { persistent: false }, (_event, filename) => {
      if (filename && !/\.m?js$/.test(String(filename))) return
      clearTimeout(timer)
      timer = setTimeout(reload, 400)
    })
  } catch (error) {
    log(`watch disabled: ${error?.message ?? error}`)
  }

  ctx.effect(() => () => {
    clearTimeout(timer)
    try {
      watcher?.close()
    } catch {}
    for (const toolName of [...registered.keys()]) disposeTool(toolName)
    try {
      sectionDisposer?.()
    } catch {}
    void rpc.close()
  }, 'artex-ops: impl child + tool registrations')
}
