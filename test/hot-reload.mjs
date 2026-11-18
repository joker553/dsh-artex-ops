// Proves the hot-reload shell: the host registers tools from the child's catalog,
// tool calls round-trip, and a change under lib/ restarts the implementation and
// re-syncs without the host process restarting.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { apply } from '../index.js'

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'artex-hot-'))
const tools = new Map()
const sections = []
const effects = []

const ctx = {
  tools: {
    register(definition) {
      tools.set(definition.name, definition)
      return () => tools.delete(definition.name)
    },
  },
  inject(_deps, callback) {
    return callback({
      systemPrompt: {
        section(section) {
          sections.push(section)
          return () => {}
        },
      },
    })
  },
  effect(factory) {
    const dispose = factory()
    if (typeof dispose === 'function') effects.push(dispose)
    return dispose
  },
  get: () => undefined,
  logger: undefined,
}

const waitFor = async (predicate, timeoutMs, label) => {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await predicate()) return
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error(`timeout waiting for ${label}`)
}

async function main() {
  apply(ctx, { dataDir, debug: false })

  await waitFor(() => tools.size >= 24, 15000, 'initial tool sync')
  console.log(`  ok  子进程 catalog 注册工具 — ${tools.size} 个`)
  assert.ok(tools.has('pt_state') && tools.has('pt_recon') && tools.has('pt_coverage'))

  const state = await tools.get('pt_state').execute({}, {})
  assert.equal(path.resolve(state.dataDir), path.resolve(dataDir))
  console.log('  ok  tool call 走子进程往返 — dataDir=' + state.dataDir)

  const reconDef = tools.get('pt_recon')
  assert.ok(reconDef.parameters && reconDef.parameters.properties.url, 'schema should come from the child catalog')
  console.log('  ok  schema 由子进程提供（pt_recon.url 存在）')

  const sectionsBefore = sections.length
  const target = path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..', 'lib', 'prompt.js')
  const now = new Date()
  fs.utimesSync(target, now, now)

  await waitFor(() => sections.length > sectionsBefore, 15000, 'reload re-registering the prompt section')
  assert.equal(tools.size, 24, 'tool count stable after reload')
  const stateAfter = await tools.get('pt_state').execute({}, {})
  assert.equal(path.resolve(stateAfter.dataDir), path.resolve(dataDir))
  console.log('  ok  lib 变动 → 重启实现 + 重挂提示段，工具调用仍可用')

  for (const dispose of effects) {
    try {
      await dispose()
    } catch {}
  }
  await new Promise((resolve) => setTimeout(resolve, 600))
  fs.rmSync(dataDir, { recursive: true, force: true })
  console.log('PASS  hot-reload shell')
}

main().catch((error) => {
  console.error('FAIL', error)
  process.exit(1)
})
