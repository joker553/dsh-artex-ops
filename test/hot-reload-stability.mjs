// 热重载稳定性：连续改动 lib/ 时，宿主必须始终只有一个实现子进程，且工具面可用。
//
// 这是之前"reload 留下孤儿进程、宿主还绑在旧进程上"的回归测试。
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { apply } from '../index.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const libDir = path.join(here, '..', 'lib')
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'artex-stability-'))
const tools = new Map()
const effects = []
let sections = 0

const ctx = {
  tools: { register: (definition) => (tools.set(definition.name, definition), () => tools.delete(definition.name)) },
  inject: (_deps, callback) => callback({ systemPrompt: { section: () => (sections += 1, () => {}) } }),
  effect: (factory) => {
    const dispose = factory()
    if (typeof dispose === 'function') effects.push(dispose)
    return dispose
  },
  get: () => undefined,
  logger: undefined,
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

const waitFor = async (predicate, timeoutMs, label) => {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await predicate()) return true
    await sleep(100)
  }
  throw new Error(`timeout waiting for ${label}`)
}

/** 当前测试进程名下的实现子进程 pid 列表（精确匹配命令行以 serve.mjs 结尾）。 */
function implPids() {
  if (process.platform === 'win32') {
    const ps = [
      'Get-CimInstance Win32_Process',
      `| Where-Object { $_.ParentProcessId -eq ${process.pid} -and $_.CommandLine -and ($_.CommandLine -match 'serve\\.mjs\\s*$') }`,
      '| Select-Object -ExpandProperty ProcessId',
    ].join(' ')
    const out = execFileSync('powershell.exe', ['-NoProfile', '-Command', ps], { encoding: 'utf8' }).trim()
    return out === '' ? [] : out.split(/\r?\n/).map((line) => Number(line.trim())).filter(Boolean)
  }
  const out = execFileSync('ps', ['-eo', 'pid=,ppid=,args='], { encoding: 'utf8' })
  return out
    .split(/\r?\n/)
    .filter((line) => new RegExp(`^\\s*\\d+\\s+${process.pid}\\s`).test(line) && /serve\.mjs\s*$/.test(line))
    .map((line) => Number(line.trim().split(/\s+/)[0]))
}

const touch = (file) => {
  const now = new Date()
  fs.utimesSync(file, now, now)
}

async function main() {
  apply(ctx, { dataDir, debug: false })
  await waitFor(() => tools.size >= 26, 20000, 'initial tool sync')
  const firstPids = implPids()
  assert.equal(firstPids.length, 1, `expected exactly 1 impl child, got ${firstPids.length}`)
  console.log(`  ok  初始只有 1 个实现子进程（pid ${firstPids[0]}）`)

  // 连续 4 次改动，模拟编辑器保存抖动 / 批量写入
  const target = path.join(libDir, 'prompt.js')
  const pidsSeen = new Set(firstPids)
  for (let i = 0; i < 4; i++) {
    touch(target)
    await sleep(700)
    const pids = implPids()
    assert.ok(pids.length <= 1, `after reload #${i + 1} expected <=1 impl child, got ${pids.length}: ${pids.join(',')}`)
    pids.forEach((pid) => pidsSeen.add(pid))
  }
  await waitFor(() => implPids().length === 1, 10000, 'single impl child after reloads')
  const finalPids = implPids()
  assert.equal(finalPids.length, 1, 'exactly one impl child must survive rapid reloads')
  assert.ok(pidsSeen.size >= 2, 'reloads should actually replace the child process')
  console.log(`  ok  4 次连续改动后仍只有 1 个（共见过 ${pidsSeen.size} 个 pid，说明确实换了进程）`)

  const state = await tools.get('pt_state').execute({}, {})
  assert.equal(path.resolve(state.dataDir), path.resolve(dataDir))
  const next = await tools.get('pt_next').execute({}, {})
  assert.equal(next.decision, 'bootstrap')
  console.log('  ok  重载后工具调用仍可用（pt_state / pt_next）')

  for (const dispose of effects) {
    try {
      await dispose()
    } catch {}
  }
  await waitFor(() => implPids().length === 0, 8000, 'impl child exit on dispose')
  console.log('  ok  卸载后实现子进程退出（无孤儿）')

  fs.rmSync(dataDir, { recursive: true, force: true })
  console.log('PASS  hot-reload stability')
}

main().catch((error) => {
  console.error('FAIL', error)
  process.exit(1)
})
