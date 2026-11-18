#!/usr/bin/env node
// 环境体检：确认「有没有残留的实现子进程 / 状态目录在哪 / 钩子是否生效」。
//
// 用法：node scripts/doctor.mjs
//
// 判据：实现子进程的命令行**以 serve.mjs 结尾**。用 `CommandLine -match 'serve.mjs'`
// 这种宽匹配会把你自己的命令行、宿主包装进程一起算进来，看起来像"残留"。
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const isWindows = process.platform === 'win32'

function implChildren() {
  if (isWindows) {
    const ps = [
      'Get-CimInstance Win32_Process',
      "| Where-Object { $_.CommandLine -and ($_.CommandLine -match 'serve\\.mjs\\s*$') }",
      '| Select-Object ProcessId,ParentProcessId,CreationDate',
      '| ConvertTo-Json -Compress',
    ].join(' ')
    const out = execFileSync('powershell.exe', ['-NoProfile', '-Command', ps], { encoding: 'utf8' }).trim()
    if (out === '') return []
    const parsed = JSON.parse(out)
    return Array.isArray(parsed) ? parsed : [parsed]
  }
  const out = execFileSync('ps', ['-eo', 'pid=,ppid=,args='], { encoding: 'utf8' })
  return out
    .split(/\r?\n/)
    .filter((line) => /serve\.mjs\s*$/.test(line))
    .map((line) => {
      const [pid, ppid] = line.trim().split(/\s+/, 2)
      return { ProcessId: Number(pid), ParentProcessId: Number(ppid) }
    })
}

function dataDir() {
  if (process.env.ARTEX_OPS_HOME) return path.resolve(process.env.ARTEX_OPS_HOME)
  const dshHome = process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh')
  return path.join(dshHome, 'artex-ops')
}

const children = implChildren()
const dir = dataDir()

let state = null
try {
  const raw = JSON.parse(fs.readFileSync(path.join(dir, 'state.json'), 'utf8'))
  state = {
    mission: raw.mission?.id ?? null,
    intents: raw.intents?.length ?? 0,
    assets: raw.assets?.length ?? 0,
    facts: raw.facts?.length ?? 0,
    findings: raw.findings?.length ?? 0,
    evidence: raw.evidence?.length ?? 0,
    hints: raw.hints?.length ?? 0,
    steps: raw.activity?.length ?? 0,
  }
} catch {}

let missions = 0
try {
  missions = fs.readdirSync(path.join(dir, 'missions')).length
} catch {}

let hook = ''
try {
  hook = execFileSync('git', ['config', 'core.hooksPath'], { encoding: 'utf8' }).trim()
} catch {}

console.log('artex-ops doctor')
console.log(`  实现子进程 : ${children.length} 个${children.map((row) => ` (pid ${row.ProcessId} ← parent ${row.ParentProcessId})`).join('')}`)
console.log(`  数据目录   : ${dir}`)
console.log(`  mission 数 : ${missions}（工作目录 <dataDir>/missions/<id>/）`)
if (state) console.log(`  state      : mission=${state.mission} intents=${state.intents} assets=${state.assets} facts=${state.facts} findings=${state.findings} evidence=${state.evidence} hints=${state.hints} steps=${state.steps}`)
else console.log('  state      : (无 state.json)')
console.log(`  pre-commit : ${hook === '.githooks' ? '已启用 (.githooks)' : hook === '' ? '未设置' : hook}`)
if (children.length > 1) {
  console.log('')
  console.log('提示：多于 1 个实现子进程通常是历史 reload 的孤儿；杀掉多余的即可，宿主下次调用会自动重拉：')
  console.log(`  Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'serve\\.mjs\\s*$' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }`)
}
