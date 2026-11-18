#!/usr/bin/env node
// ARTEX ops CLI — the same engine as the DSH plugin, usable from any shell or agent
// harness that can run a command.
//
//   artex-ops state
//   artex-ops next
//   artex-ops mission start --goal "拿到 demo.test 管理员" --scope demo.test
//   artex-ops intent add --summary "枚举 /api 的鉴权缺失接口" --summary "测上传点扩展名绕过"
//   artex-ops intent claim
//   artex-ops fact --label upload-writable --summary "..." --evidence "curl ... -> 200"
//   artex-ops oob new --note "盲 SSRF 探测"
//   artex-ops oob poll --id oob-1 --wait 3000
//   artex-ops report
//   artex-ops call pt_chain_plan '{"title":"...","steps":[...]}'
//
// Global flags: --data <dir>  --json  --help
// Data dir: --data > $ARTEX_OPS_HOME > $DSH_HOME/artex-ops > ~/.dsh/artex-ops
import fs from 'node:fs'
import process from 'node:process'
import { createEngine } from '../lib/engine.js'

const TOOL_BY_COMMAND = {
  mission: 'pt_mission',
  intent: 'pt_intent',
  asset: 'pt_asset',
  finding: 'pt_finding',
  chain: 'pt_chain_plan',
  chainadvance: 'pt_chain_advance',
  fact: 'pt_fact_add',
  facts: 'pt_fact_list',
  cred: 'pt_cred',
  defense: 'pt_defense',
  candidate: 'pt_candidate',
  evidence: 'pt_evidence_save',
  trace: 'pt_trace',
  worker: 'pt_worker',
  hint: 'pt_hint',
  goal: 'pt_goal',
  graph: 'pt_graph',
  coverage: 'pt_coverage',
  recon: 'pt_recon',
  next: 'pt_next',
  state: 'pt_state',
}

// flag → tool argument, for the flags whose names already match.
const DIRECT_FLAGS = [
  'goal', 'title', 'scope', 'constraints', 'replace', 'force', 'reason', 'note', 'evidence',
  'priority', 'id', 'output', 'limit', 'state', 'label', 'host', 'confidence', 'q', 'type',
  'tested', 'severity', 'assetId', 'chainId', 'kind', 'secret', 'username', 'waf',
  'blockedSignature', 'blockedFamilies', 'workingBypass', 'family', 'base', 'source', 'ref',
  'cve', 'verdict', 'oobId', 'name', 'content', 'waitMs', 'ord', 'steps', 'target', 'assets',
  'worker', 'intentId', 'excludeIntent', 'kinds', 'detail', 'summary', 'text', 'goals', 'hintIds', 'classId', 'cat', 'skipResolved', 'url', 'js', 'maxScripts',
]

const LIST_FLAGS = new Set(['scope', 'constraints', 'blockedFamilies', 'kinds', 'goals', 'hintIds', 'js'])

function parseArgv(argv) {
  const flags = { _: [] }
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]
    if (!token.startsWith('--')) {
      flags._.push(token)
      continue
    }
    const key = token.slice(2)
    const next = argv[i + 1]
    const value = next === undefined || next.startsWith('--') ? true : (i++, next)
    if (flags[key] === undefined) flags[key] = value
    else if (Array.isArray(flags[key])) flags[key].push(value)
    else flags[key] = [flags[key], value]
  }
  return flags
}

const asList = (value) => (value === undefined ? undefined : Array.isArray(value) ? value : [value])
const asScalar = (value) => (Array.isArray(value) ? value[value.length - 1] : value)

function coerce(value) {
  if (typeof value !== 'string') return value
  if (value === 'true') return true
  if (value === 'false') return false
  if (/^-?\d+$/.test(value)) return Number(value)
  if (/^-?\d+\.\d+$/.test(value)) return Number(value)
  if ((value.startsWith('{') && value.endsWith('}')) || (value.startsWith('[') && value.endsWith(']'))) {
    try {
      return JSON.parse(value)
    } catch {
      return value
    }
  }
  return value
}

function buildArgs(toolName, flags, action) {
  const args = {}
  if (action !== undefined) args.action = action
  for (const key of DIRECT_FLAGS) {
    const raw = flags[key]
    if (raw === undefined) continue
    if (LIST_FLAGS.has(key)) args[key] = asList(raw)
    else args[key] = coerce(asScalar(raw))
  }
  // `--summary` means "one intent direction" for pt_intent and "the fact summary" elsewhere.
  if (toolName === 'pt_intent') args.summaries = asList(flags.summary ?? flags.summaries)
  else if (flags.summary !== undefined) args.summary = asScalar(flags.summary)
  if (toolName === 'pt_evidence_save' && flags.file !== undefined) {
    args.content = fs.readFileSync(String(flags.file), 'utf8')
    if (args.name === undefined) args.name = String(flags.file).split(/[\\/]/).pop()
  }
  return args
}

const format = (value) => (typeof value === 'string' ? value : JSON.stringify(value, null, 2))

async function run() {
  const argv = process.argv.slice(2)
  const flags = parseArgv(argv)
  const positional = flags._

  if (flags.help || positional.length === 0) {
    printHelp()
    return 0
  }

  const config = {}
  if (typeof flags.data === 'string') config.dataDir = flags.data
  else if (process.env.ARTEX_OPS_HOME) config.dataDir = process.env.ARTEX_OPS_HOME
  if (flags['oob-port'] !== undefined) config.oob = { port: Number(flags['oob-port']) }
  if (flags['oob-host'] !== undefined) config.oob = { ...(config.oob ?? {}), bindHost: String(flags['oob-host']) }

  const engine = createEngine(config)
  try {
    const head = positional[0]
    let toolName
    let args

    if (head === 'tools') {
      const catalog = engine.catalog().map((tool) => ({
        name: tool.name,
        description: tool.description.split('\n')[0],
        params: Object.keys(tool.inputSchema?.properties ?? {}),
      }))
      process.stdout.write(`${format(catalog)}\n`)
      return 0
    }
    if (head === 'report') {
      toolName = 'pt_mission'
      args = { action: 'report' }
    } else if (head === 'prove') {
      toolName = 'pt_mission'
      args = { action: 'prove', evidence: asScalar(flags.evidence), force: flags.force === true }
    } else if (head === 'oob') {
      const sub = positional[1]
      if (sub === 'poll') {
        toolName = 'pt_oob_poll'
        args = buildArgs(toolName, flags, undefined)
      } else if (sub === 'payload') {
        toolName = 'pt_oob_payload'
        args = buildArgs(toolName, flags, undefined)
      } else {
        toolName = 'pt_oob_new'
        args = buildArgs(toolName, flags, undefined)
      }
    } else if (head === 'call') {
      toolName = positional[1]
      if (!toolName) throw new Error('usage: artex-ops call <tool> <json-args>')
      args = positional[2] === undefined ? {} : JSON.parse(positional[2])
    } else if (TOOL_BY_COMMAND[head]) {
      toolName = TOOL_BY_COMMAND[head]
      const takesAction = ['pt_mission', 'pt_intent', 'pt_asset', 'pt_finding', 'pt_cred', 'pt_defense', 'pt_candidate', 'pt_trace', 'pt_worker', 'pt_hint', 'pt_goal', 'pt_graph', 'pt_coverage', 'pt_recon'].includes(toolName)
      args = buildArgs(toolName, flags, takesAction ? positional[1] : undefined)
    } else {
      throw new Error(`unknown command ${JSON.stringify(head)}; run artex-ops --help`)
    }

    const result = await engine.call(toolName, args)
    if (toolName === 'pt_mission' && args.action === 'report' && !flags.json) {
      process.stdout.write(`${result.markdown}\n`)
    } else {
      process.stdout.write(`${flags.json ? JSON.stringify(result) : format(result)}\n`)
    }
    return 0
  } catch (error) {
    process.stderr.write(`error: ${error?.message ?? error}\n`)
    return 1
  } finally {
    await engine.close()
  }
}

function printHelp() {
  process.stdout.write(`ARTEX ops — 对话式渗透的本地状态层（CLI）

用法: artex-ops <command> [sub-action] [flags]

快捷:
  state                     全局态势（链/意图/事实/回连/凭据/候选/漏洞）
  next                      本轮该干什么（decision + 具体动作）
  report                    生成 Markdown 报告
  prove --evidence "..."    标记目标达成
  tools                     列出全部工具

命令（子动作与工具 action 同名）:
  mission start|state|prove|report|stop   --goal --scope --constraints --evidence --force --replace
  intent  add|claim|done|list            --summary(可多次) --priority --id --state --output
  asset   add|list|mark                  --assets '<json>' --q --type --tested --id
  finding add|list|state                 --title --severity --evidence --assetId --id --state --note
  chain                                  --title --host --steps '<json>'
  chainadvance                           --chainId --ord --evidence --force
  fact                                   --label --summary --host --confidence --evidence
  facts                                  --q --host --limit
  oob new|poll|payload                   --note --id --wait --family --target
  cred    add|list|show                  --host --kind --username --secret --id
  defense note|list|matrix               --host --waf --family --base
  candidate add|list|verdict             --title --host --source --id --verdict --evidence --oobId
  evidence                               --name --content|--file --note
  call <tool> '<json>'

全局: --data <dir>  --json  --oob-port <n>  --help
数据目录: --data > $ARTEX_OPS_HOME > $DSH_HOME/artex-ops > ~/.dsh/artex-ops
`)
}

run().then((code) => process.exit(code))
