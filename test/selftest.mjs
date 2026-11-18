// secret-scan: allow-file —— 本文件里的 cookie/token 均为本地 fixture 合成值，非真实凭据
// Self-test: proves the plugin works without booting the desktop app.
//
//   1. mounts the plugin on a fake Cordis context that captures registrations
//   2. validates every output schema against the runtime's own enforced JSON
//      Schema subset (imported from the installed dsh-tools package)
//   3. drives the real tool bodies end to end: chain assertions, a genuine OAST
//      HTTP callback, credentials, candidates (including the "no evidence" guard),
//      defense profiles, bypass matrix and evidence hashing
//
// Run: node test/selftest.mjs
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import http from 'node:http'
import { spawn, spawnSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'

import { apply, name as pluginName, inject } from '../index.js'
import { Store } from '../lib/store.js'
import { createEngine } from '../lib/engine.js'

const RUNTIME_TOOLS = 'F:/AI agent/deepseek/resources/app/dsh/node_modules/@deepseek-ai/dsh-tools/lib/index.js'

const results = []
function ok(label, detail = '') {
  results.push({ label, detail })
  console.log(`  ok  ${label}${detail ? ` — ${detail}` : ''}`)
}

function makeDataDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'artex-ops-selftest-'))
}

function fakeContext() {
  const tools = new Map()
  const sections = []
  const effects = []
  return {
    __registry: tools,
    __sections: sections,
    __effects: effects,
    tools: {
      register(definition) {
        if (!definition?.name) throw new Error('tool without name')
        if (tools.has(definition.name)) throw new Error(`duplicate tool ${definition.name}`)
        tools.set(definition.name, definition)
        return () => tools.delete(definition.name)
      },
    },
    effect(factory) {
      const dispose = factory()
      effects.push(dispose)
      return dispose
    },
    inject(_deps, callback) {
      const sub = { systemPrompt: { section: (section) => sections.push(section) } }
      callback(sub)
    },
    get() {
      return undefined
    },
    logger: undefined,
  }
}

async function loadRuntimeValidator() {
  try {
    const mod = await import(pathToFileURL(RUNTIME_TOOLS).href)
    return typeof mod.assertSupportedJsonSchema === 'function' ? mod.assertSupportedJsonSchema : null
  } catch (error) {
    console.log(`  --  runtime schema validator unavailable (${error?.message ?? error}); subset check skipped`)
    return null
  }
}

function getTool(tools, toolName) {
  const tool = tools.get(toolName)
  if (!tool) throw new Error(`tool ${toolName} not registered`)
  return tool
}

async function call(tools, toolName, args, exec = { signal: undefined }) {
  const tool = getTool(tools, toolName)
  return tool.execute(args ?? {}, exec)
}

async function httpGet(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      res.resume()
      res.on('end', () => resolve(res.statusCode))
    })
    req.on('error', reject)
    req.setTimeout(4000, () => req.destroy(new Error('timeout')))
  })
}

async function main() {
  const dataDir = makeDataDir()
  const ctx = fakeContext()
  apply(ctx, { dataDir, oob: { port: 0 } })
  // 插件现在是「宿主外壳 + 实现子进程」，工具注册是异步 catalog 同步：等它就绪再断言。
  for (let i = 0; i < 150 && ctx.__registry.size < 24; i++) await new Promise((resolve) => setTimeout(resolve, 100))

  console.log(`\n[1] 挂载与工具面 (plugin=${pluginName}, inject=${inject.join(',')})`)
  const registry = collectRegistry(ctx)
  assert.equal(registry.size, 27, `expected 17 tools, got ${registry.size}: ${[...registry.keys()].join(',')}`)
  ok('注册 27 个工具', [...registry.keys()].join(', '))
  assert.equal(ctx.__sections.length, 1, 'one prompt section registered')
  assert.equal(ctx.__sections[0].name, 'tool:artex-ops')
  ok('注入系统提示段', ctx.__sections[0].name)

  for (const [toolName, tool] of registry) {
    assert.equal(typeof tool.description, 'string')
    assert.ok(tool.description.length > 20, `${toolName} description too short`)
    assert.equal(tool.parameters?.type, 'object', `${toolName} parameters must be an object schema`)
    assert.equal(typeof tool.output?.render, 'function', `${toolName} needs output.render`)
    assert.equal(typeof tool.execute, 'function', `${toolName} needs execute`)
  }
  ok('每个工具都有描述/对象参数/output.render/execute')

  const validate = await loadRuntimeValidator()
  if (validate) {
    for (const [toolName, tool] of registry) {
      validate(tool.output.schema)
    }
    ok('全部 output.schema 通过运行时 assertSupportedJsonSchema')
  }

  console.log('\n[2] 带外探测点 + 真实 HTTP 回连')
  const probe = await call(registry, 'pt_oob_new', { kind: 'http', note: 'selftest' })
  assert.match(probe.token, /^[a-f0-9]{24}$/)
  assert.ok(probe.url.includes(probe.token), 'url must carry the token')
  assert.equal(probe.listener.listening, true)
  ok('创建探测点', `${probe.id} → ${probe.url}`)

  const payloads = await call(registry, 'pt_oob_payload', { id: probe.id, family: 'ssrf' })
  assert.ok(payloads.payloads.length >= 4)
  assert.ok(payloads.payloads[0].payload.startsWith('http://'), 'first ssrf payload is the probe URL')
  ok('生成 ssrf 带外 payload', `${payloads.payloads.length} 条`)

  const pollEmpty = await call(registry, 'pt_oob_poll', { id: probe.id })
  assert.equal(pollEmpty.count, 0)
  const status = await httpGet(probe.url)
  assert.equal(status, 200)
  const pollHit = await call(registry, 'pt_oob_poll', { id: probe.id, waitMs: 200 })
  assert.equal(pollHit.count, 1, `expected 1 hit, got ${pollHit.count}`)
  assert.equal(pollHit.probe.hits, 1)
  assert.equal(pollHit.hits[0].proto, 'http')
  ok('回连被记录并归属到探测点', `path=${pollHit.hits[0].path}`)

  console.log('\n[3] 攻击链状态机（断言驱动）')
  const chain = await call(registry, 'pt_chain_plan', {
    title: 'selftest 上传→RCE→凭据',
    host: 'h1',
    steps: [
      { title: '确认上传点', post: ['fact:upload-endpoint'] },
      { title: '带外确认命令执行', pre: ['fact:upload-endpoint'], post: [`oob:${probe.id}`] },
      { title: '取凭据', pre: [`oob:${probe.id}`], post: ['cred:h1'] },
    ],
  })
  // 探测点已在第 2 步之前收到过回连，因此步骤 3 的 pre 一开始就成立 —— ready 由
  // 断言求值决定，不按顺序硬排（这是有意的：并行维度不该被序号卡住）。
  assert.equal(chain.nextReady.join(','), '1,3')
  const blocked = await call(registry, 'pt_chain_advance', { chainId: chain.id, ord: 1, evidence: 'curl /upload -> 200' })
  assert.equal(blocked.ok, false)
  assert.deepEqual(blocked.missing, ['fact:upload-endpoint'])
  assert.equal(blocked.status, 'running')
  ok('后置断言不成立时拒绝推进', `missing=${blocked.missing.join(',')}`)

  await call(registry, 'pt_fact_add', {
    label: 'upload-endpoint',
    summary: 'POST /upload 接受任意扩展名',
    host: 'h1',
    confidence: 'observed',
    evidence: 'curl -F file=@a.php /upload -> 200 ok',
  })
  const advanced = await call(registry, 'pt_chain_advance', { chainId: chain.id, ord: 1, evidence: 'upload 200' })
  assert.equal(advanced.ok, true)
  assert.equal(advanced.status, 'satisfied')
  assert.deepEqual(advanced.unlocked, [2, 3])
  ok('事实登记后步骤 1 推进，步骤 2/3 进入 ready')

  const step2Blocked = await call(registry, 'pt_chain_advance', { chainId: chain.id, ord: 2 })
  assert.equal(step2Blocked.ok, true, 'oob 已有回连，步骤 2 应直接通过')

  const step3Blocked = await call(registry, 'pt_chain_advance', { chainId: chain.id, ord: 3 })
  assert.equal(step3Blocked.ok, false)
  assert.deepEqual(step3Blocked.missing, ['cred:h1'])
  ok('缺凭据时步骤 3 不推进', `missing=${step3Blocked.missing.join(',')}`)

  console.log('\n[4] 凭据库 / 防护画像 / 绕过矩阵')
  const cred = await call(registry, 'pt_cred', {
    action: 'add',
    host: 'h1',
    kind: 'cookie',
    username: 'admin',
    secret: 'SESSION=0123456789abcdef',
    note: '登录后 Set-Cookie',
  })
  assert.match(cred.credential.masked, /^SES…/)
  const credList = await call(registry, 'pt_cred', { action: 'list', host: 'h1' })
  assert.equal(credList.credentials.length, 1)
  assert.equal(credList.credentials[0].secret, undefined, 'list must not leak plaintext')
  const shown = await call(registry, 'pt_cred', { action: 'show', id: cred.credential.id })
  assert.equal(shown.secret, 'SESSION=0123456789abcdef')
  ok('凭据落库 + 列表掩码 + show 取明文')

  const step3Ok = await call(registry, 'pt_chain_advance', { chainId: chain.id, ord: 3, evidence: 'Set-Cookie 已获取' })
  assert.equal(step3Ok.ok, true)
  ok('凭据落库后步骤 3 通过（断言 cred:h1）')

  await call(registry, 'pt_defense', {
    action: 'note',
    host: 'h1',
    waf: 'cloudflare',
    blockedSignature: '403 + cf-ray',
    blockedFamilies: ['sqli'],
  })
  const matrix = await call(registry, 'pt_defense', { action: 'matrix', family: 'sqli', base: "1' UNION SELECT 1--", host: 'h1' })
  assert.equal(matrix.waf, 'cloudflare')
  assert.equal(matrix.variants.length >= 5, true)
  assert.ok(matrix.variants[0].label === 'double-urlencode', `cloudflare should rank double-urlencode first, got ${matrix.variants[0].label}`)
  ok('防护画像 + WAF 排序的绕过矩阵', `${matrix.variants.length} 个变体，首位=${matrix.variants[0].label}`)

  console.log('\n[5] 候选漏洞队列（拒绝无证据确认）')
  const cand = await call(registry, 'pt_candidate', {
    action: 'add',
    host: 'h1',
    title: 'Apache 2.4.49 路径穿越 RCE',
    source: 'cve',
    cve: 'CVE-2021-41773',
  })
  assert.equal(cand.candidate.state, 'candidate')
  await assert.rejects(
    () => call(registry, 'pt_candidate', { action: 'verdict', id: cand.candidate.id, verdict: 'confirmed' }),
    /真实证据/,
  )
  ok('confirmed 无证据被拒')
  const confirmed = await call(registry, 'pt_candidate', {
    action: 'verdict',
    id: cand.candidate.id,
    verdict: 'confirmed',
    evidence: 'curl --path-as-is /cgi-bin/.%2e/.%2e/etc/passwd -> root:x:0:0',
    oobId: probe.id,
  })
  assert.equal(confirmed.candidate.state, 'confirmed')
  ok('有真实证据后 confirmed')

  console.log('\n[6] 证据固化 + 态势总览')
  const evidence = await call(registry, 'pt_evidence_save', {
    name: 'poc-upload-rce',
    content: 'POST /upload HTTP/1.1\nHost: h1\n\n<?php system($_GET[c]); ?>',
    note: 'selftest',
  })
  assert.equal(evidence.sha256.length, 64)
  assert.ok(fs.existsSync(evidence.path))
  ok('证据落盘 + sha256', `${path.basename(evidence.path)} ${evidence.sha256.slice(0, 12)}…`)

  const state = await call(registry, 'pt_state', {})
  assert.equal(state.counts.chains, 1)
  assert.equal(state.counts.creds, 1)
  assert.equal(state.counts.oobHits, 1)
  assert.equal(state.counts.candidates, 1)
  assert.equal(state.readySteps.length, 0, 'all steps satisfied, nothing ready')
  ok('pt_state 汇总一致', JSON.stringify(state.counts))

  console.log('\n[8] mission / intent / pt_next 闭环')
  const mission = await call(registry, 'pt_mission', {
    action: 'start',
    goal: '拿到 demo.test 管理员权限，或证明当前范围内不可得',
    scope: ['demo.test'],
    constraints: ['不碰删除接口'],
  })
  assert.equal(mission.mission.state, 'running')
  await call(registry, 'pt_asset', {
    action: 'add',
    assets: [
      { type: 'app', name: 'https://demo.test', host: 'demo.test', props: { title: 'demo' } },
      { type: 'endpoint', name: '/upload', host: 'demo.test' },
    ],
  })
  // 先验「未登记的回连」门槛：探测点已有回连但没登记事实 → decision 必须是 verify
  let digest = await call(registry, 'pt_next', {})
  assert.equal(digest.decision, 'verify')
  assert.ok(digest.reasons.some((reason) => reason.includes('回连')))
  await call(registry, 'pt_fact_add', {
    label: `oob-hit:${probe.id}`,
    summary: '探测点收到回连，确认目标侧可出网',
    confidence: 'observed',
    evidence: `curl ${probe.url} -> 200（见 oob/hits.ndjson）`,
  })
  ok('未登记回连时 pt_next 先要求 verify')

  digest = await call(registry, 'pt_next', {})
  assert.equal(digest.decision, 'plan')
  assert.ok(digest.gates.untestedAssets >= 2)
  ok('无意图时 pt_next 指向未测资产', `decision=${digest.decision} untested=${digest.gates.untestedAssets}`)

  const added = await call(registry, 'pt_intent', {
    action: 'add',
    summaries: ['测 /upload 的扩展名与 Content-Type 绕过', '测 /api/v1 的鉴权缺失'],
    priority: 1,
  })
  assert.equal(added.created.length, 2)
  const dup = await call(registry, 'pt_intent', { action: 'add', summaries: ['测 /api/v1 的鉴权缺失'] })
  assert.equal(dup.created.length, 0)
  assert.equal(dup.skipped.length, 1)
  ok('派意图 + 去重跳过')

  digest = await call(registry, 'pt_next', {})
  assert.equal(digest.decision, 'execute')
  assert.ok(digest.gates.openIntents === 2)
  ok('派意图后 pt_next 指向 claim', `decision=${digest.decision}`)

  const claimed = await call(registry, 'pt_intent', { action: 'claim' })
  assert.ok(claimed.intent.id)
  const again = await call(registry, 'pt_intent', { action: 'claim' })
  assert.equal(again.reused, true, 'one in-flight intent per claimer')
  const finished = await call(registry, 'pt_intent', {
    action: 'done',
    id: claimed.intent.id,
    state: 'done',
    output: '上传点可写',
  })
  assert.equal(finished.intent.state, 'done')
  assert.ok(finished.warning, '写回 0 应被点名')
  ok('一人一条意图 + 收口统计写回量（0 写回被点名）')

  console.log('\n[9] 漏洞 / prove / 报告')
  const assetsNow = await call(registry, 'pt_asset', { action: 'list' })
  const appAsset = assetsNow.assets.find((asset) => asset.type === 'app')
  await assert.rejects(
    () => call(registry, 'pt_finding', { action: 'add', title: 'x', severity: 'high', evidence: 'short' }),
    /真实证据/,
  )
  ok('finding 无证据被拒')
  const finding = await call(registry, 'pt_finding', {
    action: 'add',
    title: '上传点可写 + 解析执行',
    severity: 'high',
    evidence: 'POST /upload -> 200 /u/a.php；GET /u/a.php?c=id -> uid=33(www-data)',
    assetId: appAsset.id,
    chainId: chain.id,
  })
  assert.equal(finding.finding.state, 'confirmed')
  const found = await call(registry, 'pt_finding', { action: 'list' })
  assert.equal(found.findings.length, 1)
  ok('finding 落库并绑定资产/链')

  await assert.rejects(
    () => call(registry, 'pt_mission', { action: 'prove', evidence: '拿到管理员权限，证据见文件' }),
    /未收口/,
  )
  ok('有未收口意图时 prove 被拒')

  const claimed2 = await call(registry, 'pt_intent', { action: 'claim' })
  await call(registry, 'pt_fact_add', {
    label: 'api-auth-missing',
    summary: '/api/v1/users 无鉴权返回全量用户',
    host: 'demo.test',
    confidence: 'observed',
    evidence: 'curl -s https://demo.test/api/v1/users -> 200 [{...}]',
  })
  const finished2 = await call(registry, 'pt_intent', {
    action: 'done',
    id: claimed2.intent.id,
    state: 'done',
    output: '/api/v1 无鉴权',
  })
  assert.equal(finished2.intent.writes.facts, 1)
  assert.equal(finished2.warning, undefined)
  ok('写回 1 条事实时不再告警', JSON.stringify(finished2.intent.writes))

  // prove 现在还要过类型覆盖闸门：这个 fixture 只用于流程验证，逐类兜底为 na（带理由）。
  for (const asset of assetsNow.assets) {
    await call(registry, 'pt_coverage', {
      action: 'mark',
      assetId: asset.id,
      cat: 'all',
      state: 'na',
      note: 'selftest 专用 fixture：该类面在本环境不存在（仅验证工具链）',
      skipResolved: true,
    })
  }
  const covered = await call(registry, 'pt_coverage', { action: 'stats' })
  assert.equal(covered.untested, 0, `coverage should be complete before prove, got ${covered.untested} left`)
  ok('类型矩阵兜底后可 prove', `cells=${covered.cells} tested=${covered.tested} na=${covered.na}`)

  const proved = await call(registry, 'pt_mission', {
    action: 'prove',
    evidence: '拿到管理员权限：/api/v1/users 全量泄露 + 上传点可执行；证据见 evidence 索引 sha256',
  })
  assert.equal(proved.mission.state, 'done')
  const report = await call(registry, 'pt_mission', { action: 'report' })
  assert.match(report.markdown, /已确认漏洞/)
  assert.match(report.markdown, /上传点可写/)
  assert.match(report.markdown, /证据索引/)
  ok('prove 收口 + 生成报告', `${report.markdown.split('\n').length} 行 markdown`)

  console.log('\n[10] 持久化（新 Store 实例读回同一状态）')
  const reopened = new Store({ dataDir })
  reopened.load()
  assert.equal(reopened.chains().length, 1)
  assert.equal(reopened.listCreds().length, 1)
  assert.equal(reopened.listCandidates()[0].state, 'confirmed')
  assert.equal(reopened.missionView().state, 'done')
  assert.equal(reopened.listFindings().length, 1)
  assert.equal(reopened.listIntents({ limit: 10 }).length, 2)
  const chainReopened = reopened.chains()[0]
  assert.deepEqual(chainReopened.steps.map((s) => s.status), ['satisfied', 'satisfied', 'satisfied'])
  ok('重启后链路/意图/漏洞/凭据/候选全部读回')

  console.log('\n[11] 可移植性：CLI 与 MCP 入口')
  const cliDir = makeDataDir()
  const here = path.dirname(fileURLToPath(import.meta.url))
  const cli = path.join(here, '..', 'bin', 'artex-ops.mjs')
  const cliRun = spawnSync(process.execPath, [cli, 'state', '--data', cliDir, '--json'], { encoding: 'utf8' })
  assert.equal(cliRun.status, 0, `CLI failed: ${cliRun.stderr}`)
  const cliState = JSON.parse(cliRun.stdout)
  assert.equal(path.resolve(cliState.dataDir), path.resolve(cliDir))
  assert.ok(cliState.counts)
  ok('CLI 入口可执行并回 JSON', `dataDir=${cliState.dataDir}`)

  const cliTools = spawnSync(process.execPath, [cli, 'tools', '--data', cliDir], { encoding: 'utf8' })
  assert.equal(cliTools.status, 0)
  assert.equal(JSON.parse(cliTools.stdout).length, 27)
  ok('CLI tools 列出 27 个工具')

  const mcpDir = makeDataDir()
  const mcp = path.join(path.dirname(cli), 'artex-ops-mcp.mjs')
  const mcpResponses = await runMcp(mcp, mcpDir)
  assert.equal(mcpResponses.initialize.protocolVersion, '2025-06-18')
  assert.equal(mcpResponses.list.tools.length, 27)
  assert.ok(mcpResponses.call.content[0].text.includes('decision'))
  ok('MCP stdio 握手 + tools/list + tools/call', mcpResponses.call.content[0].text.split('\n')[0])

  for (const dir of [cliDir, mcpDir]) {
    try {
      fs.rmSync(dir, { recursive: true, force: true })
    } catch {}
  }

  console.log('\n[12] 多 worker：过程级信息交换（ARTEX activity 库）')
  const mwDir = makeDataDir()
  const mw = createEngine({ dataDir: mwDir, oob: { port: 0 } })
  try {
    await mw.call('pt_mission', { action: 'start', goal: '多 worker 协作验证过程交换', scope: ['demo.test'] })
    await mw.call('pt_intent', {
      action: 'add',
      summaries: ['w1: 测 /upload 的扩展名校验', 'w2: 测 /api 的鉴权缺失'],
      priority: 1,
    })
    const claimedA = await mw.call('pt_intent', { action: 'claim', worker: 'w1' })
    const claimedB = await mw.call('pt_intent', { action: 'claim', worker: 'w2' })
    assert.notEqual(claimedA.intent.id, claimedB.intent.id, 'two workers must hold different intents')
    assert.equal((await mw.call('pt_intent', { action: 'claim', worker: 'w1' })).reused, true)
    ok('两个 worker 各领一条，重复 claim 返回同一条', `${claimedA.intent.id} / ${claimedB.intent.id}`)

    // w1 写回事实 → 自动落一条过程 step（归属由其 running intent 推断）
    const wrote = await mw.call('pt_fact_add', {
      label: 'upload-php5-500',
      summary: 'POST /upload 带 .php5 后缀 → 500 mime 校验报错',
      worker: 'w1',
      confidence: 'observed',
      evidence: 'curl -F file=x.php5 -> 500; body: unsupported mime',
    })
    assert.ok(wrote.stepId, '写回应自动记一条 step')
    // 再记一条"过程而非结论"的原始痕迹：报错全文
    await mw.call('pt_trace', {
      action: 'add',
      worker: 'w1',
      kind: 'error',
      summary: 'mime 校验抛异常（finfo 返回 text/x-php）',
      detail: 'PHP Warning: finfo_file(): unsupported image type in /var/www/upload.php line 42',
    })
    ok('写回自动记 step + 手工记原始报错')

    // w2 在别人的过程里检索：命中项带 intentId，且不返回自己那条意图
    await mw.call('pt_trace', { action: 'add', worker: 'w2', kind: 'probe', summary: '我的 mime 试探（应被排除）' })
    const hits = await mw.call('pt_trace', { action: 'search', q: 'mime', excludeIntent: claimedB.intent.id })
    assert.equal(hits.hits.length, 2, `expected 2 hits from w1, got ${hits.hits.length}`)
    assert.ok(hits.hits.every((hit) => hit.intentId === claimedA.intent.id && hit.worker === 'w1'))
    ok('w2 检索到 w1 的过程且带 intentId', hits.hits.map((hit) => `${hit.stepId}:${hit.kind}`).join(', '))

    const selfOnly = await mw.call('pt_trace', { action: 'search', q: 'mime', excludeIntent: claimedB.intent.id })
    assert.equal(selfOnly.hits.filter((hit) => hit.worker === 'w2').length, 0)
    ok('excludeIntent 排除自己的过程（不重复劳动）')

    const full = await mw.call('pt_trace', { action: 'get', intentId: claimedA.intent.id })
    assert.ok(full.steps.length >= 3, `expected >=3 steps for w1, got ${full.steps.length}`)
    assert.ok(full.steps.some((step) => step.detail.includes('finfo_file')))
    ok('get 取某条意图的步骤全文（含 detail）', `${full.steps.length} 步`)

    const traces = await mw.call('pt_trace', { action: 'list' })
    assert.equal(traces.traces.length >= 2, true)
    ok('list 按意图汇总：谁跑过、多少步', traces.traces.map((t) => `${t.worker}→${t.intentId}(${t.steps})`).join(' '))

    // 收口：写回量按 intent 归属统计，不被另一个 worker 污染
    await mw.call('pt_fact_add', {
      label: 'api-no-auth',
      summary: '/api 未鉴权',
      worker: 'w2',
      confidence: 'observed',
      evidence: 'curl /api -> 200',
    })
    const doneA = await mw.call('pt_intent', { action: 'done', id: claimedA.intent.id, worker: 'w1', state: 'done', output: 'w1 done' })
    const doneB = await mw.call('pt_intent', { action: 'done', id: claimedB.intent.id, worker: 'w2', state: 'done', output: 'w2 done' })
    assert.equal(doneA.intent.writes.facts, 1)
    assert.equal(doneB.intent.writes.facts, 1)
    ok('两个 worker 的写回量各自独立（不串账）', `w1=${JSON.stringify(doneA.intent.writes)} w2=${JSON.stringify(doneB.intent.writes)}`)

    const mwState = await mw.call('pt_state', {})
    assert.equal(mwState.counts.workers, 2)
    assert.ok(mwState.counts.steps >= 6)
    ok('pt_state 汇总 worker 数与过程步数', `workers=${mwState.counts.workers} steps=${mwState.counts.steps}`)

    // 目标没达成就不能收敛：先 prove 目标，再看 decision
    const mwGoals = await mw.call('pt_goal', { action: 'list' })
    await mw.call('pt_goal', {
      action: 'prove',
      id: mwGoals.goals[0].id,
      evidence: '两个 worker 各写回 1 条 observed 事实，目标已达成',
    })
    const mwNext = await mw.call('pt_next', {})
    assert.equal(mwNext.decision, 'converge')
    ok('两条意图收口 + 目标达成后 pt_next 收敛')
  } finally {
    await mw.close()
    try {
      fs.rmSync(mwDir, { recursive: true, force: true })
    } catch {}
  }

  console.log('\n[13] 子 agent 当 worker：作业说明 + 跨进程并发写')
  const poolDir = makeDataDir()
  await runCli(['mission', 'start', '--goal', '子 agent worker 验证', '--scope', 'demo.test'], { dataDir: poolDir })
  const pool = createEngine({ dataDir: poolDir })
  try {
    const brief = await pool.call('pt_worker', { action: 'brief', worker: 'w9', note: '优先看 /upload' })
    assert.match(brief.brief, /claim worker=w9/)
    assert.match(brief.brief, /pt_trace action=search/)
    assert.match(brief.brief, /写进库才算数/)
    assert.equal(brief.mission.goal, '子 agent worker 验证')
    ok('brief 生成可直接投喂 subagent 的作业说明', `${brief.brief.split('\n').length} 行`)

    // 四个独立进程同时写同一份 state.json（模拟四个 subagent 并发写回）
    const labels = ['c1', 'c2', 'c3', 'c4']
    const results = await Promise.all(
      labels.map((label) =>
        runCli(
          ['fact', '--label', `concurrent-${label}`, '--summary', `并发写入 ${label}`, '--worker', 'w9', '--confidence', 'observed'],
          { dataDir: poolDir },
        ),
      ),
    )
    assert.ok(results.every((run) => run.code === 0), results.map((run) => run.err).join(' | '))
    const facts = await pool.call('pt_fact_list', { limit: 50 })
    const seenLabels = facts.facts.map((fact) => fact.label)
    assert.equal(
      labels.every((label) => seenLabels.includes(`concurrent-${label}`)),
      true,
      `lost update: ${seenLabels.join(',')}`,
    )
    assert.equal(facts.facts.length, 4)
    ok('四个进程并发写回全部保留（锁 + 重载）', seenLabels.join(', '))
    assert.equal(fs.existsSync(path.join(poolDir, 'state.json.lock')), false)
    ok('锁文件已释放')

    // 僵尸 worker：claim 后不 done → reap 把意图放回 frontier
    await runCli(['intent', 'add', '--summary', 'w9 的意图'], { dataDir: poolDir })
    const claimed = JSON.parse((await runCli(['intent', 'claim', '--worker', 'w9', '--json'], { dataDir: poolDir })).out)
    const status = await pool.call('pt_worker', { action: 'status', staleMs: -1 })
    assert.equal(status.workers.length, 1)
    assert.equal(status.workers[0].worker, 'w9')
    assert.equal(status.workers[0].stale, true)
    const reaped = await pool.call('pt_worker', { action: 'reap', staleMs: -1 })
    assert.equal(reaped.reaped.length, 1)
    assert.equal(reaped.reaped[0].intentId, claimed.intent.id)
    const openAfter = await pool.call('pt_intent', { action: 'list', state: 'open' })
    assert.equal(openAfter.intents.some((intent) => intent.id === claimed.intent.id), true)
    ok('僵尸 worker 被回收，意图回到 frontier', JSON.stringify(reaped.reaped[0]))
  } finally {
    await pool.close()
    try {
      fs.rmSync(poolDir, { recursive: true, force: true })
    } catch {}
  }

  console.log('\n[14] 双图：资产包含边 + 探索血缘 + 锚点 + 覆盖度')
  const gdir = makeDataDir()
  const g = createEngine({ dataDir: gdir })
  try {
    await g.call('pt_mission', { action: 'start', goal: '双图验证', scope: ['demo.test'] })
    const added = await g.call('pt_asset', {
      action: 'add',
      assets: [
        { type: 'root_domain', name: 'demo.test' },
        { type: 'subdomain', name: 'api.demo.test', host: 'api.demo.test' },
        { type: 'endpoint', name: '/api/v1/users', host: 'api.demo.test' },
      ],
    })
    const [root, sub, endpoint] = added.created
    assert.equal(sub.parentId, root.id, 'subdomain parent should be inferred as root_domain')
    assert.equal(endpoint.parentId, sub.id, 'endpoint parent should be the subdomain')
    ok('父子关系由程序推断（root_domain → subdomain → endpoint）', `${root.id} → ${sub.id} → ${endpoint.id}`)

    await g.call('pt_intent', { action: 'add', summaries: ['测 /api/v1/users 鉴权'], priority: 1 })
    const claimedG = await g.call('pt_intent', { action: 'claim', worker: 'w1' })
    const gfact = await g.call('pt_fact_add', {
      label: 'graph-users-no-auth',
      summary: '匿名可读用户列表',
      host: 'api.demo.test',
      worker: 'w1',
      confidence: 'observed',
      evidence: 'curl http://api.demo.test/api/v1/users -> 200',
    })
    const factGraph = await g.call('pt_graph', { action: 'around', node: `fact:${gfact.id}` })
    assert.ok(
      factGraph.around.in.some((edge) => edge.rel === 'yields' && edge.from === `intent:${claimedG.intent.id}`),
      'fact should be yielded by the intent',
    )
    assert.ok(
      factGraph.around.anchors.some((anchor) => anchor.assetId === sub.id),
      `fact should anchor to the most specific asset (${sub.id}), got ${JSON.stringify(factGraph.around.anchors)}`,
    )
    ok('事实：intent —yields→ fact，并锚定到最具体资产', factGraph.around.anchors.map((a) => a.assetId).join(','))

    const gfinding = await g.call('pt_finding', {
      action: 'add',
      title: '用户列表未鉴权',
      severity: 'high',
      evidence: '匿名 GET /api/v1/users -> 200 全量用户',
      assetId: endpoint.id,
      worker: 'w1',
    })
    const assetGraph = await g.call('pt_graph', { action: 'around', assetId: endpoint.id })
    assert.equal(assetGraph.asset.parent, `asset:${sub.id}`)
    assert.ok(assetGraph.asset.anchoredNodes.some((row) => row.node === `finding:${gfinding.finding.id}` && row.rel === 'proves'))
    ok('漏洞锚定到端点资产，且能从资产反查', `parent=${assetGraph.asset.parent}`)

    const nodes = await g.call('pt_graph', { action: 'nodes' })
    assert.equal(nodes.nodes.asset, 3)
    assert.equal(nodes.nodes.fact, 1)
    assert.equal(nodes.nodes.finding, 1)
    assert.ok(nodes.edges >= 4, `expected >=4 edges, got ${nodes.edges}`)
    ok('图规模统计（节点/边/锚点）', JSON.stringify(nodes.nodes))

    const gcov = await g.call('pt_graph', { action: 'coverage' })
    assert.equal(gcov.inScope, 3)
    assert.equal(gcov.tested >= 2, true, `expected >=2 tested, got ${gcov.tested}`)
    assert.ok(gcov.pct > 0 && gcov.pct <= 100)
    ok('覆盖度以授权范围为分母，锚定过的资产算已测', `${gcov.tested}/${gcov.inScope} = ${gcov.pct}%`)

    const provesEdge = await g.call('pt_graph', { action: 'around', node: `finding:${gfinding.finding.id}` })
    assert.ok(provesEdge.around.in.some((edge) => edge.rel === 'proves'))
    ok('漏洞反查：哪条意图证出了它')
  } finally {
    await g.close()
    try {
      fs.rmSync(gdir, { recursive: true, force: true })
    } catch {}
  }

  console.log('\n[15] hint 节点（人的原话）+ 多目标逐个 prove')
  const hdir = makeDataDir()
  const h = createEngine({ dataDir: hdir })
  try {
    await h.call('pt_mission', {
      action: 'start',
      goal: '拿到 demo.test 管理员权限或证明不可得',
      scope: ['demo.test'],
      goals: ['确认 /api/v1/users 的鉴权状态', '拿到一个可用的管理员会话'],
    })
    const goals0 = await h.call('pt_goal', { action: 'list' })
    assert.equal(goals0.goals.length, 2)
    assert.equal(goals0.summary.open, 2)
    ok('mission 起步即可拆成多个子目标', goals0.goals.map((goal) => goal.id).join(','))

    let digest = await h.call('pt_next', {})
    assert.equal(digest.decision, 'plan', 'unmet goals must block converge')
    assert.equal(digest.gates.goalsOpen, 2)
    ok('目标未达成时 pt_next 不允许收敛', `decision=${digest.decision} goalsOpen=${digest.gates.goalsOpen}`)

    await assert.rejects(() => h.call('pt_goal', { action: 'prove', id: goals0.goals[0].id }), /真实证据/)
    ok('目标 prove 无证据被拒')
    await h.call('pt_goal', { action: 'prove', id: goals0.goals[0].id, evidence: '匿名 GET /api/v1/users -> 200 全量用户' })
    await assert.rejects(
      () => h.call('pt_mission', { action: 'prove', evidence: '已拿到管理员会话，证据见文件' }),
      /目标未达成/,
    )
    ok('还有未达成目标时 pt_mission prove 被拒')

    // hint = 用户原话，不占 frontier，但 pt_next 必须指着它
    const hint = await h.call('pt_hint', { action: 'add', text: '优先看 /admin 的 cookie 鉴权，别在 /upload 上耗' })
    assert.equal(hint.hint.state, 'open')
    digest = await h.call('pt_next', {})
    assert.equal(digest.gates.openHints, 1)
    assert.ok(digest.reasons.some((reason) => reason.includes('/admin')), 'hint 原文应出现在 reasons 里')
    const hintAction = digest.actions.find((action) => JSON.stringify(action.args).includes(hint.hint.id))
    assert.ok(hintAction, 'pt_next 应给出把 hint 转成意图的动作')
    ok('hint 进入 pt_next：原话 + 接手动作', hintAction.args.action)

    const intents = await h.call('pt_intent', {
      action: 'add',
      summaries: ['按提示测 /admin：伪造 role=admin cookie 是否越权'],
      hintIds: [hint.hint.id],
    })
    const hintAfter = await h.call('pt_hint', { action: 'list', state: 'addressed' })
    assert.equal(hintAfter.hints.length, 1)
    assert.equal(hintAfter.hints[0].intentIds.includes(intents.created[0].id), true)
    digest = await h.call('pt_next', {})
    assert.equal(digest.gates.openHints, 0)
    ok('派意图带 hintIds → hint 变 addressed 且可反查', `${hint.hint.id} → ${intents.created[0].id}`)

    const hintGraph = await h.call('pt_graph', { action: 'around', node: `hint:${hint.hint.id}` })
    assert.ok(hintGraph.around.out.some((edge) => edge.rel === 'spawns'), 'hint 应连出 spawns 边')
    ok('hint —spawns→ intent 边已建')

    const claimed = await h.call('pt_intent', { action: 'claim', worker: 'chat' })
    await h.call('pt_intent', { action: 'done', id: claimed.intent.id, state: 'done', output: '确认 cookie 越权' })
    await h.call('pt_goal', { action: 'prove', id: goals0.goals[1].id, evidence: '伪造 Cookie role=admin 访问 /admin -> 200' })
    digest = await h.call('pt_next', {})
    assert.equal(digest.decision, 'converge')
    assert.equal(digest.gates.goalsOpen, 0)
    ok('全部目标达成 + hint 已接手 → 收敛')

    const proved = await h.call('pt_mission', { action: 'prove', evidence: '两个子目标均有实测依据；证据见 pt_evidence_save' })
    assert.equal(proved.mission.state, 'done')
    const report = await h.call('pt_mission', { action: 'report' })
    assert.match(report.markdown, /## 目标/)
    assert.match(report.markdown, /\[x\]/)
    assert.match(report.markdown, /## 人给的提示/)
    ok('报告含目标勾选与 hint 段', `${report.markdown.split('\n').length} 行`)
  } finally {
    await h.close()
    try {
      fs.rmSync(hdir, { recursive: true, force: true })
    } catch {}
  }

  console.log('\n[16] 漏洞类型覆盖矩阵：不许只打一类就收工')
  const cdir = makeDataDir()
  const c = createEngine({ dataDir: cdir })
  try {
    await c.call('pt_mission', { action: 'start', goal: '类型覆盖验证', scope: ['demo.test'] })
    // 覆盖闸门属于 sweep 阶段：recon 阶段只推 recon 类目，先把阶段切到 sweep。
    await c.call('pt_phase', { action: 'set', phase: 'sweep' })
    const addedA = await c.call('pt_asset', {
      action: 'add',
      assets: [
        { type: 'app', name: 'https://demo.test', host: 'demo.test' },
        { type: 'service', name: 'redis:6379', host: 'demo.test', port: 6379 },
      ],
    })
    const app = addedA.created[0]
    const svc = addedA.created[1]

    const tax = await c.call('pt_coverage', { action: 'taxonomy' })
    const cats = Object.keys(tax.categories)
    assert.ok(cats.length >= 9, `expected >=9 categories, got ${cats.length}`)
    const totalClasses = Object.values(tax.categories).reduce((sum, cat) => sum + cat.classes.length, 0)
    assert.ok(totalClasses >= 55, `expected >=55 classes, got ${totalClasses}`)
    ok('类型目录：类目 + 类型 + 打法提示', `${cats.length} 类目 / ${totalClasses} 个类型`)

    const stats0 = await c.call('pt_coverage', { action: 'stats' })
    assert.equal(stats0.pct, 0)
    assert.ok(stats0.cells > 80, `expected >80 cells for app+service, got ${stats0.cells}`)
    ok('初始矩阵全未测', `cells=${stats0.cells} pct=${stats0.pct}%`)

    // 未覆盖格子要按类目优先级排序，且能落到具体资产
    const nx = await c.call('pt_coverage', { action: 'next', limit: 5 })
    assert.equal(nx.cells.length, 5)
    assert.equal(nx.cells[0].cat, 'recon')
    assert.ok(nx.cells.every((cell) => cell.assetId && cell.classId))
    ok('next 给出下一批格子（recon 优先）', nx.cells.map((cell) => `${cell.classId}@${cell.assetId}`).join(', '))

    // na 必须写理由
    await assert.rejects(
      () => c.call('pt_coverage', { action: 'mark', assetId: app.id, classId: 'upload-bypass', state: 'na' }),
      /必须写 note/,
    )
    ok('标 na 不写理由被拒')

    // 不适用的类型要拦（service 上没有 apk 类）
    await assert.rejects(
      () => c.call('pt_coverage', { action: 'mark', assetId: svc.id, classId: 'apk-exported', state: 'tested' }),
      /不适用/,
    )
    ok('不适用的类型被拒（service × apk）')

    // 单格标记 + 整类标记
    await c.call('pt_coverage', { action: 'mark', assetId: app.id, classId: 'sqli', state: 'tested', note: "' and 1=2 无差异" })
    const reconCount = (tax.categories.recon.classes.filter((cls) => cls.appliesTo.includes('app')) ?? []).length
    await c.call('pt_coverage', { action: 'mark', assetId: app.id, cat: 'recon', state: 'na', note: '该站点为纯静态页面，无对应面' })
    const stats1 = await c.call('pt_coverage', { action: 'stats' })
    assert.equal(stats1.tested, 1)
    assert.equal(stats1.na, reconCount)
    ok('单格 tested + 整类 na 均生效', `tested=${stats1.tested} na=${stats1.na}`)

    // 还有未测格子时不许收敛
    let digestC = await c.call('pt_next', {})
    assert.equal(digestC.decision, 'plan')
    assert.equal(digestC.classCoverage.untested > 0, true)
    assert.ok(digestC.reasons.some((reason) => reason.includes('漏洞类型覆盖')))
    ok('未覆盖格子在时 pt_next 不许收敛', `pct=${digestC.classCoverage.pct}% untested=${digestC.classCoverage.untested}`)

    // 补齐：把剩余格子全部标 tested（模拟扫过但没发现）
    const remaining = await c.call('pt_coverage', { action: 'matrix', limit: 2000 })
    for (const cell of remaining.cells.filter((row) => row.state === 'untested' || row.state === 'testing')) {
      await c.call('pt_coverage', { action: 'mark', assetId: cell.assetId, classId: cell.classId, state: 'tested', note: 'selftest 补齐' })
    }
    const stats2 = await c.call('pt_coverage', { action: 'stats' })
    assert.equal(stats2.untested, 0)
    assert.equal(stats2.pct, 100)
    ok('全部格子标记后覆盖率 100%', `cells=${stats2.cells} na=${stats2.na}`)

    const goalsC = await c.call('pt_goal', { action: 'list' })
    await c.call('pt_goal', { action: 'prove', id: goalsC.goals[0].id, evidence: '类型矩阵已 100% 覆盖（含 na 理由）' })
    digestC = await c.call('pt_next', {})
    assert.equal(digestC.decision, 'converge')
    ok('类型覆盖补齐且目标达成后收敛')
  } finally {
    await c.close()
    try {
      fs.rmSync(cdir, { recursive: true, force: true })
    } catch {}
  }

  console.log('\n[17] 隐藏接口发现：SPA 的 JS bundle → 接口/参数/功能点')
  const port = 18131
  const spa = spawn(process.execPath, [path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixture-spa.mjs'), String(port)], {
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const waitSpa = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('spa fixture did not start')), 8000)
    spa.stdout.setEncoding('utf8')
    spa.stdout.on('data', (chunk) => {
      if (chunk.includes('spa fixture on')) {
        clearTimeout(timer)
        resolve()
      }
    })
    spa.on('error', reject)
  })
  try {
    await waitSpa
    const rdir = makeDataDir()
    const rc = createEngine({ dataDir: rdir })
    try {
      await rc.call('pt_mission', { action: 'start', goal: 'recon 验证', scope: [`127.0.0.1:${port}`] })
      const scan = await rc.call('pt_recon', { action: 'scan', url: `http://127.0.0.1:${port}/` })
      const paths = scan.endpoints.map((endpoint) => endpoint.path)
      assert.ok(paths.includes('/api/v2/admin/users'), `expected /api/v2/admin/users in ${paths.join(',')}`)
      assert.ok(paths.includes('/api/v2/files/upload'))
      assert.ok(paths.includes('/api/v2/internal/debug'), 'path literal with query should be normalized')
      assert.ok(paths.includes('/graphql'))
      assert.ok(paths.every((value) => !value.includes('?')), 'asset paths must be query-free')
      const login = scan.endpoints.find((endpoint) => endpoint.path === '/api/v2/login')
      assert.ok(login.methods.includes('POST'), 'form action should carry POST')
      ok('从 HTML+JS 挖出隐藏接口', `${scan.endpoints.length} 个接口，含 admin/upload/internal`)

      const names = scan.params.map((param) => param.name)
      for (const expected of ['page', 'size', 'q', 'verbose']) {
        assert.ok(names.includes(expected), `expected param ${expected} in ${names.join(',')}`)
      }
      ok('提取查询参数', names.join(', '))

      assert.ok(scan.features.some((feature) => feature.kind === 'link'))
      assert.ok(scan.features.some((feature) => feature.kind === 'form'))
      ok('提取功能点（链接/表单/按钮/前端路由）', scan.features.slice(0, 5).map((feature) => feature.kind).join(','))

      assert.ok(scan.hints.some((hint) => hint.includes('access_token')), 'token storage hint')
      assert.ok(scan.hints.some((hint) => hint.includes('internal.corp.example')), 'external host hint')
      ok('线索：token 存储 + 外域地址 + sourcemap', `${scan.hints.length} 条`)

      const saved = await rc.call('pt_recon', { action: 'save', url: `http://127.0.0.1:${port}/` })
      assert.ok(saved.saved.endpoints >= 10, `expected >=10 endpoint assets, got ${saved.saved.endpoints}`)
      const assets = await rc.call('pt_asset', { action: 'list', limit: 100 })
      assert.ok(assets.assets.some((asset) => asset.type === 'app'))
      assert.ok(assets.assets.some((asset) => asset.name === '/api/v2/admin/users'))
      ok('落进资产图（app + endpoint）', `${assets.assets.length} 个资产`)

      const cov = await rc.call('pt_coverage', { action: 'stats' })
      assert.ok(cov.tested >= 8, `recon cells should be auto-tested, got ${cov.tested}`)
      ok('recon 类目自动置为 tested', `tested=${cov.tested} pct=${cov.pct}%`)

      const again = await rc.call('pt_recon', { action: 'save', url: `http://127.0.0.1:${port}/` })
      assert.equal(again.saved.endpoints, 0, 'second run should merge, not duplicate')
      assert.ok(again.saved.endpointsMerged >= 10)
      ok('重复采集幂等（合并而非重复登记）', `merged=${again.saved.endpointsMerged}`)
    } finally {
      await rc.close()
      try {
        fs.rmSync(rdir, { recursive: true, force: true })
      } catch {}
    }
  } finally {
    spa.kill()
  }

  console.log('\n[18] 阶段状态机 + 分阶段 worker 合同')
  const pdir = makeDataDir()
  const ph = createEngine({ dataDir: pdir })
  try {
    await ph.call('pt_mission', { action: 'start', goal: '阶段验证', scope: ['demo.test'] })
    const status = await ph.call('pt_phase', { action: 'status' })
    assert.equal(status.phase, 'recon')
    assert.deepEqual(status.allowedNext, ['sweep', 'deepdive'])
    ok('mission 起步在 recon，且不允许直接跳 report', status.allowedNext.join(','))

    await assert.rejects(() => ph.call('pt_phase', { action: 'set', phase: 'report' }), /不是允许的迁移/)
    await ph.call('pt_phase', { action: 'set', phase: 'sweep', note: 'recon 完成' })
    const afterSweep = await ph.call('pt_phase', { action: 'status' })
    assert.equal(afterSweep.phase, 'sweep')
    assert.ok(afterSweep.allowedNext.includes('deepdive'))
    ok('recon → sweep 迁移生效', `next: ${afterSweep.allowedNext.join(',')}`)

    const added = await ph.call('pt_asset', {
      action: 'add',
      assets: [
        { type: 'app', name: 'https://demo.test', host: 'demo.test' },
        { type: 'endpoint', name: '/api/orders', host: 'demo.test' },
      ],
    })
    assert.equal(added.created.length, 2)

    const nextSweep = await ph.call('pt_next', {})
    assert.equal(nextSweep.phase, 'sweep')
    const sweepCell = (nextSweep.actions.find((action) => action.tool === 'pt_coverage' && action.args.classId) ?? {}).args
    assert.ok(sweepCell?.classId, 'sweep 阶段应给出具体格子')
    assert.notEqual(sweepCell.classId, 'vcs-exposure', 'sweep 阶段不应再推 recon 类目')
    ok('sweep 阶段只推非 recon 类目', `首个格子 ${sweepCell.classId}`)

    await ph.call('pt_phase', { action: 'set', phase: 'recon' })
    const nextRecon = await ph.call('pt_next', {})
    const reconCell = (nextRecon.actions.find((action) => action.tool === 'pt_coverage' && action.args.classId) ?? {}).args
    assert.equal(reconCell?.classId, 'vcs-exposure')
    ok('recon 阶段只推 recon 类目', `首个格子 ${reconCell.classId}`)

    const briefRecon = await ph.call('pt_worker', { action: 'brief', worker: 'w1', phase: 'recon' })
    assert.match(briefRecon.brief, /pt_recon action=save/)
    assert.match(briefRecon.brief, /不要判漏洞、不要试 payload/)
    ok('brief/recon：合同指向抓面且禁止判洞')

    const briefSweep = await ph.call('pt_worker', { action: 'brief', worker: 'w2', phase: 'sweep', cat: 'injection' })
    assert.match(briefSweep.brief, /sweep \/ injection/)
    assert.match(briefSweep.brief, /pt_coverage action=next cat=injection/)
    assert.match(briefSweep.brief, /na 必须写/)
    ok('brief/sweep：合同给出类目格子与 na 理由要求')

    const briefDeep = await ph.call('pt_worker', { action: 'brief', worker: 'w3', phase: 'deepdive' })
    assert.match(briefDeep.brief, /pt_chain_plan/)
    assert.match(briefDeep.brief, /pt_oob_new/)
    ok('brief/deepdive：合同要求链式推进 + 带外')

    const briefVerify = await ph.call('pt_worker', { action: 'brief', worker: 'w4', phase: 'verify' })
    assert.match(briefVerify.brief, /verdict=confirmed\|refuted/)
    ok('brief/verify：合同要求独立复验后定论')
  } finally {
    await ph.close()
    try {
      fs.rmSync(pdir, { recursive: true, force: true })
    } catch {}
  }

  console.log('\n[19] 每次 mission 一个独立工作目录')
  const wdir = makeDataDir()
  const ws = createEngine({ dataDir: wdir })
  try {
    const started = await ws.call('pt_mission', { action: 'start', goal: '工作目录验证', scope: ['x.test'] })
    const workspace = started.mission.workspace
    assert.ok(workspace?.root?.startsWith(path.resolve(wdir)), `workspace root should live under dataDir, got ${workspace?.root}`)
    assert.equal(fs.existsSync(workspace.work), true, 'work/ should be created')
    assert.equal(fs.existsSync(workspace.evidence), true, 'evidence/ should be created')
    ok('mission 起步即创建 work/ 与 evidence/', path.basename(workspace.root))

    const second = await ws.call('pt_mission', { action: 'start', goal: '第二个任务', scope: ['y.test'], replace: true })
    assert.notEqual(second.mission.workspace.root, workspace.root, 'each mission gets its own directory')
    assert.equal(fs.existsSync(workspace.root), true, 'previous mission directory is kept')
    ok('换 mission 不覆盖旧目录', `新旧：${path.basename(workspace.root)} / ${path.basename(second.mission.workspace.root)}`)

    const saved = await ws.call('pt_evidence_save', { name: 'ws-probe', content: 'GET /health -> 200', note: 'workspace 验证' })
    assert.ok(saved.path.startsWith(second.mission.workspace.root), `evidence should land in the mission dir, got ${saved.path}`)
    ok('证据落进本次 mission 的 evidence/', path.basename(saved.path))

    const listing = await ws.call('pt_mission', { action: 'workspace' })
    assert.equal(listing.workspace.evidenceFiles.length, 1)
    assert.equal(listing.workspace.evidenceFiles[0].name, path.basename(saved.path))
    ok('action=workspace 能列出产物', `evidence ${listing.workspace.evidenceFiles.length} 个`)

    const report = await ws.call('pt_mission', { action: 'report' })
    assert.ok(report.artifacts?.report?.startsWith(second.mission.workspace.root))
    assert.equal(fs.existsSync(report.artifacts.report), true)
    assert.equal(fs.existsSync(report.artifacts.manifest), true)
    const manifest = JSON.parse(fs.readFileSync(report.artifacts.manifest, 'utf8'))
    assert.equal(manifest.mission.id, second.mission.id)
    assert.ok(Array.isArray(manifest.findings))
    ok('report 落盘 report.md + manifest.json', path.basename(report.artifacts.report))

    const goal = (await ws.call('pt_goal', { action: 'list' })).goals[0]
    await ws.call('pt_goal', { action: 'prove', id: goal.id, evidence: '工作目录与产物验证通过（见 report.md）' })
    const proved = await ws.call('pt_mission', { action: 'prove', evidence: 'mission 工作区验证完成，产物已落盘' })
    assert.ok(proved.mission.artifacts?.root?.startsWith(second.mission.workspace.root))
    ok('prove 时再次写盘并回传路径', path.basename(proved.mission.artifacts.root))
  } finally {
    await ws.close()
    try {
      fs.rmSync(wdir, { recursive: true, force: true })
    } catch {}
  }

  console.log('\n[20] nuclei 结果 → 类型矩阵（映射/落库/去重）')
  const ndir = makeDataDir()
  const nu = createEngine({ dataDir: ndir })
  try {
    await nu.call('pt_mission', { action: 'start', goal: 'nuclei 映射验证', scope: ['127.0.0.1:18200'] })
    await nu.call('pt_asset', { action: 'add', assets: [{ type: 'app', name: 'http://127.0.0.1:18200', host: '127.0.0.1:18200' }] })
    const jsonl = [
      JSON.stringify({ 'template-id': 'CVE-2021-41773', info: { name: 'Apache 2.4.49 Path Traversal', severity: 'critical', tags: ['cve', 'apache'] }, host: 'http://127.0.0.1:18200', 'matched-at': 'http://127.0.0.1:18200/cgi-bin/.%2e/etc/passwd' }),
      JSON.stringify({ 'template-id': 'sqli-error-based', info: { name: 'Error Based SQL Injection', severity: 'high', tags: ['sqli', 'injection'] }, host: 'http://127.0.0.1:18200', 'matched-at': 'http://127.0.0.1:18200/api/v2/search?q=1' }),
      JSON.stringify({ 'template-id': 'http-missing-security-headers', info: { name: 'Missing Security Headers', severity: 'info', tags: ['misconfig'] }, host: 'http://127.0.0.1:18200' }),
    ].join('\n')

    const first = await nu.call('pt_nuclei', { action: 'ingest', json: jsonl })
    assert.equal(first.total, 3)
    assert.equal(first.markedCells, 2, `expected 2 cells marked, got ${first.markedCells}`)
    assert.equal(first.candidates, 3)
    assert.equal(first.unmapped, 1, 'CVE template has no stable class')
    ok('nuclei 命中 → 格子 tested + candidate', `marked=${first.markedCells} candidates=${first.candidates} unmapped=${first.unmapped}`)

    const mappedIds = first.mapped.map((row) => row.classId).sort()
    assert.deepEqual(mappedIds, ['security-headers', 'sqli'])
    ok('模板 → 类目映射正确', mappedIds.join(', '))

    const second = await nu.call('pt_nuclei', { action: 'ingest', json: jsonl })
    assert.equal(second.markedCells, 0, 'already-marked cells must not be counted again')
    assert.equal(second.candidates, 0, 'duplicate candidates must be skipped')
    assert.equal(second.duplicates, 3)
    ok('重复灌入幂等（0 新格子 / 0 新候选 / 3 去重）')

    const preview = await nu.call('pt_nuclei', { action: 'map', json: jsonl })
    assert.equal(preview.total, 3)
    assert.equal(preview.mapped.filter((row) => row.classId === '').length, 1)
    ok('action=map 可先看映射再落库')

    const cov = await nu.call('pt_coverage', { action: 'matrix', state: 'tested', limit: 10 })
    assert.ok(cov.cells.some((cell) => cell.classId === 'sqli' && cell.note.startsWith('nuclei')))
    ok('格子备注里带模板 id 与命中地址', 'sqli @ nuclei')
  } finally {
    await nu.close()
    try {
      fs.rmSync(ndir, { recursive: true, force: true })
    } catch {}
  }

  console.log('\n[21] 候选聚合 + 工作目录清理')
  const adir = makeDataDir()
  const ag = createEngine({ dataDir: adir })
  try {
    await ag.call('pt_mission', { action: 'start', goal: '聚合与清理', scope: ['127.0.0.1:18200'] })
    await ag.call('pt_asset', { action: 'add', assets: [{ type: 'app', name: 'http://127.0.0.1:18200', host: '127.0.0.1:18200' }] })

    // 同一个 CVE 在 3 个路径上各报一次 + 另一个模板在另一台主机上
    const rows = [
      ['CVE-2021-41773', 'critical', ['cve', 'apache'], 'http://127.0.0.1:18200/a', 'Apache Path Traversal'],
      ['CVE-2021-41773', 'critical', ['cve', 'apache'], 'http://127.0.0.1:18200/b', 'Apache Path Traversal'],
      ['CVE-2021-41773', 'critical', ['cve', 'apache'], 'http://127.0.0.1:18200/c', 'Apache Path Traversal'],
      ['sqli-error-based', 'high', ['sqli'], 'http://127.0.0.1:18201/api?q=1', 'Error Based SQL Injection'],
    ].map(([id, severity, tags, url, name]) =>
      JSON.stringify({ 'template-id': id, info: { name, severity, tags, classification: id.startsWith('CVE') ? { 'cve-id': [id] } : {} }, host: new URL(url).host, 'matched-at': url }),
    )
    const ingest = await ag.call('pt_nuclei', { action: 'ingest', json: rows.join('\n') })
    assert.equal(ingest.total, 4)
    assert.equal(ingest.aggregatedGroups, 2, `expected 2 groups, got ${ingest.aggregatedGroups}`)
    assert.equal(ingest.candidates, 2, 'aggregated candidates, not one per path')
    ok('同一 CVE 多路径聚合为 1 条候选', `4 条命中 → ${ingest.aggregatedGroups} 组 / ${ingest.candidates} 候选`)

    const list = await ag.call('pt_candidate', { action: 'list', limit: 10 })
    const cve = list.candidates.find((row) => row.ref === 'CVE-2021-41773')
    assert.ok(cve, 'candidate should be keyed by CVE')
    assert.match(cve.title, /\+2 处/, `title should mention extra matches, got ${cve.title}`)
    ok('候选标题带命中处数', cve.title)

    // 工作目录清理：默认只清 work/，evidence 保留；显式指定才清 evidence/artifacts
    const ws = (await ag.call('pt_mission', { action: 'workspace' })).workspace
    fs.writeFileSync(path.join(ws.work, 'scratch.txt'), 'mid artifact')
    await ag.call('pt_evidence_save', { name: 'keep-me', content: 'GET / -> 200' })
    const cleaned = await ag.call('pt_mission', { action: 'clean' })
    assert.equal(cleaned.removed.work, 1)
    assert.equal(cleaned.removed.evidence, 0)
    assert.equal(cleaned.removed.artifacts, 0)
    assert.equal(cleaned.remaining.evidenceFiles.length, 1, 'evidence must survive a default clean')
    ok('clean 默认只清 work/，证据保留', `removed work=${cleaned.removed.work}`)

    const before = (await ag.call('pt_state', {})).counts.evidence
    const deep = await ag.call('pt_mission', { action: 'clean', includeEvidence: true, includeArtifacts: true })
    assert.equal(deep.remaining.evidenceFiles.length, 0)
    const after = (await ag.call('pt_state', {})).counts.evidence
    assert.equal(after, before - deep.removed.evidence, 'state index must drop deleted evidence rows')
    ok('includeEvidence 会清证据并同步索引', `${before} → ${after}`)
  } finally {
    await ag.close()
    try {
      fs.rmSync(adir, { recursive: true, force: true })
    } catch {}
  }

  console.log('\n[22] 业务逻辑层：不变量清单 + 变异器')
  const bdir = makeDataDir()
  const biz = createEngine({ dataDir: bdir })
  try {
    await biz.call('pt_mission', { action: 'start', goal: '业务逻辑验证', scope: ['127.0.0.1:18200'] })
    const app = await biz.call('pt_asset', { action: 'add', assets: [{ type: 'app', name: 'http://127.0.0.1:18200', host: '127.0.0.1:18200' }] })

    const domains = await biz.call('pt_biz', { action: 'playbook' })
    assert.equal(domains.domains.length, 4)
    const playbook = await biz.call('pt_biz', { action: 'playbook', domain: 'ecommerce' })
    assert.equal(playbook.invariants.length, 4)
    assert.equal(playbook.invariants[0].id, 'price-server-side')
    ok('行业清单：4 个行业，电商 4 条不变量', playbook.name)

    await biz.call('pt_biz', {
      action: 'model',
      domain: 'ecommerce',
      actors: ['user', 'admin'],
      entities: ['order', 'coupon'],
      notes: '定价页：满 199 减 50，券不可叠加',
    })
    const added = await biz.call('pt_biz', { action: 'invariant', items: playbook.invariants.slice(0, 2) })
    assert.equal(added.created.length, 2)
    assert.equal(added.total, 2)
    ok('业务模型 + 不变量入库', added.created.map((row) => row.id).join(','))

    const next = await biz.call('pt_next', {})
    assert.equal(next.business.invariants, 2)
    assert.equal(next.business.open, 2)
    assert.ok(next.actions.some((action) => action.tool === 'pt_biz'), 'pt_next 应推动未验证的不变量')
    ok('pt_next 把业务不变量纳入决策', `open=${next.business.open}`)

    await assert.rejects(
      () => biz.call('pt_biz', { action: 'test', id: added.created[0].id, state: 'violated' }),
      /必须给证据/,
    )
    ok('无证据判 violated 被拒（逻辑洞同样要证据）')

    const tested = await biz.call('pt_biz', {
      action: 'test',
      id: added.created[0].id,
      state: 'violated',
      evidence: 'POST /api/v2/price {"price":0.01} → charged=0.01（服务端采信客户端金额）',
      assetId: app.created[0].id,
    })
    assert.equal(tested.invariant.state, 'violated')
    assert.equal(tested.summary.violated, 1)
    ok('不变量被违反 → 记录证据并统计', `violated=${tested.summary.violated}`)

    const cells = await biz.call('pt_coverage', { action: 'matrix', assetId: app.created[0].id, state: 'tested', limit: 20 })
    assert.ok(cells.cells.some((cell) => cell.classId === 'price-tamper' && cell.note.includes('业务不变量')))
    ok('违反不变量自动关联矩阵格子（price-tamper）')

    const mutated = await biz.call('pt_biz', { action: 'mutate', method: 'POST', url: '/api/v2/price', body: { price: 199, quantity: 1 } })
    assert.ok(mutated.count >= 15, `expected many variants, got ${mutated.count}`)
    const kinds = mutated.variants.map((variant) => variant.kind)
    assert.ok(kinds.includes('price:zero') && kinds.includes('price:negative') && kinds.includes('concurrent-replay'))
    ok('变异器：金额/数量/换方法/并发重放', `${mutated.count} 个变体`)

    const open = await biz.call('pt_biz', { action: 'invariant', stateFilter: 'open' })
    assert.equal(open.invariants.length, 1)
    ok('按状态过滤不变量', `open=${open.invariants.length}`)
  } finally {
    await biz.close()
    try {
      fs.rmSync(bdir, { recursive: true, force: true })
    } catch {}
  }

  console.log(`\nPASS  ${results.length} 项检查全部通过 · dataDir=${dataDir}`)
  // Cleanup: dispose effects (closes the listener) and drop the temp data dir.
  for (const dispose of ctx.__effects ?? []) {
    try {
      if (typeof dispose === 'function') await dispose()
    } catch {}
  }
  await new Promise((resolve) => setTimeout(resolve, 100))
  try {
    fs.rmSync(dataDir, { recursive: true, force: true })
  } catch {}
}

// The fake context hides its map; expose it for the assertions above.
function collectRegistry(ctx) {
  const registry = ctx.__registry
  if (!registry) throw new Error('registry not exposed by fake context')
  return registry
}

/** Run the CLI in a separate process (the portable entry point real workers use). */
function runCli(args, { dataDir, env = {} } = {}) {
  const here = path.dirname(fileURLToPath(import.meta.url))
  const cli = path.join(here, '..', 'bin', 'artex-ops.mjs')
  const argv = [...args, ...(dataDir ? ['--data', dataDir] : [])]
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [cli, ...argv], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...env },
    })
    let out = ''
    let err = ''
    child.stdout.setEncoding('utf8').on('data', (chunk) => (out += chunk))
    child.stderr.setEncoding('utf8').on('data', (chunk) => (err += chunk))
    child.on('close', (code) => resolve({ code, out, err }))
    child.on('error', (error) => resolve({ code: 1, out, err: `${err}${error.message}` }))
  })
}

/** Drive the MCP stdio server: initialize → tools/list → tools/call. */
function runMcp(script, dataDir) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script], {
      env: { ...process.env, ARTEX_OPS_HOME: dataDir },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    const replies = new Map()
    let buffer = ''
    let stderr = ''
    const timer = setTimeout(() => {
      child.kill()
      reject(new Error(`mcp timeout; stderr=${stderr}; buffer=${buffer}`))
    }, 20000)
    child.stderr.setEncoding('utf8')
    child.stderr.on('data', (chunk) => {
      stderr += chunk
    })
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      buffer += chunk
      let index = buffer.indexOf('\n')
      while (index >= 0) {
        const line = buffer.slice(0, index).trim()
        buffer = buffer.slice(index + 1)
        index = buffer.indexOf('\n')
        if (line === '') continue
        let message
        try {
          message = JSON.parse(line)
        } catch {
          continue
        }
        if (message.id !== undefined) replies.set(message.id, message)
        if (replies.has(1) && replies.has(2) && replies.has(3)) {
          clearTimeout(timer)
          child.kill()
          resolve({
            initialize: replies.get(1).result,
            list: replies.get(2).result,
            call: replies.get(3).result,
          })
        }
      }
    })
    child.on('error', reject)
    const send = (message) => child.stdin.write(`${JSON.stringify(message)}\n`)
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'selftest', version: '1' } } })
    send({ jsonrpc: '2.0', method: 'notifications/initialized' })
    send({ jsonrpc: '2.0', id: 2, method: 'tools/list' })
    send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'pt_next', arguments: {} } })
  })
}

main().catch((error) => {
  console.error('\nFAIL', error)
  process.exitCode = 1
})
