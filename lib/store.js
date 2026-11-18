// Persistent state for the ARTEX ops layer.
//
// One JSON document holds the model (chains / facts / oobs / credentials /
// defense profiles / vulnerability candidates); credential material and hashed
// evidence live in sibling directories. Writes are atomic (tmp + rename) so a
// crash mid-write can never leave a truncated state file, and the whole doc is
// loaded lazily on first access.
import fs from 'node:fs'
import path from 'node:path'
import { createHash, randomBytes } from 'node:crypto'
import { resolveDataDir } from './paths.js'
import { evalAssertions, recomputeChain, stepOf } from './chains.js'
import { CLASSES, CLASS_BY_ID, CATEGORIES, classesFor, COVERAGE_STATES } from './taxonomy.js'

const STATE_VERSION = 1

export const CHAIN_STATUS = ['locked', 'ready', 'running', 'satisfied', 'unverified']
export const CANDIDATE_STATES = ['candidate', 'verifying', 'confirmed', 'refuted']
export const PHASES = ['recon', 'sweep', 'deepdive', 'report']

const PHASE_TRANSITIONS = {
  recon: ['sweep', 'deepdive'],
  sweep: ['deepdive', 'report', 'recon'],
  deepdive: ['sweep', 'report'],
  report: ['sweep', 'deepdive'],
}
export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']

const SEVERITY_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

function severityRank(severity) {
  return SEVERITY_ORDER[severity] ?? 0
}

function now() {
  return Date.now()
}

function statOf(file) {
  try {
    const stat = fs.statSync(file)
    return { mtimeMs: stat.mtimeMs, size: stat.size }
  } catch {
    return null
  }
}

/** Blocking sleep for the lock retry loop (Node allows Atomics.wait on the main thread). */
function sleepSync(ms) {
  const shared = new SharedArrayBuffer(4)
  Atomics.wait(new Int32Array(shared), 0, 0, ms)
}

function ensureDirs(paths) {
  for (const dir of [paths.root, paths.secrets, paths.oob, paths.evidence]) {
    fs.mkdirSync(dir, { recursive: true })
  }
}

function emptyState() {
  return {
    version: STATE_VERSION,
    seq: 1,
    mission: null,
    intents: [],
    activity: [],
    hints: [],
    assets: [],
    edges: [],
    anchors: [],
    findings: [],
    chains: [],
    facts: [],
    oobs: [],
    creds: [],
    defense: [],
    candidates: [],
    evidence: [],
    coverageCells: {},
  }
}

function maskSecret(secret) {
  const s = String(secret ?? '')
  if (s.length <= 4) return '****'
  if (s.length <= 10) return `${s.slice(0, 1)}****${s.slice(-1)}`
  return `${s.slice(0, 3)}…${s.slice(-4)}`
}

function slugify(text, fallback = 'item') {
  const slug = String(text ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48)
  return slug === '' ? fallback : slug
}

export class Store {
  constructor(config = {}) {
    this.paths = resolveDataDir(config)
    this.loaded = false
    this.state = emptyState()
    this.lastStat = null
    this.lockHeld = false
  }

  load() {
    if (this.loaded) return this.state
    this.loaded = true
    ensureDirs(this.paths)
    try {
      const raw = fs.readFileSync(this.paths.state, 'utf8')
      const parsed = JSON.parse(raw)
      if (parsed && typeof parsed === 'object') {
        this.state = { ...emptyState(), ...parsed }
        if (!Array.isArray(this.state.chains)) this.state.chains = []
      }
      this.lastStat = statOf(this.paths.state)
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        // Keep the unreadable document for inspection instead of silently dropping it.
        try {
          fs.renameSync(this.paths.state, `${this.paths.state}.corrupt-${now()}`)
        } catch {}
      }
    }
    return this.state
  }

  save() {
    this.load()
    const tmp = `${this.paths.state}.${process.pid}.${Math.random().toString(16).slice(2)}.tmp`
    fs.writeFileSync(tmp, `${JSON.stringify(this.state, null, 2)}\n`, 'utf8')
    fs.renameSync(tmp, this.paths.state)
    this.lastStat = statOf(this.paths.state)
  }

  // ── cross-process write serialization ─────────────────────────────────────
  //
  // 多个 worker 可以同时是子 agent、CLI 进程或 MCP server，它们都"读-改-写"同一个
  // state.json。Node 单线程只保护同一实例内的调用；跨进程必须显式互斥，否则两个
  // worker 同时写会丢更新（last-writer-wins）。这里用 O_EXCL 锁文件 + 陈旧锁回收，
  // 只在「可能写」的工具调用期间持有，读调用不占锁（避免 pt_oob_poll 等待 10s 时
  // 把其他 worker 卡死）。
  lockPath() {
    return `${this.paths.state}.lock`
  }

  acquire({ timeoutMs = 8000, staleMs = 20000 } = {}) {
    if (this.lockHeld) return
    const deadline = Date.now() + timeoutMs
    for (;;) {
      try {
        const fd = fs.openSync(this.lockPath(), 'wx')
        fs.writeSync(fd, `${process.pid} ${Date.now()}`)
        fs.closeSync(fd)
        this.lockHeld = true
        return
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error
        const stat = statOf(this.lockPath())
        if (stat && Date.now() - stat.mtimeMs > staleMs) {
          try {
            fs.unlinkSync(this.lockPath())
          } catch {}
          continue
        }
        if (Date.now() > deadline) {
          throw new Error(
            'artex-ops: state.json 被另一个进程占用超过 8s（workers 太多或某个进程卡死）；先确认没有僵尸 worker，或手动删掉 state.json.lock',
          )
        }
        sleepSync(20)
      }
    }
  }

  release() {
    if (!this.lockHeld) return
    this.lockHeld = false
    try {
      fs.unlinkSync(this.lockPath())
    } catch {}
  }

  /** Pick up another process's commit before mutating (cheap mtime+size check). */
  reloadIfChanged() {
    const stat = statOf(this.paths.state)
    if (!stat) return false
    if (this.lastStat && stat.mtimeMs === this.lastStat.mtimeMs && stat.size === this.lastStat.size) return false
    this.loaded = false
    this.load()
    return true
  }

  nextId(prefix) {
    this.load()
    const n = this.state.seq++
    return `${prefix}-${n}`
  }

  // ── facts ──────────────────────────────────────────────────────────────────
  /** Record one observed/inferred fact. Same label upserts (keeps one row). */
  addFact({ label, summary, host = '', confidence = 'observed', evidence = '', intentId = '', assetId = '', worker = '' }) {
    this.load()
    const key = String(label ?? '').trim()
    if (key === '') throw new Error('pt_fact_add: label must be a non-empty string')
    const text = String(summary ?? '').trim()
    if (text === '') throw new Error('pt_fact_add: summary must be a non-empty string')
    if (!['observed', 'inferred'].includes(confidence)) {
      throw new Error(`pt_fact_add: confidence must be observed or inferred (got ${JSON.stringify(confidence)})`)
    }
    const existing = this.state.facts.find((f) => f.label === key)
    const row = {
      id: existing?.id ?? this.nextId('fact'),
      label: key,
      summary: text,
      host: String(host ?? '').trim(),
      confidence,
      evidence: String(evidence ?? '').trim(),
      ts: now(),
      hits: (existing?.hits ?? 0) + 1,
    }
    if (existing) Object.assign(existing, row)
    else this.state.facts.push(row)

    // 探索图边 + 资产锚点：哪条意图产出了这条事实、它落在哪台资产上。
    const owner = String(intentId ?? '') || (worker === '' ? '' : this.runningIntentOf(worker)?.id ?? '')
    if (owner !== '') this.linkEdge({ from: `intent:${owner}`, rel: 'yields', to: `fact:${row.id}` })
    const anchoredAsset = String(assetId ?? '') || this.assetIdForHost(row.host)
    if (anchoredAsset !== '') this.anchor({ node: `fact:${row.id}`, nodeType: 'fact', assetId: anchoredAsset, rel: 'observed_on' })

    this.save()
    return row
  }

  hasFact(label) {
    this.load()
    return this.state.facts.some((f) => f.label === label)
  }

  listFacts({ q = '', host = '', limit = 20 } = {}) {
    this.load()
    const needle = String(q ?? '').toLowerCase()
    const rows = this.state.facts
      .filter((f) => (host === '' ? true : f.host === host))
      .filter((f) =>
        needle === ''
          ? true
          : `${f.label} ${f.summary} ${f.evidence}`.toLowerCase().includes(needle),
      )
      .sort((a, b) => b.ts - a.ts)
    return rows.slice(0, Math.max(1, Math.min(200, Number(limit) || 20)))
  }

  // ── chains ─────────────────────────────────────────────────────────────────
  planChain({ title, chainId = '', host = '', steps = [] } = {}) {
    this.load()
    const name = String(title ?? '').trim()
    if (name === '') throw new Error('pt_chain_plan: title must be a non-empty string')
    if (!Array.isArray(steps) || steps.length === 0) {
      throw new Error('pt_chain_plan: steps must be a non-empty array')
    }
    if (steps.length > 24) throw new Error('pt_chain_plan: at most 24 steps per chain')
    const normalized = steps.map((step, index) => {
      const stepTitle = String(step?.title ?? '').trim()
      if (stepTitle === '') throw new Error(`pt_chain_plan: step ${index + 1} needs a title`)
      const asList = (value, field) => {
        if (value === undefined || value === null) return []
        const list = Array.isArray(value) ? value : [value]
        const out = list.map((item) => String(item ?? '').trim()).filter((item) => item !== '')
        for (const item of out) {
          if (!/^(fact|oob|cred|defense|candidate):/.test(item)) {
            throw new Error(
              `pt_chain_plan: step ${index + 1} ${field} entry ${JSON.stringify(item)} must start with fact:/oob:/cred:/defense:/candidate:`,
            )
          }
        }
        return out
      }
      return {
        ord: index + 1,
        title: stepTitle,
        pre: asList(step?.pre, 'pre'),
        post: asList(step?.post, 'post'),
        status: 'locked',
        evidence: '',
        ts: 0,
      }
    })

    const existing = chainId === '' ? undefined : this.state.chains.find((c) => c.id === chainId)
    const chain = {
      id: existing?.id ?? this.nextId('chain'),
      title: name,
      host: String(host ?? '').trim(),
      createdAt: existing?.createdAt ?? now(),
      updatedAt: now(),
      steps: existing ? this.preserveProgress(existing, normalized) : normalized,
    }
    if (existing) Object.assign(existing, chain)
    else this.state.chains.push(chain)
    recomputeChain(this, chain)
    this.save()
    return this.chainView(chain)
  }

  /** Re-planning a chain keeps a step's satisfied state when its title is unchanged. */
  preserveProgress(existing, steps) {
    return steps.map((step) => {
      const prior = existing.steps.find((s) => s.title === step.title)
      if (prior && (prior.status === 'satisfied' || prior.status === 'unverified')) {
        return { ...step, status: prior.status, evidence: prior.evidence, ts: prior.ts }
      }
      return step
    })
  }

  chains() {
    this.load()
    const out = this.state.chains.map((chain) => this.chainView(chain))
    return out.sort((a, b) => b.updatedAt - a.updatedAt)
  }

  chain(id) {
    this.load()
    return this.state.chains.find((c) => c.id === id)
  }

  chainView(chain) {
    recomputeChain(this, chain)
    return {
      id: chain.id,
      title: chain.title,
      host: chain.host,
      updatedAt: chain.updatedAt,
      steps: chain.steps.map((step) => ({
        ord: step.ord,
        title: step.title,
        status: step.status,
        pre: step.pre,
        post: step.post,
        evidence: step.evidence,
      })),
      nextReady: chain.steps.filter((s) => s.status === 'ready').map((s) => s.ord),
    }
  }

  /**
   * Advance a step only when its post-conditions hold. `force` records an
   * explicitly unverified advance instead of pretending the evidence exists.
   */
  advanceChain({ chainId, ord = 0, evidence = '', force = false } = {}) {
    this.load()
    const chain = this.chain(chainId)
    if (!chain) throw new Error(`pt_chain_advance: unknown chain ${JSON.stringify(chainId)}`)
    const step = ord > 0 ? stepOf(chain, ord) : chain.steps.find((s) => s.status === 'ready')
    if (!step) {
      const ready = chain.steps.filter((s) => s.status === 'ready').map((s) => s.ord)
      throw new Error(
        `pt_chain_advance: no such step${ready.length ? `; ready steps are ${ready.join(', ')}` : '; no step is ready yet'}`,
      )
    }
    if (step.status === 'satisfied') {
      return { ok: true, alreadySatisfied: true, chainId: chain.id, ord: step.ord, status: step.status, missing: [] }
    }
    const verdict = evalAssertions(this, step.post)
    if (!verdict.ok && !force) {
      step.status = 'running'
      if (String(evidence).trim() !== '') step.evidence = String(evidence).trim()
      chain.updatedAt = now()
      recomputeChain(this, chain)
      this.save()
      return {
        ok: false,
        chainId: chain.id,
        ord: step.ord,
        status: step.status,
        missing: verdict.missing,
        detail: verdict.detail,
        hint: 'post 条件未满足：先用 pt_fact_add 登记真实观察，或用 pt_oob_poll 确认回连、pt_cred 落库、pt_defense 记录防护。确需跳过请显式传 force=true（会记为 unverified）。',
      }
    }
    step.status = force && !verdict.ok ? 'unverified' : 'satisfied'
    step.evidence = String(evidence).trim()
    step.ts = now()
    chain.updatedAt = now()
    recomputeChain(this, chain)
    this.save()
    return {
      ok: true,
      forced: force && !verdict.ok,
      chainId: chain.id,
      ord: step.ord,
      status: step.status,
      missing: force && !verdict.ok ? verdict.missing : [],
      unlocked: chain.steps.filter((s) => s.status === 'ready').map((s) => s.ord),
    }
  }

  // ── out-of-band probes ─────────────────────────────────────────────────────
  addOob({ token, kind = 'http', note = '', url = '', dnsName = '' }) {
    this.load()
    const row = {
      id: this.nextId('oob'),
      token,
      kind,
      note: String(note ?? '').trim(),
      url,
      dnsName,
      hits: 0,
      createdAt: now(),
      lastHitAt: 0,
    }
    this.state.oobs.push(row)
    this.save()
    return row
  }

  oobShot(id) {
    this.load()
    return this.state.oobs.find((o) => o.id === id || o.token === id)
  }

  oobs() {
    this.load()
    return this.state.oobs.slice().sort((a, b) => b.createdAt - a.createdAt)
  }

  bumpHit(id) {
    this.load()
    const row = this.oobShot(id)
    if (!row) return
    row.hits += 1
    row.lastHitAt = now()
    this.save()
  }

  // ── credentials ────────────────────────────────────────────────────────────
  addCred({ host, kind = 'password', username = '', secret, note = '' }) {
    this.load()
    const target = String(host ?? '').trim()
    if (target === '') throw new Error('pt_cred: host must be a non-empty string')
    const allowed = ['password', 'cookie', 'jwt', 'sshkey', 'hash', 'token', 'session']
    if (!allowed.includes(kind)) {
      throw new Error(`pt_cred: kind must be one of ${allowed.join(', ')} (got ${JSON.stringify(kind)})`)
    }
    if (typeof secret !== 'string' || secret.trim() === '') {
      throw new Error('pt_cred: secret must be a non-empty string')
    }
    const id = this.nextId('cred')
    const file = path.join(this.paths.secrets, `${id}.secret`)
    fs.writeFileSync(file, secret, { encoding: 'utf8', mode: 0o600 })
    const row = {
      id,
      host: target,
      kind,
      username: String(username ?? '').trim(),
      masked: maskSecret(secret),
      secretRef: file,
      note: String(note ?? '').trim(),
      ts: now(),
    }
    this.state.creds.push(row)
    this.save()
    return row
  }

  listCreds({ host = '' } = {}) {
    this.load()
    return this.state.creds
      .filter((c) => (host === '' ? true : c.host === host))
      .map((c) => ({ id: c.id, host: c.host, kind: c.kind, username: c.username, masked: c.masked, note: c.note, ts: c.ts }))
  }

  credSecret(id) {
    this.load()
    const row = this.state.creds.find((c) => c.id === id)
    if (!row) throw new Error(`pt_cred: unknown credential id ${JSON.stringify(id)}`)
    return { row, secret: fs.readFileSync(row.secretRef, 'utf8') }
  }

  hasCred(host) {
    this.load()
    return this.state.creds.some((c) => c.host === host || c.host.endsWith(`.${host}`) || host.endsWith(`.${c.host}`))
  }

  // ── defense profiles ───────────────────────────────────────────────────────
  noteDefense({ host, waf = '', blockedSignature = '', blockedFamilies = [], workingBypass = '' } = {}) {
    this.load()
    const target = String(host ?? '').trim()
    if (target === '') throw new Error('pt_defense: host must be a non-empty string')
    const families = (Array.isArray(blockedFamilies) ? blockedFamilies : [blockedFamilies])
      .map((f) => String(f ?? '').trim())
      .filter((f) => f !== '')
    const row = this.state.defense.find((d) => d.host === target)
    const merged = {
      host: target,
      waf: String(waf ?? '').trim() || row?.waf || '',
      blockedSignature: String(blockedSignature ?? '').trim() || row?.blockedSignature || '',
      blockedFamilies: [...new Set([...(row?.blockedFamilies ?? []), ...families])],
      workingBypass: String(workingBypass ?? '').trim() || row?.workingBypass || '',
      ts: now(),
    }
    if (row) Object.assign(row, merged)
    else this.state.defense.push(merged)
    this.save()
    return merged
  }

  listDefense({ host = '' } = {}) {
    this.load()
    return this.state.defense.filter((d) => (host === '' ? true : d.host === host))
  }

  hasDefense(host) {
    this.load()
    return this.state.defense.some((d) => d.host === host)
  }

  // ── vulnerability candidates ───────────────────────────────────────────────
  addCandidate({ host, title, source = 'model', ref = '', cve = '' } = {}) {
    this.load()
    const target = String(host ?? '').trim()
    const name = String(title ?? '').trim()
    if (target === '') throw new Error('pt_candidate: host must be a non-empty string')
    if (name === '') throw new Error('pt_candidate: title must be a non-empty string')
    const allowed = ['template', 'cve', 'model', 'guess']
    if (!allowed.includes(source)) {
      throw new Error(`pt_candidate: source must be one of ${allowed.join(', ')}`)
    }
    const row = {
      id: this.nextId('cand'),
      host: target,
      title: name,
      source,
      ref: String(ref ?? '').trim(),
      cve: String(cve ?? '').trim().toUpperCase(),
      state: 'candidate',
      evidence: '',
      verdictNote: '',
      oobId: '',
      ts: now(),
    }
    this.state.candidates.push(row)
    this.save()
    return row
  }

  listCandidates({ state = '', host = '', limit = 40 } = {}) {
    this.load()
    return this.state.candidates
      .filter((c) => (state === '' ? true : c.state === state))
      .filter((c) => (host === '' ? true : c.host === host))
      .sort((a, b) => b.ts - a.ts)
      .slice(0, Math.max(1, Math.min(200, Number(limit) || 40)))
  }

  candidate(id) {
    this.load()
    return this.state.candidates.find((c) => c.id === id)
  }

  /**
   * Record a verdict. `confirmed` demands real evidence: a non-empty evidence
   * string or an OOB probe that actually received a hit. Version/CVE matching
   * alone never satisfies this, so "looks exploitable" cannot become a finding.
   */
  setCandidateVerdict({ id, verdict, evidence = '', note = '', oobId = '' } = {}) {
    this.load()
    const row = this.candidate(id)
    if (!row) throw new Error(`pt_candidate: unknown candidate ${JSON.stringify(id)}`)
    const allowed = ['confirmed', 'refuted', 'inconclusive', 'verifying']
    if (!allowed.includes(verdict)) {
      throw new Error(`pt_candidate: verdict must be one of ${allowed.join(', ')}`)
    }
    const proof = String(evidence ?? '').trim()
    const shot = oobId === '' ? undefined : this.oobShot(oobId)
    if (oobId !== '' && !shot) throw new Error(`pt_candidate: unknown oob id ${JSON.stringify(oobId)}`)
    const oobHit = shot !== undefined && shot.hits > 0
    if (verdict === 'confirmed') {
      if (proof.length < 8 && !oobHit) {
        throw new Error(
          'pt_candidate: confirmed 需要真实证据——evidence 至少写清「命令/payload + 关键回显」，或用 oobId 指向已有回连的探测点；仅凭版本/CVE/模板匹配不能确认',
        )
      }
    }
    if (verdict === 'refuted' && proof.length < 4) {
      throw new Error('pt_candidate: refuted 需要写明否定依据（探测方式 + 结果）')
    }
    row.state = verdict === 'inconclusive' ? 'verifying' : verdict
    row.evidence = proof !== '' ? proof : row.evidence
    row.verdictNote = String(note ?? '').trim() || row.verdictNote
    row.oobId = oobId !== '' ? (shot?.id ?? '') : row.oobId
    row.ts = now()
    this.save()
    return row
  }

  // ── business logic（业务模型 + 不变量）────────────────────────────────────
  //
  // 逻辑洞不靠 payload 命中，靠"业务规则被违反"。所以这里存三样：
  // 业务模型（谁 / 什么东西 / 什么流程）、不变量清单（可证伪的规则）、每条规则的验证结论。
  businessOf() {
    const mission = this.missionRow()
    if (!mission) return null
    mission.business = mission.business ?? { domain: '', actors: [], entities: [], notes: '', invariants: [] }
    return mission.business
  }

  setBusinessModel({ domain = '', actors = [], entities = [], notes = '' } = {}) {
    this.load()
    this.acquire()
    try {
      this.reloadIfChanged()
      const business = this.businessOf()
      if (!business) throw new Error('pt_biz: 还没有 mission')
      if (domain !== '') business.domain = String(domain)
      if (actors.length > 0) business.actors = [...new Set([...business.actors, ...actors.map(String)])]
      if (entities.length > 0) business.entities = [...new Set([...business.entities, ...entities.map(String)])]
      if (notes !== '') business.notes = [business.notes, String(notes)].filter(Boolean).join('\n')
      this.save()
      return { business }
    } finally {
      this.release()
    }
  }

  addBizInvariants({ items = [] } = {}) {
    this.load()
    this.acquire()
    try {
      this.reloadIfChanged()
      const business = this.businessOf()
      if (!business) throw new Error('pt_biz: 还没有 mission')
      const created = []
      for (const item of items) {
        const statement = String(item.statement ?? '').trim()
        if (statement === '') continue
        const row = {
          id: this.nextId('inv'),
          statement,
          classId: String(item.classId ?? ''),
          recipe: Array.isArray(item.recipe) ? item.recipe.map(String) : [],
          detect: String(item.detect ?? ''),
          source: String(item.source ?? 'manual'),
          state: 'open',
          evidence: '',
          assetId: '',
          ts: now(),
        }
        business.invariants.push(row)
        created.push(row)
      }
      this.save()
      return { created, total: business.invariants.length }
    } finally {
      this.release()
    }
  }

  testBizInvariant({ id, state = 'inconclusive', evidence = '', assetId = '' } = {}) {
    this.load()
    this.acquire()
    try {
      this.reloadIfChanged()
      const business = this.businessOf()
      if (!business) throw new Error('pt_biz: 还没有 mission')
      const row = business.invariants.find((item) => item.id === id)
      if (!row) throw new Error(`pt_biz: 没有这条不变量 ${id}`)
      if (!['open', 'holds', 'violated', 'inconclusive'].includes(state)) throw new Error('pt_biz: state 必须是 holds/violated/inconclusive')
      if (state === 'violated' && String(evidence).trim().length < 8) {
        throw new Error('pt_biz: 判定 violated 必须给证据（命令/payload + 关键回显）；没证据先记 inconclusive')
      }
      row.state = state
      row.evidence = String(evidence ?? '').trim()
      if (assetId !== '') row.assetId = String(assetId)
      // 不变量被违反 = 该逻辑面确实存在 → 顺手把对应矩阵格子标 tested
      if (state !== 'open' && row.assetId !== '' && row.classId !== '') {
        try {
          this.markCoverage({ assetId: row.assetId, classId: row.classId, state: 'tested', note: `业务不变量 ${row.id}: ${state}`, skipResolved: true })
        } catch {}
      }
      this.save()
      return { invariant: row, summary: this.businessSummary() }
    } finally {
      this.release()
    }
  }

  listBizInvariants({ state = '' } = {}) {
    const business = this.businessOf()
    if (!business) return []
    return state === '' ? business.invariants : business.invariants.filter((item) => item.state === state)
  }

  businessSummary() {
    const business = this.businessOf()
    if (!business) return { domain: '', invariants: 0, open: 0, holds: 0, violated: 0, inconclusive: 0, actors: 0, entities: 0 }
    const count = (state) => business.invariants.filter((item) => item.state === state).length
    return {
      domain: business.domain,
      invariants: business.invariants.length,
      open: count('open'),
      holds: count('holds'),
      violated: count('violated'),
      inconclusive: count('inconclusive'),
      actors: business.actors.length,
      entities: business.entities.length,
    }
  }

  // ── per-mission workspace ─────────────────────────────────────────────────
  //
  // 每次 mission 一个独立目录：work/（脚本、payload、抓包等中间产物）、evidence/（证据）、
  // report.md、manifest.json。这样多次测试不会互相污染，也能整包交给人复现或归档。
  workspaceOf() {
    const mission = this.missionRow()
    if (!mission) return null
    const root = path.join(this.paths.root, 'missions', mission.id)
    return {
      root,
      work: path.join(root, 'work'),
      evidence: path.join(root, 'evidence'),
      report: path.join(root, 'report.md'),
      manifest: path.join(root, 'manifest.json'),
    }
  }

  ensureWorkspace() {
    const ws = this.workspaceOf()
    if (!ws) return null
    for (const dir of [ws.root, ws.work, ws.evidence]) fs.mkdirSync(dir, { recursive: true })
    return ws
  }

  /** 工作区清单：work/ 与 evidence/ 下的文件（供 pt_mission action=workspace 展示）。 */
  workspaceListing({ limit = 50 } = {}) {
    const ws = this.ensureWorkspace()
    if (!ws) return null
    const list = (dir) => {
      try {
        return fs
          .readdirSync(dir)
          .slice(0, limit)
          .map((name) => {
            const full = path.join(dir, name)
            const stat = fs.statSync(full)
            return { name, bytes: stat.size, dir: stat.isDirectory() }
          })
      } catch {
        return []
      }
    }
    return { ...ws, workFiles: list(ws.work), evidenceFiles: list(ws.evidence) }
  }

  /** 把报告与清单写进 mission 目录（prove / report 时调用）。 */
  writeWorkspaceArtifacts() {
    const ws = this.ensureWorkspace()
    if (!ws) return null
    const report = this.missionReport()
    fs.writeFileSync(ws.report, report.markdown, 'utf8')
    const manifest = {
      mission: this.missionView(),
      coverage: this.coverage(),
      classCoverage: this.coverageStats(),
      findings: this.listFindings({ limit: 200 }),
      evidence: this.state.evidence.filter((row) => row.path.startsWith(ws.root)),
      goals: this.listGoals(),
      hints: this.state.hints.filter((hint) => hint.missionId === (this.missionRow()?.id ?? '')),
      chains: this.chains(),
      generatedAt: new Date().toISOString(),
    }
    fs.writeFileSync(ws.manifest, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
    return { report: ws.report, manifest: ws.manifest, root: ws.root }
  }

  /** 清空工作区（默认只清 work/，evidence 与报告要显式指定）。 */
  cleanWorkspace({ work = true, evidence = false, artifacts = false } = {}) {
    const ws = this.workspaceOf()
    if (!ws) throw new Error('pt_mission: 还没有 mission')
    const removed = { work: 0, evidence: 0, artifacts: 0 }
    const emptyDir = (dir) => {
      let count = 0
      let entries = []
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true })
      } catch {
        return 0
      }
      for (const entry of entries) {
        const full = path.join(dir, entry.name)
        try {
          if (entry.isDirectory()) {
            count += fs.readdirSync(full).length
            fs.rmSync(full, { recursive: true, force: true })
          } else {
            fs.unlinkSync(full)
            count += 1
          }
        } catch {}
      }
      return count
    }
    if (work) removed.work = emptyDir(ws.work)
    if (evidence) {
      removed.evidence = emptyDir(ws.evidence)
      // 证据文件没了，索引也要跟着清，避免报告指向不存在的文件
      this.state.evidence = this.state.evidence.filter((row) => !row.path.startsWith(ws.root))
    }
    if (artifacts) {
      for (const file of [ws.report, ws.manifest]) {
        try {
          if (fs.existsSync(file)) {
            fs.unlinkSync(file)
            removed.artifacts += 1
          }
        } catch {}
      }
    }
    this.save()
    return { workspace: ws, removed, remaining: this.workspaceListing({ limit: 50 }) }
  }
  // ── evidence ───────────────────────────────────────────────────────────────
  saveEvidence({ name = 'evidence', content, note = '' }) {
    this.load()
    const body = typeof content === 'string' ? content : JSON.stringify(content, null, 2)
    if (body === '' || body === undefined) throw new Error('pt_evidence_save: content must be a non-empty string')
    const stamp = new Date().toISOString().replace(/[:.]/g, '-')
    // 有进行中的 mission 就落进它的 evidence/，没有才回到全局目录。
    const ws = this.ensureWorkspace()
    const dir = ws ? ws.evidence : this.paths.evidence
    const file = path.join(dir, `${stamp}-${slugify(name)}.txt`)
    fs.writeFileSync(file, body, 'utf8')
    const sha256 = createHash('sha256').update(body).digest('hex')
    const row = { id: this.nextId('ev'), name: slugify(name), path: file, sha256, bytes: Buffer.byteLength(body), note: String(note ?? '').trim(), ts: now() }
    this.state.evidence.push(row)
    this.save()
    return row
  }

  // ── mission (the ARTEX-style task frame) ──────────────────────────────────
  startMission({ goal, scope = [], constraints = [], title = '', replace = false, goals = [] } = {}) {
    this.load()
    const target = String(goal ?? '').trim()
    if (target === '') throw new Error('pt_mission: goal must be a non-empty string')
    const running = this.state.mission && this.state.mission.state === 'running'
    if (running && replace !== true) {
      throw new Error(
        `pt_mission: 已有进行中的 mission（${this.state.mission.id}）。要换目标先 action=state 看现状，或显式传 replace=true 重开（旧 mission 的记录会保留在报告里但不参与 pt_next）`,
      )
    }
    const list = (value) =>
      (Array.isArray(value) ? value : value === undefined || value === null ? [] : [value])
        .map((item) => String(item ?? '').trim())
        .filter((item) => item !== '')
    this.state.mission = {
      id: this.nextId('mission'),
      title: String(title ?? '').trim(),
      goal: target,
      scope: list(scope),
      constraints: list(constraints),
      state: 'running',
      phase: 'recon',
      createdAt: now(),
      closedAt: 0,
      evidence: '',
      note: '',
      goals: [],
    }
    // 目标可以拆成多条（ARTEX 的 goals + prove_goal）：每条都要有独立达成依据。
    // 没显式给 goals 时用 mission.goal 生成一条 `derived` 目标——它和 mission 同源，
    // 允许用 mission 级证据直接结清（否则单目标任务会被迫多走一步空证明）。
    const goalTexts = list(goals)
    const explicit = goalTexts.length > 0
    for (const text of explicit ? goalTexts : [target]) {
      this.state.mission.goals.push({
        id: this.nextId('goal'),
        text,
        state: 'open',
        evidence: '',
        derived: !explicit,
        ts: now(),
      })
    }
    // A new mission starts with a clean intent frontier; assets/facts/evidence stay
    // (they are observations, not task state) but are tagged by missionId at write.
    this.state.intents = this.state.intents.filter((intent) => intent.missionId !== this.state.mission.id)
    this.save()
    this.ensureWorkspace()
    return this.missionView()
  }

  missionRow() {
    this.load()
    return this.state.mission
  }

  missionView() {
    const mission = this.missionRow()
    if (!mission) return null
    const intents = this.state.intents.filter((intent) => intent.missionId === mission.id)
    return {
      ...mission,
      workspace: this.workspaceOf(),
      intents: {
        open: intents.filter((i) => i.state === 'open').length,
        running: intents.filter((i) => i.state === 'running').length,
        done: intents.filter((i) => i.state === 'done').length,
        exhausted: intents.filter((i) => i.state === 'exhausted').length,
        blocked: intents.filter((i) => i.state === 'blocked').length,
      },
    }
  }

  proveMission({ evidence = '', note = '', force = false } = {}) {
    const mission = this.missionRow()
    if (!mission) throw new Error('pt_mission: 还没有 mission；先 action=start')
    if (mission.state !== 'running') throw new Error(`pt_mission: mission 已是 ${mission.state}，无需再证明`)
    const proof = String(evidence ?? '').trim()
    if (proof.length < 8) {
      throw new Error('pt_mission: prove 需要真实证据（命令/请求 + 关键回显，或用 pt_evidence_save 的 sha256/path）')
    }
    const open = this.state.intents.filter((i) => i.missionId === mission.id && (i.state === 'open' || i.state === 'running'))
    if (open.length > 0 && force !== true) {
      throw new Error(
        `pt_mission: 还有 ${open.length} 条 intent 未收口（#${open.map((i) => i.id).join(', #')}）；先 pt_intent done/exhausted/blocked 收口，或显式 force=true 承认未收口收尾`,
      )
    }
    const unmet = (mission.goals ?? []).filter((g) => g.state !== 'met')
    // 单条 derived 目标 = mission.goal 本身，用 mission 级证据结清即可；
    // 显式拆出来的多个目标必须逐个 prove。
    if (unmet.length === 1 && unmet[0].derived === true && force !== true) {
      unmet[0].state = 'met'
      unmet[0].evidence = proof
      unmet[0].ts = now()
    } else if (unmet.length > 0 && force !== true) {
      throw new Error(
        `pt_mission: 还有 ${unmet.length} 个目标未达成（${unmet.map((g) => `${g.id}:${g.text}`).join('; ')}）；用 pt_goal action=prove 逐个标记达成，或显式 force=true`,
      )
    }
    // 类型覆盖同样是一道收尾闸门：没测完的类目不能靠 prove 蒙过去。
    const classStats = this.coverageStats()
    if (classStats.untested > 0 && force !== true) {
      throw new Error(
        `pt_mission: 还有 ${classStats.untested} 个「资产 × 漏洞类型」格子未测（覆盖率 ${classStats.pct}%）；用 pt_coverage action=next 补测或 action=mark 标 na（需写理由），或显式 force=true`,
      )
    }
    mission.state = 'done'
    mission.closedAt = now()
    mission.evidence = proof
    mission.note = String(note ?? '').trim()
    this.save()
    const artifacts = this.writeWorkspaceArtifacts()
    return { ...this.missionView(), artifacts }
  }

  stopMission({ reason = '' } = {}) {
    const mission = this.missionRow()
    if (!mission) throw new Error('pt_mission: 还没有 mission')
    mission.state = 'stopped'
    mission.closedAt = now()
    mission.note = String(reason ?? '').trim()
    for (const intent of this.state.intents) {
      if (intent.missionId === mission.id && (intent.state === 'open' || intent.state === 'running')) {
        intent.state = 'blocked'
        intent.output = 'mission stopped'
        intent.closedAt = now()
      }
    }
    this.save()
    return this.missionView()
  }

  // ── phase (recon → sweep → deepdive → report) ────────────────────────────
  //
  // 阶段不是装饰：同一个人在"挖面"和"打洞"时该做的事完全不同。没有阶段约束时，
  // 常见故障是刚发现两个端點就开始逐个试 payload，面还没摸清、覆盖度永远上不去。
  phaseOf() {
    return this.missionRow()?.phase ?? 'recon'
  }

  setPhase({ phase, note = '', force = false } = {}) {
    const mission = this.missionRow()
    if (!mission) throw new Error('pt_phase: 还没有 mission；先 pt_mission action=start')
    const next = String(phase ?? '').trim()
    if (!PHASES.includes(next)) throw new Error(`pt_phase: phase must be one of ${PHASES.join(', ')}`)
    const current = mission.phase ?? 'recon'
    if (next === current) {
      return { phase: next, previous: current, changed: false, note: mission.phaseNote ?? '' }
    }
    const allowed = PHASE_TRANSITIONS[current] ?? []
    if (!allowed.includes(next) && force !== true) {
      throw new Error(
        `pt_phase: ${current} → ${next} 不是允许的迁移（可选：${allowed.join(', ')}）；确认要走这条就传 force=true`,
      )
    }
    mission.phase = next
    mission.phaseNote = String(note ?? '').trim()
    mission.phaseAt = now()
    this.logActivity({ worker: 'system', intentId: '', kind: 'note', summary: `phase ${current} → ${next}${mission.phaseNote ? `: ${mission.phaseNote}` : ''}` })
    this.save()
    return { phase: next, previous: current, changed: true, note: mission.phaseNote }
  }

  // ── goals (each goal is proved on its own) ────────────────────────────────
  addGoal({ text }) {
    const mission = this.missionRow()
    if (!mission) throw new Error('pt_goal: 还没有 mission')
    const value = String(text ?? '').trim()
    if (value === '') throw new Error('pt_goal: text must be a non-empty string')
    mission.goals = mission.goals ?? []
    const row = { id: this.nextId('goal'), text: value, state: 'open', evidence: '', ts: now() }
    mission.goals.push(row)
    this.save()
    return row
  }

  listGoals() {
    const mission = this.missionRow()
    return (mission?.goals ?? []).map((goal) => ({ ...goal }))
  }

  /** Mark one goal met. Evidence is mandatory: a goal is a claim, not a checkbox. */
  proveGoal({ id, evidence = '', force = false }) {
    const mission = this.missionRow()
    if (!mission) throw new Error('pt_goal: 还没有 mission')
    const goal = (mission.goals ?? []).find((row) => row.id === id)
    if (!goal) throw new Error(`pt_goal: unknown goal ${JSON.stringify(id)}`)
    const proof = String(evidence ?? '').trim()
    if (proof.length < 8 && force !== true) {
      throw new Error('pt_goal: 达成一个目标需要真实证据（命令/请求 + 关键回显，或证据文件 sha256/path）')
    }
    goal.state = 'met'
    goal.evidence = proof
    goal.ts = now()
    this.save()
    return { ...goal }
  }

  goalsSummary() {
    const goals = this.listGoals()
    return { total: goals.length, met: goals.filter((g) => g.state === 'met').length, open: goals.filter((g) => g.state !== 'met').length }
  }

  // ── hints (the human's own words, kept as first-class nodes) ───────────────
  /**
   * A hint is what the human typed, verbatim — not an intent. It never enters the
   * frontier; it sits on the exploration graph until some intent addresses it, so
   * a directive cannot be silently dropped and `pt_next` can point at it.
   */
  addHint({ text, assetIds = [], worker = 'human' }) {
    this.load()
    const value = String(text ?? '').trim()
    if (value === '') throw new Error('pt_hint: text must be a non-empty string')
    const mission = this.missionRow()
    const row = {
      id: this.nextId('hint'),
      missionId: mission?.id ?? '',
      text: value,
      state: 'open',
      intentIds: [],
      assetIds: (Array.isArray(assetIds) ? assetIds : [assetIds]).map((id) => String(id ?? '')).filter(Boolean),
      by: String(worker ?? '').trim() || 'human',
      ts: now(),
    }
    // 文本里提到的资产自动挂锚点（人指的方向 → 落到具体资产上）。
    const lower = value.toLowerCase()
    for (const asset of this.state.assets) {
      const needles = [asset.name, asset.host, asset.url].filter(Boolean).map((v) => String(v).toLowerCase())
      if (needles.some((needle) => needle !== '' && lower.includes(needle))) {
        if (!row.assetIds.includes(asset.id)) row.assetIds.push(asset.id)
        this.anchor({ node: `hint:${row.id}`, nodeType: 'hint', assetId: asset.id, rel: 'suggests' })
      }
    }
    this.state.hints.push(row)
    this.save()
    return row
  }

  listHints({ state = '', limit = 20 } = {}) {
    this.load()
    const mission = this.missionRow()
    return this.state.hints
      .filter((hint) => (mission ? hint.missionId === mission.id : true))
      .filter((hint) => (state === '' ? true : hint.state === state))
      .sort((a, b) => b.ts - a.ts)
      .slice(0, Math.max(1, Math.min(100, Number(limit) || 20)))
      .map((hint) => ({ ...hint }))
  }

  openHints() {
    return this.listHints({ state: 'open', limit: 20 })
  }

  /** Link a hint to the intent that takes it up; the hint leaves the open set. */
  addressHint({ id, intentId = '' }) {
    this.load()
    const hint = this.state.hints.find((row) => row.id === id)
    if (!hint) throw new Error(`pt_hint: unknown hint ${JSON.stringify(id)}`)
    hint.state = 'addressed'
    if (intentId !== '' && !hint.intentIds.includes(intentId)) hint.intentIds.push(String(intentId))
    if (intentId !== '') this.linkEdge({ from: `hint:${hint.id}`, rel: 'spawns', to: `intent:${intentId}` })
    this.save()
    return { ...hint }
  }

  // ── intents (one worker = one intent, the ARTEX frontier) ─────────────────
  addIntents({ summaries = [], priority = 0 } = {}) {
    this.load()
    const mission = this.missionRow()
    if (!mission) throw new Error('pt_intent: 还没有 mission；先 pt_mission action=start')
    if (!Array.isArray(summaries) || summaries.length === 0) {
      throw new Error('pt_intent: summaries must be a non-empty array')
    }
    if (summaries.length > 8) throw new Error('pt_intent: 一次最多 8 条（一次派太多会让链路散掉）')
    const live = this.state.intents.filter(
      (intent) => intent.missionId === mission.id && (intent.state === 'open' || intent.state === 'running'),
    )
    const created = []
    const skipped = []
    for (const item of summaries) {
      const summary = String(typeof item === 'string' ? item : item?.summary ?? '').trim()
      if (summary === '') throw new Error('pt_intent: 每条 intent 的 summary 必须非空')
      if (live.some((intent) => intent.summary === summary)) {
        skipped.push({ summary, reason: '与在跑/在排队的 intent 重复' })
        continue
      }
      const row = {
        id: this.nextId('intent'),
        missionId: mission.id,
        summary,
        assetIds: Array.isArray(item?.assetIds) ? item.assetIds.map((id) => String(id)) : [],
        parentIds: Array.isArray(item?.parentIds) ? item.parentIds.map((id) => String(id)) : [],
        hintIds: Array.isArray(item?.hintIds) ? item.hintIds.map((id) => String(id)) : [],
        priority: Number.isFinite(Number(item?.priority)) ? Number(item.priority) : Number(priority) || 0,
        state: 'open',
        claimedBy: '',
        claimedAt: 0,
        closedAt: 0,
        output: '',
        writes: null,
        baseline: null,
      }
      // 一条 intent 明确"接的是哪条 hint"——人给的方向因此可追踪到执行。
      for (const hintId of row.hintIds) this.addressHint({ id: hintId, intentId: row.id })
      if (row.hintIds.length > 0) this.linkEdge({ from: `intent:${row.id}`, rel: 'derived_from', to: `hint:${row.hintIds[0]}` })
      this.state.intents.push(row)
      live.push(row)
      created.push(row)
    }
    this.save()
    return { created, skipped, open: this.state.intents.filter((i) => i.missionId === mission.id && i.state === 'open').length }
  }

  intentRow(id) {
    this.load()
    return this.state.intents.find((intent) => intent.id === id)
  }

  /** The intent a given worker currently holds (empty object when idle). */
  runningIntentOf(worker) {
    this.load()
    const mission = this.missionRow()
    return this.state.intents.find(
      (intent) => (mission ? intent.missionId === mission.id : true) && intent.state === 'running' && intent.claimedBy === worker,
    )
  }

  listIntents({ state = '', limit = 20 } = {}) {
    this.load()
    const mission = this.missionRow()
    const rows = this.state.intents
      .filter((intent) => (mission ? intent.missionId === mission.id : true))
      .filter((intent) => (state === '' ? true : intent.state === state))
      .slice()
      .sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id))
    const cap = Math.max(1, Math.min(100, Number(limit) || 20))
    return rows.slice(0, cap).map((intent) => ({
      id: intent.id,
      summary: intent.summary,
      state: intent.state,
      priority: intent.priority,
      claimedBy: intent.claimedBy,
      writes: intent.writes,
      output: intent.output,
    }))
  }

  /** Claim the next intent. One in-flight intent per claimer keeps the loop honest. */
  claimIntent({ by = 'chat' } = {}) {
    this.load()
    const mission = this.missionRow()
    if (!mission) throw new Error('pt_intent: 还没有 mission；先 pt_mission action=start')
    const running = this.state.intents.find(
      (intent) => intent.missionId === mission.id && intent.state === 'running' && intent.claimedBy === by,
    )
    if (running) {
      return {
        reused: true,
        intent: { id: running.id, summary: running.summary, assetIds: running.assetIds, claimedAt: running.claimedAt },
        hint: '你手上还有一条 running intent——先做完并 pt_intent done，再领下一条（ARTEX 的边界：一个 worker 同时只做一条意图）。',
      }
    }
    const next = this.state.intents
      .filter((intent) => intent.missionId === mission.id && intent.state === 'open')
      .sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id))[0]
    if (!next) {
      return { intent: null, hint: 'frontier 为空：没有待执行意图。用 pt_next 看该补哪个方向（未测资产 / 待验证候选 / 未覆盖的链步骤）。' }
    }
    next.state = 'running'
    next.claimedBy = by
    next.claimedAt = now()
    next.baseline = {
      facts: this.state.facts.length,
      assets: this.state.assets.length,
      findings: this.state.findings.length,
    }
    this.logActivity({
      worker: by,
      intentId: next.id,
      kind: 'claim',
      summary: `claim: ${next.summary}`,
      detail: '',
    })
    this.save()
    return {
      reused: false,
      intent: { id: next.id, summary: next.summary, assetIds: next.assetIds, parentIds: next.parentIds },
      hint: '只做这一条意图；做完用 pt_intent done 收口（写回量按这条意图的 activity 统计）。',
    }
  }

  finishIntent({ id, state = 'done', output = '' } = {}) {
    this.load()
    const intent = this.intentRow(id)
    if (!intent) throw new Error(`pt_intent: unknown intent ${JSON.stringify(id)}`)
    const allowed = ['done', 'exhausted', 'blocked', 'open']
    if (!allowed.includes(state)) throw new Error(`pt_intent: state must be one of ${allowed.join(', ')}`)
    // 多 worker 并行时，全局计数差值会被别的 worker 污染；优先按本条意图的
    // activity 归属统计，没有 activity 时才回落到 baseline 差值（单人场景）。
    const attributed = this.state.activity.filter(
      (row) => row.intentId === intent.id && row.ts >= (intent.claimedAt || 0) && ['fact', 'asset', 'finding'].includes(row.kind),
    )
    const byKind = (kind) => attributed.filter((row) => row.kind === kind).length
    const base = intent.baseline ?? null
    intent.state = state === 'open' ? 'open' : state
    intent.output = String(output ?? '').trim()
    intent.closedAt = state === 'open' ? 0 : now()
    intent.claimedBy = state === 'open' ? '' : intent.claimedBy
    intent.writes = attributed.length > 0
      ? { facts: byKind('fact'), assets: byKind('asset'), findings: byKind('finding') }
      : {
          facts: Math.max(0, this.state.facts.length - (base?.facts ?? this.state.facts.length)),
          assets: Math.max(0, this.state.assets.length - (base?.assets ?? this.state.assets.length)),
          findings: Math.max(0, this.state.findings.length - (base?.findings ?? this.state.findings.length)),
        }
    const empty = state === 'done' && intent.writes.facts + intent.writes.assets + intent.writes.findings === 0
    this.logActivity({
      worker: intent.claimedBy || 'chat',
      intentId: intent.id,
      kind: 'close',
      summary: `${state}: ${intent.output || '(no output)'} — writes ${JSON.stringify(intent.writes)}`,
      detail: '',
    })
    this.save()
    const result = {
      intent: { id: intent.id, state: intent.state, output: intent.output, writes: intent.writes },
    }
    if (empty) {
      result.warning =
        '这条 intent 标记 done 但什么都没写回（facts/assets/findings 全 0）——要么真的没有观察，要么观察只在对话里。ARTEX 的规则是：写进库才算数。'
    }
    return result
  }

  // ── activity (the process-level store workers exchange through) ───────────
  /**
   * Append one process step. This is deliberately NOT a fact: a step is "what this
   * worker tried, and what came back", including dead ends, and it carries the
   * intent it belongs to. Facts are conclusions; activity is the raw trail another
   * worker can dig through when the conclusions look thin.
   */
  logActivity({ worker = 'chat', intentId = '', kind = 'note', summary = '', detail = '' } = {}) {
    this.load()
    const text = String(summary ?? '').trim()
    if (text === '') throw new Error('pt_trace: summary must be a non-empty string')
    const allowedKinds = ['claim', 'close', 'note', 'probe', 'fact', 'asset', 'finding', 'error', 'dead-end', 'bypass']
    if (!allowedKinds.includes(kind)) {
      throw new Error(`pt_trace: kind must be one of ${allowedKinds.join(', ')} (got ${JSON.stringify(kind)})`)
    }
    const rows = this.state.activity.filter((row) => row.intentId === intentId && row.worker === worker)
    const row = {
      id: this.nextId('step'),
      worker: String(worker ?? '').trim() || 'chat',
      intentId: String(intentId ?? ''),
      seq: rows.length + 1,
      kind,
      summary: text,
      detail: String(detail ?? ''),
      ts: now(),
    }
    this.state.activity.push(row)
    if (this.state.activity.length > 5000) this.state.activity.splice(0, this.state.activity.length - 5000)
    this.save()
    return row
  }

  /**
   * Keyword search across other workers' process trails — the direct analogue of
   * ARTEX's `search_all_worker_traces(q)`: it looks inside step text (summary +
   * detail), not at conclusions, and every hit reports the intent it came from.
   * `excludeIntent` is what keeps a worker from re-reading its own trail.
   */
  searchActivity({ q = '', excludeIntent = '', worker = '', kinds = [], limit = 20 } = {}) {
    this.load()
    const needle = String(q ?? '').toLowerCase()
    if (needle === '') throw new Error('pt_trace: search 需要非空 q（没有关键字就覆盖整条过程库，没有意义）')
    const wanted = new Set((Array.isArray(kinds) ? kinds : [kinds]).map((k) => String(k)).filter(Boolean))
    return this.state.activity
      .filter((row) => (excludeIntent === '' ? true : row.intentId !== excludeIntent))
      .filter((row) => (worker === '' ? true : row.worker === worker))
      .filter((row) => (wanted.size === 0 ? true : wanted.has(row.kind)))
      .filter((row) => `${row.summary}\n${row.detail}`.toLowerCase().includes(needle))
      .sort((a, b) => b.ts - a.ts)
      .slice(0, Math.max(1, Math.min(100, Number(limit) || 20)))
      .map((row) => ({
        stepId: row.id,
        intentId: row.intentId,
        worker: row.worker,
        seq: row.seq,
        kind: row.kind,
        summary: row.summary,
        detail: row.detail.length > 600 ? `${row.detail.slice(0, 600)}…` : row.detail,
        ts: row.ts,
      }))
  }

  /** One line per intent that produced process steps: who ran it, how many steps. */
  listTraces({ worker = '', limit = 20 } = {}) {
    this.load()
    const byIntent = new Map()
    for (const row of this.state.activity) {
      if (worker !== '' && row.worker !== worker) continue
      const key = row.intentId || '(unassigned)'
      const entry = byIntent.get(key) ?? { intentId: key, worker: row.worker, steps: 0, firstTs: row.ts, lastTs: row.ts, kinds: {} }
      entry.steps += 1
      entry.lastTs = Math.max(entry.lastTs, row.ts)
      entry.firstTs = Math.min(entry.firstTs, row.ts)
      entry.kinds[row.kind] = (entry.kinds[row.kind] ?? 0) + 1
      byIntent.set(key, entry)
    }
    return [...byIntent.values()]
      .sort((a, b) => b.lastTs - a.lastTs)
      .slice(0, Math.max(1, Math.min(100, Number(limit) || 20)))
  }

  /** Full content of specific steps (or all steps) of one intent — the deep dive. */
  traceSteps({ intentId, stepIds = [], limit = 50 } = {}) {
    this.load()
    const wanted = new Set((Array.isArray(stepIds) ? stepIds : [stepIds]).map((id) => String(id)).filter(Boolean))
    const rows = this.state.activity
      .filter((row) => (intentId === undefined || intentId === '' ? true : row.intentId === intentId))
      .filter((row) => (wanted.size === 0 ? true : wanted.has(row.id)))
      .sort((a, b) => a.ts - b.ts)
      .slice(0, Math.max(1, Math.min(200, Number(limit) || 50)))
    return rows.map((row) => ({
      stepId: row.id,
      intentId: row.intentId,
      worker: row.worker,
      seq: row.seq,
      kind: row.kind,
      summary: row.summary,
      detail: row.detail,
      ts: row.ts,
    }))
  }

  // ── assets (the shared truth side of the dual graph) ──────────────────────
  addAssets({ assets = [] } = {}) {
    this.load()
    if (!Array.isArray(assets) || assets.length === 0) throw new Error('pt_asset: assets must be a non-empty array')
    const allowed = ['root_domain', 'subdomain', 'ip', 'service', 'app', 'endpoint', 'credential', 'host']
    const created = []
    const merged = []
    for (const item of assets) {
      const type = String(item?.type ?? '').trim()
      const name = String(item?.name ?? '').trim()
      if (!allowed.includes(type)) throw new Error(`pt_asset: type must be one of ${allowed.join(', ')} (got ${JSON.stringify(type)})`)
      if (name === '') throw new Error('pt_asset: name must be a non-empty string')
      const existing = this.state.assets.find((asset) => asset.type === type && asset.name === name)
      const props = item?.props && typeof item.props === 'object' ? item.props : {}
      if (existing) {
        existing.props = { ...existing.props, ...props }
        existing.host = String(item?.host ?? existing.host ?? '').trim()
        existing.updatedAt = now()
        merged.push({ id: existing.id, type, name })
        continue
      }
      const row = {
        id: this.nextId('asset'),
        missionId: this.state.mission?.id ?? '',
        type,
        name,
        host: String(item?.host ?? '').trim(),
        port: item?.port === undefined ? null : Number(item.port),
        url: String(item?.url ?? '').trim(),
        props,
        parentId: item?.parentId ? String(item.parentId) : '',
        tested: false,
        createdAt: now(),
        updatedAt: now(),
      }
      // 父级由程序推断（显式 parentId 优先）：域名→子域→服务→端点的包含关系不靠 agent 记。
      if (row.parentId === '') row.parentId = this.inferParentId(row)
      this.state.assets.push(row)
      if (row.parentId !== '') this.linkEdge({ from: `asset:${row.parentId}`, rel: 'contains', to: `asset:${row.id}` })
      created.push({ id: row.id, type, name, parentId: row.parentId })
    }
    this.save()
    return { created, merged, total: this.state.assets.length }
  }

  listAssets({ q = '', type = '', tested = '', limit = 40 } = {}) {
    this.load()
    const needle = String(q ?? '').toLowerCase()
    return this.state.assets
      .filter((asset) => (type === '' ? true : asset.type === type))
      .filter((asset) => (tested === '' ? true : asset.tested === (tested === true || tested === 'true')))
      .filter((asset) => (needle === '' ? true : `${asset.type} ${asset.name} ${asset.host} ${asset.url}`.toLowerCase().includes(needle)))
      .slice(0, Math.max(1, Math.min(200, Number(limit) || 40)))
      .map((asset) => ({
        id: asset.id,
        type: asset.type,
        name: asset.name,
        host: asset.host,
        url: asset.url,
        parentId: asset.parentId,
        tested: asset.tested,
        props: asset.props,
      }))
  }

  markAsset({ id, tested = true } = {}) {
    this.load()
    const asset = this.state.assets.find((row) => row.id === id)
    if (!asset) throw new Error(`pt_asset: unknown asset ${JSON.stringify(id)}`)
    asset.tested = tested === true
    asset.updatedAt = now()
    this.save()
    return { id: asset.id, name: asset.name, tested: asset.tested }
  }

  // ── findings (confirmed only — candidates stay in their own queue) ────────
  addFinding({ assetId = '', title, severity = 'medium', evidence, chainId = '', cvss = null, intentId = '', worker = '' } = {}) {
    this.load()
    const name = String(title ?? '').trim()
    if (name === '') throw new Error('pt_finding: title must be a non-empty string')
    const levels = ['info', 'low', 'medium', 'high', 'critical']
    if (!levels.includes(severity)) throw new Error(`pt_finding: severity must be one of ${levels.join(', ')}`)
    const proof = String(evidence ?? '').trim()
    if (proof.length < 8) {
      throw new Error('pt_finding: confirmed finding 需要真实证据（命令/payload + 关键回显）；仅凭版本/模板/CVE 匹配请用 pt_candidate 登记')
    }
    if (assetId !== '' && !this.state.assets.some((asset) => asset.id === assetId)) {
      throw new Error(`pt_finding: unknown asset ${JSON.stringify(assetId)}；先 pt_asset action=add`)
    }
    const row = {
      id: this.nextId('finding'),
      missionId: this.state.mission?.id ?? '',
      assetId: String(assetId ?? ''),
      title: name,
      severity,
      state: 'confirmed',
      cvss: cvss === null || cvss === undefined ? null : Number(cvss),
      evidence: proof,
      chainId: String(chainId ?? ''),
      createdAt: now(),
      updatedAt: now(),
    }
    this.state.findings.push(row)
    if (assetId !== '') {
      const asset = this.state.assets.find((item) => item.id === assetId)
      if (asset) asset.tested = true
    }
    // 探索图：哪条意图"证出"了这条漏洞；资产图：这条漏洞落在哪台资产。
    const owner = String(intentId ?? '') || (worker === '' ? '' : this.runningIntentOf(worker)?.id ?? '')
    if (owner !== '') this.linkEdge({ from: `intent:${owner}`, rel: 'proves', to: `finding:${row.id}` })
    if (row.assetId !== '') this.anchor({ node: `finding:${row.id}`, nodeType: 'finding', assetId: row.assetId, rel: 'proves' })
    this.save()
    return row
  }

  listFindings({ state = '', severity = '', limit = 20 } = {}) {
    this.load()
    return this.state.findings
      .filter((row) => (state === '' ? true : row.state === state))
      .filter((row) => (severity === '' ? true : row.severity === severity))
      .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.createdAt - a.createdAt)
      .slice(0, Math.max(1, Math.min(200, Number(limit) || 20)))
  }

  setFindingState({ id, state, note = '' } = {}) {
    this.load()
    const row = this.state.findings.find((item) => item.id === id)
    if (!row) throw new Error(`pt_finding: unknown finding ${JSON.stringify(id)}`)
    const allowed = ['confirmed', 'fixed', 'false_positive', 'suspected']
    if (!allowed.includes(state)) throw new Error(`pt_finding: state must be one of ${allowed.join(', ')}`)
    row.state = state
    if (String(note ?? '').trim() !== '') row.evidence = `${row.evidence}\n[状态变更 ${new Date().toISOString()}] ${state}: ${String(note).trim()}`
    row.updatedAt = now()
    this.save()
    return row
  }

  missionReport() {
    this.load()
    const mission = this.missionRow()
    if (!mission) return { markdown: '# 无进行中的 mission\n\n先 `pt_mission action=start` 建立目标。', mission: null }
    const intents = this.state.intents.filter((i) => i.missionId === mission.id)
    const findings = this.state.findings.filter((f) => f.missionId === mission.id || f.missionId === '')
    const assets = this.state.assets
    const chains = this.chains()
    const tested = assets.filter((a) => a.tested).length
    const unverified = chains.flatMap((chain) => chain.steps.filter((s) => s.status === 'unverified').map((s) => `${chain.title} #${s.ord} ${s.title}`))
    const lines = []
    lines.push(`# ${mission.title || mission.goal}`)
    lines.push('')
    lines.push(`- mission: \`${mission.id}\`（${mission.state}）`)
    lines.push(`- 目标: ${mission.goal}`)
    if (mission.scope.length) lines.push(`- 范围: ${mission.scope.join(', ')}`)
    if (mission.constraints.length) lines.push(`- 约束: ${mission.constraints.join('; ')}`)
    const coverage = this.coverage()
    lines.push(`- 资产覆盖: ${coverage.tested}/${coverage.inScope} 已测（${coverage.pct}%）${coverage.outOfScope > 0 ? `；${coverage.outOfScope} 个资产不在授权范围内` : ''}`)
    lines.push(`- intent: ${intents.length} 条（done ${intents.filter((i) => i.state === 'done').length} / exhausted ${intents.filter((i) => i.state === 'exhausted').length} / blocked ${intents.filter((i) => i.state === 'blocked').length} / open ${intents.filter((i) => i.state === 'open').length}）`)
    lines.push('')
    lines.push('## 目标')
    const goals = mission.goals ?? []
    if (goals.length === 0) lines.push('（无）')
    for (const goal of goals) {
      lines.push(`- [${goal.state === 'met' ? 'x' : ' '}] ${goal.id} ${goal.text}${goal.evidence ? ` — 依据: ${goal.evidence.split('\n')[0]}` : ''}`)
    }
    const hints = this.state.hints.filter((hint) => hint.missionId === mission.id)
    if (hints.length > 0) {
      lines.push('')
      lines.push('## 人给的提示（hint）')
      for (const hint of hints) {
        lines.push(`- [${hint.state === 'addressed' ? 'x' : ' '}] ${hint.id} ${hint.text}${hint.intentIds.length ? ` → ${hint.intentIds.join(',')}` : ''}`)
      }
    }
    lines.push('')
    lines.push('## 已确认漏洞')
    if (findings.length === 0) lines.push('（无）')
    for (const finding of findings) {
      lines.push(`### [${finding.severity.toUpperCase()}] ${finding.title}`)
      lines.push(`- 状态: ${finding.state}${finding.cvss === null ? '' : ` · CVSS ${finding.cvss}`}`)
      if (finding.assetId) lines.push(`- 资产: ${finding.assetId}`)
      if (finding.chainId) lines.push(`- 链: ${finding.chainId}`)
      lines.push(`- 证据: ${finding.evidence.split('\n')[0]}`)
      lines.push('')
    }
    lines.push('## 攻击链')
    if (chains.length === 0) lines.push('（无）')
    for (const chain of chains) {
      lines.push(`- ${chain.title}: ${chain.steps.filter((s) => s.status === 'satisfied').length}/${chain.steps.length} 步已证实`)
    }
    if (unverified.length) {
      lines.push('')
      lines.push('## 未验证（force 跳过）')
      for (const item of unverified) lines.push(`- ${item}`)
    }
    lines.push('')
    lines.push('## 待办')
    const pendingCandidates = this.state.candidates.filter((c) => c.state === 'candidate' || c.state === 'verifying')
    lines.push(`- 候选漏洞待验证: ${pendingCandidates.length}`)
    lines.push(`- 带外回连: ${this.state.oobs.reduce((sum, oob) => sum + oob.hits, 0)} 次 / ${this.state.oobs.length} 个探测点`)
    const untested = assets.filter((a) => !a.tested).length
    lines.push(`- 范围内未测资产: ${untested}`)
    lines.push('')
    lines.push('## 证据索引')
    if (this.state.evidence.length === 0) lines.push('（无）')
    for (const item of this.state.evidence) {
      lines.push(`- \`${item.sha256.slice(0, 16)}…\` ${item.name} — ${item.path}`)
    }
    if (mission.evidence) {
      lines.push('')
      lines.push(`## 目标达成依据`)
      lines.push(mission.evidence)
    }
    return { markdown: lines.join('\n'), mission: this.missionView(), counts: { findings: findings.length, assets: assets.length, tested, intents: intents.length } }
  }

  // ── worker supervision (subagents / CLI processes holding intents) ────────
  /**
   * One row per worker that currently holds an intent: how far it got, how long it
   * has been quiet. A worker that dies mid-intent leaves the frontier blocked
   * forever, which is why "quiet for too long" is a first-class signal here.
   */
  workerStatus({ staleMs = 600000 } = {}) {
    this.load()
    const mission = this.missionRow()
    const ts = now()
    return this.state.intents
      .filter((intent) => (mission ? intent.missionId === mission.id : true) && intent.state === 'running')
      .map((intent) => {
        const steps = this.state.activity.filter((row) => row.intentId === intent.id)
        const lastTs = steps.reduce((max, row) => Math.max(max, row.ts), intent.claimedAt || 0)
        const idleMs = ts - Math.max(lastTs, intent.claimedAt || 0)
        return {
          worker: intent.claimedBy || 'chat',
          intentId: intent.id,
          summary: intent.summary,
          claimedAt: intent.claimedAt,
          steps: steps.length,
          lastActivityAt: lastTs || 0,
          idleMs,
          stale: idleMs > staleMs,
        }
      })
  }

  /**
   * Return a silent worker's intent to the frontier. Only `running` intents are
   * touched, and the release is logged, so nothing disappears silently.
   */
  reapStaleWorkers({ staleMs = 600000 } = {}) {
    this.load()
    const reaped = []
    for (const row of this.workerStatus({ staleMs })) {
      if (!row.stale) continue
      const intent = this.intentRow(row.intentId)
      if (!intent || intent.state !== 'running') continue
      intent.state = 'open'
      intent.claimedBy = ''
      intent.claimedAt = 0
      intent.baseline = null
      this.logActivity({
        worker: 'system',
        intentId: intent.id,
        kind: 'note',
        summary: `reaped: worker ${row.worker} 静默 ${Math.round(row.idleMs / 1000)}s，意图放回 frontier`,
      })
      reaped.push({ intentId: intent.id, worker: row.worker, idleMs: row.idleMs })
    }
    if (reaped.length > 0) this.save()
    return { reaped, open: this.state.intents.filter((i) => i.state === 'open').length }
  }

  // ── dual graph: containment edges + anchors ────────────────────────────────
  //
  // 两张图分开存、用锚点相连：
  //   资产图（全局真值）：assets + edges(contains)，父子关系由程序算；
  //   探索图（本任务推进）：intents/facts/findings + edges(yields|spawns|proves|derived_from)，
  //   靠 anchors(node → asset) 把"哪个方向打的是哪台资产"钉住。
  // 这样既能从探索方向反查资产，也能从资产反查被哪些意图测过。
  linkEdge({ from, rel, to }) {
    if (!from || !rel || !to) return null
    const exists = this.state.edges.find((edge) => edge.from === from && edge.rel === rel && edge.to === to)
    if (exists) return exists
    const edge = { from, rel, to, ts: now() }
    this.state.edges.push(edge)
    return edge
  }

  anchor({ node, nodeType, assetId, rel }) {
    if (!node || !assetId) return null
    const exists = this.state.anchors.find((row) => row.node === node && row.assetId === assetId && row.rel === rel)
    if (exists) return exists
    const row = { node, nodeType, assetId, rel, ts: now() }
    this.state.anchors.push(row)
    return row
  }

  /** 用 host 反查资产（name/host/url 任一匹配即算命中），给事实/漏洞自动挂锚点用。 */
  assetIdForHost(host) {
    const needle = String(host ?? '').trim().toLowerCase()
    if (needle === '') return ''
    let best = null
    for (const asset of this.state.assets) {
      for (const value of [asset.name, asset.host, asset.url].filter(Boolean)) {
        const candidate = String(value).toLowerCase()
        // 精确 > 后缀 > 包含，避免 "api.demo.test" 被父域 "demo.test" 抢走锚点。
        const score =
          candidate === needle ? 3
            : candidate.endsWith(`.${needle}`) || needle.endsWith(`.${candidate}`) ? 2
              : candidate.includes(needle) || needle.includes(candidate) ? 1
                : 0
        if (score === 0) continue
        if (!best || score > best.score || (score === best.score && candidate.length > best.length)) {
          best = { id: asset.id, score, length: candidate.length }
        }
      }
    }
    return best?.id ?? ''
  }

  /** 资产父子关系由程序推断（agent 只交原始信息），显式 parentId 优先。 */
  inferParentId(asset) {
    const byHost = this.state.assets.filter((row) => row.id !== asset.id && row.host && asset.host && row.host === asset.host)
    const pick = (types) => byHost.find((row) => types.includes(row.type))?.id ?? ''
    switch (asset.type) {
      case 'subdomain':
        return this.state.assets.find((row) => row.type === 'root_domain' && asset.name.endsWith(`.${row.name}`))?.id ?? ''
      case 'service':
        return pick(['app', 'host', 'ip', 'subdomain'])
      case 'endpoint':
        return pick(['app', 'service', 'host', 'subdomain'])
      case 'app':
        return pick(['service', 'host', 'subdomain', 'ip'])
      case 'host':
        return pick(['subdomain', 'ip'])
      default:
        return ''
    }
  }

  scopeMatch(asset, scopeEntry) {
    const needle = String(scopeEntry ?? '').toLowerCase().replace(/^https?:\/\//, '').replace(/\/+$/, '')
    if (needle === '') return false
    return [asset.name, asset.host, asset.url]
      .filter(Boolean)
      .map((value) => String(value).toLowerCase().replace(/^https?:\/\//, '').replace(/\/+$/, ''))
      .some((value) => value === needle || value.includes(needle) || needle.includes(value))
  }

  /** 授权范围内的资产（覆盖度与漏洞类型矩阵共用同一个分母）。 */
  inScopeAssets() {
    this.load()
    const scope = this.missionRow()?.scope ?? []
    return scope.length === 0 ? this.state.assets.slice() : this.state.assets.filter((asset) => scope.some((entry) => this.scopeMatch(asset, entry)))
  }

  /**
   * 漏洞测试类型矩阵（按资产 × 类目）：稀疏存储，未写过的格子默认 untouched。
   * 这是"不能遗漏"的可计算版本——`pt_next` 会拿 uncovered() 当收尾闸门。
   */
  markCoverage({ assetId, classId = '', cat = '', state = 'tested', note = '', intentId = '', skipResolved = false } = {}) {
    this.load()
    const asset = this.state.assets.find((row) => row.id === assetId)
    if (!asset) throw new Error(`pt_coverage: unknown asset ${JSON.stringify(assetId)}`)
    if (!COVERAGE_STATES.includes(state)) throw new Error(`pt_coverage: state must be one of ${COVERAGE_STATES.join(', ')}`)
    if (state === 'na' && String(note ?? '').trim() === '') {
      throw new Error('pt_coverage: 标 na 必须写 note 说明为什么不适用（如「该资产无上传功能」）——否则等于默认豁免')
    }
    const targets = []
    if (classId !== '') {
      const cls = CLASS_BY_ID.get(classId)
      if (!cls) throw new Error(`pt_coverage: unknown class ${JSON.stringify(classId)}；用 action=taxonomy 查可用 id`)
      if (!cls.appliesTo.includes(asset.type)) {
        throw new Error(`pt_coverage: ${classId} 不适用于 ${asset.type}（适用：${cls.appliesTo.join(', ')}）`)
      }
      targets.push(cls.id)
    } else if (cat !== '') {
      if (cat === 'all') {
        // 一次性兜底：把该资产所有适用类型按同一结论处理（收尾批量用，仍需 note）。
        for (const cls of classesFor(asset.type)) targets.push(cls.id)
      } else {
        if (!CATEGORIES[cat]) throw new Error(`pt_coverage: unknown cat ${JSON.stringify(cat)}`)
        for (const cls of classesFor(asset.type)) if (cls.cat === cat) targets.push(cls.id)
      }
    } else {
      throw new Error('pt_coverage: mark 需要 classId 或 cat（整类批量标记）')
    }
    const bucket = (this.state.coverageCells[asset.id] = this.state.coverageCells[asset.id] ?? {})
    const ts = now()
    // skipResolved：整类兜底时只填还没定论的格子，不会覆盖已经单独测过的结论。
    const effective = skipResolved ? targets.filter((id) => !['tested', 'na'].includes(bucket[id]?.state)) : targets
    for (const id of effective) bucket[id] = { state, note: String(note ?? '').trim(), intentId: String(intentId ?? ''), ts }
    if (state === 'tested' || state === 'na') asset.tested = true
    this.save()
    return { assetId: asset.id, marked: effective, state }
  }

  /** 明细矩阵：可按资产 / 类目 / 状态过滤。 */
  coverageMatrix({ assetId = '', cat = '', state = '', limit = 200 } = {}) {
    const rows = []
    for (const asset of this.inScopeAssets()) {
      if (assetId !== '' && asset.id !== assetId) continue
      const bucket = this.state.coverageCells[asset.id] ?? {}
      for (const cls of classesFor(asset.type)) {
        if (cat !== '' && cls.cat !== cat) continue
        const cell = bucket[cls.id]
        const cellState = cell?.state ?? 'untested'
        if (state !== '' && cellState !== state) continue
        rows.push({
          assetId: asset.id,
          asset: `${asset.type}:${asset.name}`,
          classId: cls.id,
          name: cls.name,
          cat: cls.cat,
          state: cellState,
          note: cell?.note ?? '',
        })
      }
    }
    return rows.slice(0, Math.max(1, Math.min(2000, Number(limit) || 200)))
  }

  /** 类目目录：给 action=taxonomy 用，把"该测什么"摊开给人看。 */
  taxonomySummary() {
    const out = {}
    for (const [id, name] of Object.entries(CATEGORIES)) out[id] = { name, classes: [] }
    for (const cls of CLASSES) {
      out[cls.cat].classes.push({ id: cls.id, name: cls.name, appliesTo: cls.appliesTo, hint: cls.hint })
    }
    return out
  }

  /** 未覆盖的格子（untested/testing），按类目顺序 → 资产顺序，直接喂给 pt_next。 */
  uncovered({ limit = 20 } = {}) {
    const order = Object.keys(CATEGORIES)
    const rows = this.coverageMatrix({}).filter((row) => row.state === 'untested' || row.state === 'testing')
    rows.sort((a, b) => order.indexOf(a.cat) - order.indexOf(b.cat) || (a.assetId < b.assetId ? -1 : 1))
    return rows.slice(0, Math.max(1, Math.min(200, Number(limit) || 20)))
  }

  /** 按类目统计：这是给人看"哪一类还没测"的报表。 */
  coverageStats() {
    const stats = {}
    let total = 0
    let tested = 0
    let na = 0
    for (const row of this.coverageMatrix({ limit: 5000 })) {
      const bucket = (stats[row.cat] = stats[row.cat] ?? { total: 0, tested: 0, na: 0, untested: 0 })
      bucket.total += 1
      total += 1
      if (row.state === 'tested') {
        bucket.tested += 1
        tested += 1
      } else if (row.state === 'na') {
        bucket.na += 1
        na += 1
      } else {
        bucket.untested += 1
      }
    }
    const denominator = total - na
    return {
      cells: total,
      tested,
      na,
      untested: total - tested - na,
      pct: denominator <= 0 ? 100 : Math.round((tested / denominator) * 100),
      byCategory: stats,
    }
  }

  /** 覆盖度：分母是"授权范围内的资产"，分子是已测（含被漏洞/事实锚定过的）。 */
  coverage() {
    this.load()
    const mission = this.missionRow()
    const scope = mission?.scope ?? []
    const anchored = new Set(this.state.anchors.map((row) => row.assetId))
    const inScope = scope.length === 0 ? this.state.assets : this.state.assets.filter((asset) => scope.some((entry) => this.scopeMatch(asset, entry)))
    const isTested = (asset) => asset.tested || anchored.has(asset.id)
    const tested = inScope.filter(isTested)
    return {
      scope: scope.length,
      inScope: inScope.length,
      tested: tested.length,
      pct: inScope.length === 0 ? 0 : Math.round((tested.length / inScope.length) * 100),
      untested: inScope.filter((asset) => !isTested(asset)).map((asset) => ({ id: asset.id, type: asset.type, name: asset.name })),
      outOfScope: this.state.assets.length - inScope.length,
      byType: inScope.reduce((acc, asset) => {
        acc[asset.type] = acc[asset.type] ?? { total: 0, tested: 0 }
        acc[asset.type].total += 1
        if (isTested(asset)) acc[asset.type].tested += 1
        return acc
      }, {}),
    }
  }

  /** 图查询：节点/边/锚点/覆盖，或绕某个资产/节点看血缘。 */
  graphView({ assetId = '', node = '', limit = 50 } = {}) {
    this.load()
    const cap = Math.max(1, Math.min(500, Number(limit) || 50))
    const nodes = {
      intent: this.state.intents.length,
      fact: this.state.facts.length,
      finding: this.state.findings.length,
      asset: this.state.assets.length,
    }
    const view = {
      nodes,
      edges: this.state.edges.length,
      anchors: this.state.anchors.length,
      coverage: this.coverage(),
    }
    if (node !== '') {
      view.around = {
        node,
        out: this.state.edges.filter((edge) => edge.from === node).slice(0, cap),
        in: this.state.edges.filter((edge) => edge.to === node).slice(0, cap),
        anchors: this.state.anchors.filter((row) => row.node === node).slice(0, cap),
      }
    }
    if (assetId !== '') {
      const rows = this.state.anchors.filter((row) => row.assetId === assetId)
      view.asset = {
        id: assetId,
        anchoredNodes: rows.map((row) => ({ node: row.node, nodeType: row.nodeType, rel: row.rel })),
        children: this.state.edges.filter((edge) => edge.from === `asset:${assetId}` && edge.rel === 'contains').map((edge) => edge.to),
        parent: this.state.edges.find((edge) => edge.to === `asset:${assetId}` && edge.rel === 'contains')?.from ?? '',
      }
    }
    if (arguments[0]?.all) {
      view.edgeList = this.state.edges.slice(-cap)
      view.anchorList = this.state.anchors.slice(-cap)
    }
    return view
  }

  // ── summary ────────────────────────────────────────────────────────────────
  summary() {
    this.load()
    const chains = this.chains()
    const ready = []
    for (const chain of chains) {
      for (const step of chain.steps) {
        if (step.status === 'ready') ready.push({ chainId: chain.id, ord: step.ord, title: step.title })
      }
    }
    return {
      dataDir: this.paths.root,
      mission: this.missionView(),
      counts: {
        chains: chains.length,
        facts: this.state.facts.length,
        oobs: this.state.oobs.length,
        oobHits: this.state.oobs.reduce((sum, o) => sum + o.hits, 0),
        creds: this.state.creds.length,
        defense: this.state.defense.length,
        candidates: this.state.candidates.length,
        openCandidates: this.state.candidates.filter((c) => c.state === 'candidate' || c.state === 'verifying').length,
        evidence: this.state.evidence.length,
        intents: this.state.intents.length,
        openIntents: this.state.intents.filter((i) => i.state === 'open').length,
        assets: this.state.assets.length,
        untestedAssets: this.coverage().untested.length,
        findings: this.state.findings.length,
        edges: this.state.edges.length,
        anchors: this.state.anchors.length,
        coveragePct: this.coverage().pct,
        steps: this.state.activity.length,
        workers: [...new Set(this.state.activity.map((row) => row.worker))].length,
        hints: this.state.hints.length,
        openHints: this.openHints().length,
        goals: this.goalsSummary().total,
        goalsMet: this.goalsSummary().met,
        classesUntested: this.coverageStats().untested,
        classCoveragePct: this.coverageStats().pct,
      },
      goals: this.listGoals(),
      openHints: this.openHints(),
      coverage: this.coverage(),
      readySteps: ready,
      intents: this.listIntents({ limit: 10 }),
      chainDetails: chains,
      assets: this.listAssets({ limit: 20 }),
      findings: this.listFindings({ limit: 20 }),
      facts: this.listFacts({ limit: 10 }),
      oobs: this.state.oobs.slice(-5).map((o) => ({ id: o.id, kind: o.kind, hits: o.hits, url: o.url, note: o.note })),
      creds: this.listCreds(),
      defense: this.listDefense(),
      candidates: this.listCandidates({ limit: 20 }),
    }
  }
}

export function newToken() {
  return randomBytes(12).toString('hex')
}
