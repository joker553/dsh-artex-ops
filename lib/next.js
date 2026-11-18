// Deterministic "what should happen next" digest.
//
// ARTEX's planner is an LLM that reads the graph and emits intents. That works, but
// it is also the part that most often drifts: it re-dispatches covered directions,
// front-loads a serial chain, or concludes the task while coverage is 40%. Here the
// same judgement is a pure function over the store — the model is left with what it
// is actually good at (generating directions and executing them), and the loop
// cannot silently stall or skip a gate.
export function nextActions({ store }) {
  const mission = store.missionView()
  const phase = store.phaseOf()
  const counts = store.summary().counts
  const chains = store.chains()
  const readySteps = chains.flatMap((chain) =>
    chain.steps.filter((step) => step.status === 'ready').map((step) => ({ chainId: chain.id, ord: step.ord, title: step.title, post: step.post })),
  )
  const running = store.listIntents({ state: 'running', limit: 5 })
  // 多 worker：谁在做什么、已经留下多少过程步骤。过程步骤少而时间长，通常意味着
  // 这个 worker 在"想"而不是在"试"——这是唯一能从外部观察到的卡顿信号。
  const workers = running.map((intent) => ({
    worker: intent.claimedBy || 'chat',
    intentId: intent.id,
    summary: intent.summary,
    steps: store.traceSteps({ intentId: intent.id, limit: 200 }).length,
  }))
  const open = store.listIntents({ state: 'open', limit: 10 })
  const untested = store.listAssets({ tested: false, limit: 10 })
  // 覆盖度以「授权范围内的资产」为分母；锚定过事实/漏洞的资产算已测（coverage 里判定）。
  const coverage = store.coverage()
  const untestedInScope = store
    .listAssets({ limit: 200 })
    .filter((asset) => coverage.untested.some((row) => row.id === asset.id))
    .slice(0, 10)
  const pendingCandidates = store.listCandidates({ state: 'candidate', limit: 10 }).concat(store.listCandidates({ state: 'verifying', limit: 10 }))
  const hits = store.oobs().filter((oob) => oob.hits > 0)
  const freshHits = hits.filter((oob) => !store.hasFact(`oob-hit:${oob.id}`))
  const actions = []
  const push = (action) => actions.push(action)

  if (!mission) {
    return {
      decision: 'bootstrap',
      stalled: true,
      reasons: ['还没有 mission：ARTEX 的闭环要先有「目标 + 范围」，否则探索没有验收基准'],
      actions: [
        {
          tool: 'pt_mission',
          args: { action: 'start', goal: '<一句话目标>', scope: ['<域名/IP/CIDR>'], constraints: ['<不许做的操作>'] },
          why: '建立 mission 后再派意图；范围与约束会进入后续每次决策',
        },
      ],
      counts,
    }
  }

  if (mission.state === 'done' || mission.state === 'stopped') {
    return {
      decision: 'report',
      stalled: false,
      reasons: [`mission 已 ${mission.state}`],
      actions: [{ tool: 'pt_mission', args: { action: 'report' }, why: '出报告：漏洞、链路、覆盖、证据索引' }],
      counts,
    }
  }

  const reasons = []
  if (phase !== 'sweep' && phase !== 'report') {
    reasons.push(
      '当前阶段 ' +
        phase +
        '：' +
        (phase === 'recon'
          ? '先挖面（pt_recon / 浏览器 / 目录扫描），不要急着试 payload'
          : '只做链上的 ready 步骤与候选复验'),
    )
  }
  if (workers.length > 1) {
    reasons.push(
      `${workers.length} 个 worker 并行：${workers.map((w) => `${w.worker}→${w.intentId}(${w.steps} 步)`).join('、')}——跨 worker 的观察用 pt_trace search（排除自己的意图）取，不要重复别人已经试过的路子`,
    )
  }
  if (running.length > 0) {
    reasons.push(`有 ${running.length} 条 intent 正在执行（#${running.map((i) => i.id).join(', #')}）：一个 worker 同时只做一条，先把这条收口再领下一条`)
    push({
      tool: 'pt_intent',
      args: { action: 'done', id: running[0].id, state: 'done', output: '<一句话结论>' },
      why: '收口会按 baseline 统计写回量；writes 全 0 说明观察只留在对话里，没有进库',
    })
  }
  if (readySteps.length > 0) {
    reasons.push(`有 ${readySteps.length} 个攻击链步骤前置已满足：${readySteps.map((s) => `${s.chainId}#${s.ord}`).join(', ')}`)
    for (const step of readySteps.slice(0, 3)) {
      push({
        tool: 'pt_chain_advance',
        args: { chainId: step.chainId, ord: step.ord, evidence: '<命令/payload + 关键回显>' },
        why: `做完「${step.title}」后推进；post 断言不成立会被拒绝（${step.post.join(' / ') || '无后置断言'}）`,
      })
    }
  }
  if (open.length > 0) {
    reasons.push(`frontier 有 ${open.length} 条待执行意图：领一条、只做它`)
    push({ tool: 'pt_intent', args: { action: 'claim' }, why: '原子领取下一条（按 priority，再按创建顺序）' })
  }
  if (pendingCandidates.length > 0) {
    reasons.push(`${pendingCandidates.length} 条候选漏洞待定论：模板/CVE 命中不算漏洞，必须真触发`)
    for (const candidate of pendingCandidates.slice(0, 3)) {
      push({
        tool: 'pt_candidate',
        args: { action: 'verdict', id: candidate.id, verdict: 'confirmed', evidence: '<命令/payload + 关键回显>', oobId: '<有回连的探测点>' },
        why: `${candidate.title}（${candidate.source}）——没有证据只能 refuted 或保持 candidate`,
      })
    }
  }
  if (hits.length > 0) {
    if (freshHits.length > 0) {
      reasons.push(`${freshHits.length} 个带外探测点有回连但还没登记事实：${freshHits.map((o) => o.id).join(', ')}`)
      for (const oob of freshHits.slice(0, 3)) {
        push({
          tool: 'pt_fact_add',
          args: { label: `oob-hit:${oob.id}`, summary: `<哪个参数/请求触发了回连>`, confidence: 'observed', evidence: `<触发请求 + 回连时间>` },
          why: '回连是 observed 级证据；登记后才能作链断言 oob:<id>',
        })
      }
    } else {
      // 已登记过的回连只作为态势信息，不再驱动 decision（否则会永远停在 verify）
      reasons.push(`带外探测点已有回连且已登记事实（${hits.map((o) => o.id).join(', ')}）`)
    }
  }
  if (untestedInScope.length > 0 && open.length === 0 && running.length === 0) {
    reasons.push(
      `范围内还有 ${coverage.untested.length} 个未测资产（覆盖 ${coverage.tested}/${coverage.inScope} = ${coverage.pct}%；示例：${untestedInScope
        .slice(0, 3)
        .map((asset) => `${asset.type}:${asset.name}`)
        .join(', ')}）`,
    )
    push({
      tool: 'pt_intent',
      args: { action: 'add', summaries: untestedInScope.slice(0, 3).map((asset) => `测 ${asset.type} ${asset.name} 的已知攻击面并落事实`) },
      why: '覆盖度是验收下限：没有在跑的意图时必须补方向，否则任务停摆',
    })
  }

  const goals = store.listGoals()
  const unmetGoals = goals.filter((goal) => goal.state !== 'met')
  const hintsOpen = store.openHints()
  // 类型覆盖：只要范围内还有「资产 × 漏洞类型」格子没测，就不算覆盖到位。
  const classStats = store.coverageStats()
  const uncoveredAll = store.uncovered({ limit: 200 })
  // 阶段过滤：recon 阶段只推 recon 类目；sweep 阶段推其余类目；deepdive 阶段不推覆盖动作。
  const phasePool = phase === 'recon'
    ? uncoveredAll.filter((cell) => cell.cat === 'recon')
    : phase === 'sweep'
      ? uncoveredAll.filter((cell) => cell.cat !== 'recon')
      : []
  // 先按阶段筛完再截断，否则 recon 的格子会把名额占满、sweep 阶段看不到活。
  const uncovered = phasePool.slice(0, 8)

  if (uncovered.length > 0) {
    const byCat = {}
    for (const cell of uncovered) byCat[cell.cat] = (byCat[cell.cat] ?? 0) + 1
    reasons.push(
      `漏洞类型覆盖 ${classStats.pct}%（${classStats.tested}/${classStats.cells - classStats.na}；剩 ${classStats.untested} 格未测）：${Object.entries(byCat)
        .map(([cat, n]) => `${cat}×${n}`)
        .join('、')}`,
    )
    const first = uncovered[0]
    push({
      tool: 'pt_coverage',
      args: { action: 'mark', assetId: first.assetId, classId: first.classId, state: 'tested', note: '<依据：请求/回显或"确认不存在">' },
      why: `下一个该测：${first.asset} × ${first.name}（@${first.cat}）——按这个类目补，不要把同一种打法重复第五遍`,
    })
    push({ tool: 'pt_coverage', args: { action: 'next', limit: 10 }, why: '批量领取下一批未覆盖格子，按类目优先级排过序' })
  }

  for (const hint of hintsOpen.slice(0, 2)) {
    reasons.push(`人给的提示还没被任何意图接手：${hint.text}`)
    push({
      tool: 'pt_intent',
      args: { action: 'add', summaries: [`围绕提示「${hint.text}」给出具体可执行方向`], hintIds: [hint.id] },
      why: 'hint 是人给的方向；接它时带 hintIds，hint 会离开 open 集并可反查到执行',
    })
  }
  for (const goal of unmetGoals.slice(0, 2)) {
    reasons.push(`目标未达成：${goal.id} ${goal.text}`)
    push({
      tool: 'pt_goal',
      args: { action: 'prove', id: goal.id, evidence: '<达成依据：权限/数据/回连 + 证据文件>' },
      why: '目标要逐个 prove；还有未达成目标时 pt_mission prove 会被拒绝',
    })
  }

  let decision
  if (actions.length === 0 && (unmetGoals.length > 0 || hintsOpen.length > 0 || uncovered.length > 0)) {
    // 还有人的方向没接手、目标没达成、或漏洞类型没覆盖完：不能收敛，只能补方向。
    decision = 'plan'
    reasons.push(
      `没有 ready 步骤/待执行意图/未测资产，但${unmetGoals.length > 0 ? ` 还有 ${unmetGoals.length} 个目标未达成` : ''}${unmetGoals.length > 0 && hintsOpen.length > 0 ? '、' : ''}${hintsOpen.length > 0 ? ` 有 ${hintsOpen.length} 条提示未接手` : ''}${uncovered.length > 0 ? ` 还有 ${classStats.untested} 个类型格子未测` : ''}——补一条与既有意图实质不同的新方向`,
    )
    push({
      tool: 'pt_intent',
      args: { action: 'add', summaries: ['<一条与图中既有意图实质不同的新方向>'] },
      why: '目标未达成时不能收尾；换机理而不是换措辞',
    })
  } else if (actions.length === 0) {
    // Nothing ready: the honest options are "prove with what you have" or "open a new
    // direction". Both are stated instead of silently idling.
    decision = 'converge'
    reasons.push('没有 ready 步骤、没有待执行意图、没有未测资产、没有待定候选、目标全部达成——可以收尾，也可以补一条全新方向')
    push({
      tool: 'pt_mission',
      args: { action: 'prove', evidence: '<达成依据：拿到的权限/数据/回连 + 证据文件>' },
      why: '目标真的达成才 prove；有未收口 intent 或未达成目标时会被拒绝',
    })
    push({
      tool: 'pt_intent',
      args: { action: 'add', summaries: ['<一条与图中既有意图实质不同的新方向>'] },
      why: '还没达成但已知方向都探尽时，补一条新机理的方向（不是换措辞重派）',
    })
  } else if (running.length > 0) {
    decision = 'execute'
  } else if (readySteps.length > 0) {
    decision = 'execute'
  } else if (open.length > 0) {
    decision = 'execute'
  } else if (pendingCandidates.length > 0 || freshHits.length > 0) {
    decision = 'verify'
  } else {
    decision = 'plan'
  }

  return {
    decision,
    stalled: actions.length === 0,
    phase,
    mission: { id: mission.id, goal: mission.goal, state: mission.state, phase },
    reasons,
    actions,
    workers,
    coverage: { inScope: coverage.inScope, tested: coverage.tested, pct: coverage.pct, untested: coverage.untested.length },
    classCoverage: { cells: classStats.cells, tested: classStats.tested, na: classStats.na, untested: classStats.untested, pct: classStats.pct },
    gates: {
      runningIntent: running.length,
      openIntents: open.length,
      readySteps: readySteps.length,
      untestedAssets: counts.untestedAssets,
      openHints: hintsOpen.length,
      goalsOpen: unmetGoals.length,
      goalsTotal: goals.length,
      pendingCandidates: pendingCandidates.length,
      oobProbesWithHits: hits.length,
      chains: chains.length,
      findings: counts.findings,
    },
    counts,
  }
}
