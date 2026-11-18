// Chain assertion evaluation.
//
// A chain step's `pre`/`post` lists are machine-checked predicates, not prose.
// The grammar is deliberately tiny because the point is a contract the plugin
// can verify on its own, without asking a model to grade itself:
//
//   fact:<label>                     a fact with exactly this label was recorded
//   oob:<id|token>                   that out-of-band probe received ≥1 callback
//   cred:<host>                      a credential exists for that host
//   defense:<host>                   a defense profile exists for that host
//   candidate:<id>:confirmed         that candidate reached state=confirmed
//
// Prefix any predicate with `!` to require its absence (e.g. `!cred:h1` before
// the credential-theft step is solved).
const GRAMMAR = /^!?(fact|oob|cred|defense|candidate):.+$/

export function stepOf(chain, ord) {
  return chain.steps.find((step) => step.ord === Number(ord))
}

function checkOne(store, expr) {
  const raw = String(expr ?? '').trim()
  if (!GRAMMAR.test(raw)) {
    return { expr: raw, ok: false, why: '断言语法不支持（应为 fact:/oob:/cred:/defense:/candidate:）' }
  }
  const negated = raw.startsWith('!')
  const body = negated ? raw.slice(1) : raw
  const [kind, ...rest] = body.split(':')
  const arg = rest.join(':')
  let present = false
  let why = ''
  switch (kind) {
    case 'fact': {
      present = store.hasFact(arg)
      why = present ? `事实 ${arg} 已登记` : `缺少事实 ${arg}`
      break
    }
    case 'oob': {
      const shot = store.oobShot(arg)
      if (!shot) {
        present = false
        why = `探测点 ${arg} 不存在`
      } else {
        present = shot.hits > 0
        why = present ? `探测点 ${arg} 收到 ${shot.hits} 次回连` : `探测点 ${arg} 尚无回连`
      }
      break
    }
    case 'cred': {
      present = store.hasCred(arg)
      why = present ? `已有 ${arg} 的凭据` : `尚无 ${arg} 的凭据`
      break
    }
    case 'defense': {
      present = store.hasDefense(arg)
      why = present ? `已有 ${arg} 的防护画像` : `尚无 ${arg} 的防护画像`
      break
    }
    case 'candidate': {
      const [id, state] = arg.split(':')
      const row = store.candidate(id)
      if (!row) {
        present = false
        why = `候选 ${id} 不存在`
      } else {
        present = state === undefined ? row.state === 'confirmed' : row.state === state
        why = present ? `候选 ${id} 状态为 ${row.state}` : `候选 ${id} 状态为 ${row.state}，期望 ${state ?? 'confirmed'}`
      }
      break
    }
    default:
      present = false
      why = `未知断言类型 ${kind}`
  }
  const ok = negated ? !present : present
  return { expr: raw, ok, why: negated ? `${ok ? '满足' : '违反'}否定条件（${why}）` : why }
}

/** Evaluate every predicate; `ok` only when all of them hold. */
export function evalAssertions(store, list) {
  const items = (Array.isArray(list) ? list : []).map((expr) => checkOne(store, expr))
  const missing = items.filter((item) => !item.ok).map((item) => item.expr)
  return {
    ok: missing.length === 0,
    missing,
    detail: items.map((item) => ({ expr: item.expr, ok: item.ok, why: item.why })),
  }
}

/** Recompute locked/ready for every step that is not already resolved. */
export function recomputeChain(store, chain) {
  if (!chain || !Array.isArray(chain.steps)) return chain
  for (const step of chain.steps) {
    // Resolved steps keep their verdict; an attempted step stays `running` so the
    // transcript distinguishes "not started" from "tried, evidence still missing".
    if (step.status === 'satisfied' || step.status === 'unverified' || step.status === 'running') continue
    const verdict = evalAssertions(store, step.pre)
    step.status = verdict.ok ? 'ready' : 'locked'
  }
  return chain
}
