// Tool surface for dsh-artex-ops.
//
// Definitions are plain objects (raw JSON Schema parameters + output) so the
// package needs no import from the harness's own packages: any Cordis host with
// `ctx.tools` can register them, and the file resolves from a symlinked profile
// directory without walking into the runtime's node_modules.
import { newToken } from './store.js'
import { oobPayloads, bypassVariants, PAYLOAD_FAMILIES, MATRIX_FAMILIES } from './payloads.js'
import { nextActions } from './next.js'
import { discover } from './discover.js'

const ANY_OBJECT = { type: 'object', additionalProperties: true }

const str = (description) => ({ type: 'string', description })
const int = (description) => ({ type: 'integer', description })
const bool = (description) => ({ type: 'boolean', description })
const strList = (description) => ({ type: 'array', items: { type: 'string' }, description })

function jsonRender(headline) {
  return (_args, value) => [{ type: 'text', text: `${headline}\n${JSON.stringify(value, null, 2)}` }]
}

/**
 * Tool results are validated as lossless JSON by the harness, so `undefined`
 * (an absent optional field) must never reach it. A JSON round-trip drops absent
 * keys and leaves everything else byte-identical.
 */
function lossless(value) {
  if (value === undefined) return null
  return JSON.parse(JSON.stringify(value))
}

/**
 * Append one process step for a write a worker just made.
 *
 * Only runs when the caller identifies itself (`worker`): attribution is what makes
 * the trail useful to someone else, and an unattributed step is noise. The step
 * carries the intent, so `pt_trace search --exclude-intent` can hide a worker's own
 * trail while still surfacing everyone else's.
 */
function processLog(store, args, kind, summary, detail = '') {
  const worker = typeof args?.worker === 'string' ? args.worker.trim() : ''
  if (worker === '') return null
  const intentId = String(args?.intentId ?? store.runningIntentOf(worker)?.id ?? '')
  try {
    return store.logActivity({ worker, intentId, kind, summary, detail: detail || String(args?.detail ?? '') })
  } catch {
    return null
  }
}

function sleep(ms, signal) {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve()
    const timer = setTimeout(resolve, ms)
    signal?.addEventListener?.('abort', () => {
      clearTimeout(timer)
      resolve()
    }, { once: true })
  })
}

/**
 * Build every tool definition.
 * @param {{store: import('./store.js').Store, oob: import('./oob.js').OobServer, config: object}} deps
 */
/**
 * 每个阶段给 worker 的「合同」：准入条件、方法、产出、退出。
 * 没有合同，worker 会漂成"逛一圈、写两条 fact、done"。
 */
function workerContract(phase, cat, worker) {
  const p = String(phase ?? 'recon').trim()
  if (p === 'recon') {
    return [
      '## 本阶段合同：recon（挖面，不打洞）',
      '1. `pt_recon action=save url=<入口>` —— 静态抓 HTML/JS bundle，接口/参数/功能点进资产图；跨域 bundle 用 `js=[...]`',
      '2. 浏览器驱动页面（登录、点菜单、翻页），从 network 里把观测到的 XHR 用 `pt_asset action=add` 登记',
      '3. 目录/子域探测（ffuf / subfinder 等）结果同样 `pt_asset action=add`',
      '4. `pt_coverage action=mark assetId=<app资产> cat=recon state=tested note="采集 N 接口 / M 参数 / K 功能点"`',
      '5. **不要判漏洞、不要试 payload**；看到可疑点写 `pt_trace kind=probe`，交给下一阶段',
      `退出：\`pt_intent done ... output="新增 X 端点 / Y 参数 / Z 功能点"\``,
    ].join('\n')
  }
  if (p === 'sweep') {
    return [
      `## 本阶段合同：sweep / ${cat || '<cat>'}（按类目横扫，逐格定论）`,
      `1. \`pt_coverage action=next cat=${cat || '<cat>'} limit=40\` —— 拿到格子清单（资产 × 类型）`,
      '2. 逐格测：该类目最小判据写在 taxonomy 的 hint 里（`pt_coverage action=taxonomy` 可查）',
      '3. 每格 `pt_coverage action=mark assetId=… classId=… state=tested|na note=<依据>`；**na 必须写"为什么不存在该面"**',
      '4. 有洞 → `pt_candidate action=add`（**不要 finding**，确认由调度者复验后做），原始请求/响应用 `pt_evidence_save` 落盘',
      '5. 先用 1 个代表端点确认该类目是否适用；整类不适用就批量 na（带同一理由），别逐格重复劳动',
      `退出：\`pt_intent done ... output="${cat || '<cat>'}: tested X / na Y / candidate Z"\``,
    ].join('\n')
  }
  if (p === 'deepdive') {
    return [
      '## 本阶段合同：deepdive（串行利用链，一步一证）',
      '1. `pt_chain_plan` 把链记成步骤（每步 pre/post 断言），**不要**一次并行前置展开',
      '2. 只做 ready 的那一步；盲漏洞先 `pt_oob_new` → `pt_oob_payload` → 触发 → `pt_oob_poll`',
      '3. 每步完成 `pt_chain_advance`；post 断言不成立就补证据，别用 force 假装通过',
      '4. 拿到凭据 `pt_cred action=add`；确认漏洞 `pt_candidate`（finding 由调度者复验后登记）',
      `退出：\`pt_intent done ... output="链 <id> 推进到第 N 步 / 卡在 <missing>"\``,
    ].join('\n')
  }
  if (p === 'verify') {
    return [
      '## 本阶段合同：verify（独立复验，不改结论级别以外的东西）',
      '1. `pt_candidate action=list state=verifying`（没有就看 state=candidate）挑一条',
      '2. 用与候选描述**不同**的路径/命令重新触发（换方法、换编码、换参数位置、换身份）',
      '3. 写回：`pt_candidate action=verdict id=… verdict=confirmed|refuted evidence=<命令+回显>`',
      `退出：\`pt_intent done ... output="cand-<id> → confirmed|refuted"\``,
    ].join('\n')
  }
  return `## 本阶段合同：${p}（自定义阶段，按 pt_next 的 actions 执行）`
}

export function buildTools({ store, oob, config }) {
  const dnsDomain = typeof config?.oob?.dnsDomain === 'string' ? config.oob.dnsDomain.trim().replace(/^\.+|\.+$/g, '') : ''

  const ptState = {
    name: 'pt_state',
    description:
      '读取本机 ARTEX ops 层的全局态势（唯一入口）：攻击链与其 ready 步骤、事实板、带外探测点与回连数、凭据、防护画像、候选漏洞队列、监听状态。每轮规划或长任务恢复后先调它，不要凭记忆推断链路进度。',
    parameters: {
      type: 'object',
      properties: {
        factsLimit: int('事实板返回条数，默认 10'),
      },
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('ARTEX ops 态势：') },
    async execute(args = {}) {
      const summary = store.summary()
      if (args.factsLimit !== undefined) {
        summary.facts = store.listFacts({ limit: Number(args.factsLimit) || 10 })
      }
      return { ...summary, oob: oob.info(), families: { payloads: PAYLOAD_FAMILIES, matrix: MATRIX_FAMILIES } }
    },
  }

  const ptChainPlan = {
    name: 'pt_chain_plan',
    description:
      '建立/重写一条「结构化攻击链」：steps 是有序步骤，每步可带前置 pre 与后置 post 断言。断言语法：fact:<label>、oob:<id>、cred:<host>、defense:<host>、candidate:<id>:confirmed，前缀 ! 表示要求不存在。链一旦建立，只有 pre 全部成立的步骤才是 ready——串行利用链（注入点→取凭据→横向→提权）请逐步推进，不要一次并行前置展开。同名步骤重规划时保留已完成状态。',
    parameters: {
      type: 'object',
      properties: {
        title: str('链标题，如「example.com 从上传到 RCE」'),
        chainId: str('可选：重写已有链时传其 id（保留已完成步骤）'),
        host: str('可选：该链的主目标（域名/IP）'),
        steps: {
          type: 'array',
          description: '有序步骤，最多 24 条',
          items: {
            type: 'object',
            properties: {
              title: str('步骤标题（一句话，动词开头）'),
              pre: strList('前置断言：全部成立该步才 ready'),
              post: strList('后置断言：pt_chain_advance 校验它，不成立不会推进'),
            },
            required: ['title'],
            additionalProperties: false,
          },
        },
      },
      required: ['title', 'steps'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('攻击链已保存：') },
    async execute(args = {}) {
      return store.planChain(args)
    },
  }

  const ptChainAdvance = {
    name: 'pt_chain_advance',
    description:
      '推进攻击链的下一步：只对 ready 的步骤（或显式 ord）生效。它会重新校验该步的 post 断言——事实没登记、探测点没有回连、凭据没落库时返回 ok=false 与 missing 列表，并把该步标为 running（不推进）。真的走不通要跳过时显式传 force=true，该步记为 unverified（不伪装成已证实）。',
    parameters: {
      type: 'object',
      properties: {
        chainId: str('链 id'),
        ord: int('可选：步骤序号（1 起）；省略则取第一个 ready 步骤'),
        evidence: str('本次推进的证据摘要（命令/请求 + 关键回显）'),
        force: bool('无证据跳过（记为 unverified），默认 false'),
        worker: str('可选：worker 标识；给了就会记一条过程 step'),
        intentId: str('可选：归属意图 id'),
      },
      required: ['chainId'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('推进结果：') },
    async execute(args = {}) {
      const result = store.advanceChain(args)
      const chain = store.chain(args.chainId)
      processLog(
        store,
        args,
        result.ok ? 'note' : 'dead-end',
        `chain ${args.chainId}#${result.ord}: ${result.ok ? result.status : `blocked, missing=${(result.missing ?? []).join(',')}`}`,
        String(args.evidence ?? ''),
      )
      return { ...result, chain: chain ? store.chainView(chain) : undefined }
    },
  }

  const ptFactAdd = {
    name: 'pt_fact_add',
    description:
      '把一条真实观察登记进事实板（链断言与后续判断都以此为准）。只写增量、只写看到的：evidence 写「命令/请求 + 最能证明的一两行输出」，confidence 用 observed（直接看到）或 inferred（据现象推断）。同一 label 重复登记会合并为一行。',
    parameters: {
      type: 'object',
      properties: {
        label: str('稳定短标签，如 upload-endpoint-reachable、waf-cloudflare-on-h1'),
        summary: str('一句话结论'),
        host: str('可选：所属主机（域名/IP）'),
        confidence: { type: 'string', enum: ['observed', 'inferred'], description: 'observed=直接看到 / inferred=推断' },
        evidence: str('证据：命令或请求 + 关键输出行'),
        worker: str('可选：写这条事实的 worker 标识；给了就会自动记一条过程 step'),
        intentId: str('可选：归属意图 id（省略时取该 worker 当前 running 的意图）'),
      },
      required: ['label', 'summary'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('事实已登记：') },
    async execute(args = {}) {
      const row = store.addFact(args)
      const step = processLog(store, args, 'fact', `fact: ${row.label} — ${row.summary}`, args.evidence ?? '')
      return step ? { ...row, stepId: step.id } : row
    },
  }

  const ptFactList = {
    name: 'pt_fact_list',
    description: '按关键字/主机检索事实板（最新在前），用于回看已确认的观察，避免重复登记。',
    parameters: {
      type: 'object',
      properties: {
        q: str('可选：关键字（匹配 label/summary/evidence）'),
        host: str('可选：限定主机'),
        limit: int('返回条数，默认 20'),
      },
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('事实列表：') },
    async execute(args = {}) {
      return { facts: store.listFacts(args) }
    },
  }

  const ptOobNew = {
    name: 'pt_oob_new',
    description:
      '申请一个带外（OAST）探测点并启动本地监听：返回唯一 token、HTTP 探测 URL 与 DNS 名。盲 SSRF/盲 RCE/XXE/盲 SQLi/JNDI 这类「没回显」的漏洞必须先拿到探测点再发 payload，回连才是 observed 级证据。注意：URL 中的 host 是本机/公网地址，目标必须能回连到它；公网不可达时先在配置里设 oob.publicHost（或端口映射/隧道）。',
    parameters: {
      type: 'object',
      properties: {
        kind: { type: 'string', enum: ['http', 'dns'], description: '探测类型：http=HTTP 回连，dns=仅 DNS 解析回连' },
        note: str('可选：这条探测点的用途备注（便于回连时辨认）'),
      },
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('带外探测点：') },
    async execute(args = {}) {
      const info = await oob.ensure()
      const token = newToken()
      const kind = args.kind === 'dns' ? 'dns' : 'http'
      const baseUrl = info.baseUrl
      if (baseUrl === '') throw new Error('pt_oob_new: 监听未就绪，无法生成探测点')
      const url = `${baseUrl}/${token}`
      const dnsName = dnsDomain !== '' ? `${token}.${dnsDomain}` : `${token}.oob.local`
      const row = store.addOob({ token, kind, note: args.note ?? '', url, dnsName })
      return {
        id: row.id,
        token,
        kind,
        url,
        dnsName,
        listener: info,
        hint:
          kind === 'dns'
            ? 'dns 类型只认 DNS 解析回连：需要 oob.dns.enabled 或公网 DNS 指向本机，否则用 http 类型'
            : '发送 payload 后用 pt_oob_poll 拉回连；命中会自动给该探测点 +1 并可作为链断言 oob:<id>',
      }
    },
  }

  const ptOobPoll = {
    name: 'pt_oob_poll',
    description:
      '拉取带外回连记录（可按探测点 id/token 过滤，可短等）。返回每次回连的协议、路径、来源地址、头部与正文片段——这就是盲漏洞的真实证据，命中后可 pt_fact_add 登记并以 oob:<id> 作为链断言。',
    parameters: {
      type: 'object',
      properties: {
        id: str('可选：探测点 id 或 token；省略则返回全局最近回连'),
        since: int('可选：只返回该毫秒时间戳之后的回连'),
        waitMs: int('可选：等待回连的毫秒数（上限 10000），用于触发后立即确认'),
        limit: int('返回条数，默认 20'),
      },
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('带外回连：') },
    async execute(args = {}, exec) {
      const wait = Math.max(0, Math.min(10000, Number(args.waitMs) || 0))
      if (wait > 0) await sleep(wait, exec?.signal)
      const info = oob.info()
      const hits = oob.poll({ id: args.id ?? '', since: Number(args.since) || 0, limit: args.limit })
      const shot = args.id !== undefined && args.id !== '' ? store.oobShot(args.id) : undefined
      return {
        listener: info,
        probe: shot ? { id: shot.id, token: shot.token, hits: shot.hits, url: shot.url, dnsName: shot.dnsName, note: shot.note } : undefined,
        count: hits.length,
        hits,
      }
    },
  }

  const ptOobPayload = {
    name: 'pt_oob_payload',
    description:
      `按探测点生成即用 payload（family：${PAYLOAD_FAMILIES.join('/')}）。返回的每条 payload 已把该探测点的 URL/DNS 名填好，直接放进参数/命令即可。listener 字段说明本机实际能观测什么（http/dns）；ldap/smtp 相关条目只是形态参考，未被监听时不要据此判死。`,
    parameters: {
      type: 'object',
      properties: {
        id: str('探测点 id 或 token（pt_oob_new 的返回）'),
        family: { type: 'string', enum: PAYLOAD_FAMILIES, description: '漏洞族' },
        target: str('可选：目标地址，仅回填到结果里便于拼请求'),
      },
      required: ['id', 'family'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('带外 payload：') },
    async execute(args = {}) {
      const shot = store.oobShot(args.id)
      if (!shot) throw new Error(`pt_oob_payload: 未知探测点 ${JSON.stringify(args.id)}；先 pt_oob_new`)
      const info = oob.info()
      return oobPayloads({
        family: args.family,
        baseUrl: info.baseUrl,
        dnsName: shot.dnsName,
        token: shot.token,
        target: args.target ?? '',
      })
    },
  }

  const ptCred = {
    name: 'pt_cred',
    description:
      '凭据与会话库：action=add 落库（明文写本地文件，回显只给掩码）、action=list 查看、action=show 取明文用于构造命令。拿到口令/cookie/JWT/SSH key/hash 后立刻 add——「取凭据→横向」这条链不能靠上下文记忆维持，压缩或长任务会丢。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['add', 'list', 'show'], description: 'add 新增 / list 列表 / show 取明文' },
        id: str('show 时的凭据 id'),
        host: str('add/list：所属主机（域名/IP）'),
        kind: {
          type: 'string',
          enum: ['password', 'cookie', 'jwt', 'sshkey', 'hash', 'token', 'session'],
          description: 'add 时的凭据类型',
        },
        username: str('add：用户名'),
        secret: str('add：凭据原文（cookie 整串、私钥全文、hash 值等）'),
        note: str('add：来源与适用范围备注'),
        worker: str('add：可选 worker 标识；给了就会自动记一条过程 step'),
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('凭据库：') },
    async execute(args = {}) {
      switch (args.action) {
        case 'add': {
          const row = store.addCred(args)
          processLog(store, args, 'bypass', `cred ${row.kind}@${row.host} (${row.username || 'n/a'}) 已落库 ${row.masked}`)
          return { credential: row }
        }
        case 'list':
          return { credentials: store.listCreds({ host: args.host ?? '' }) }
        case 'show': {
          if (!args.id) throw new Error('pt_cred: show 需要 id')
          const { row, secret } = store.credSecret(args.id)
          return {
            id: row.id,
            host: row.host,
            kind: row.kind,
            username: row.username,
            note: row.note,
            secret,
            usage:
              row.kind === 'cookie'
                ? `curl -H 'Cookie: ${secret}' http://${row.host}/`
                : row.kind === 'sshkey'
                  ? `把私钥写入临时文件并 chmod 600 后 ssh -i <file> ${row.username || 'user'}@${row.host}`
                  : `按 ${row.kind} 类型直接用于目标鉴权；不要把明文写进会入库的 artifact`,
          }
        }
        default:
          throw new Error('pt_cred: action must be add, list or show')
      }
    },
  }

  const ptDefense = {
    name: 'pt_defense',
    description:
      `防护画像与绕过矩阵：action=note 记录某主机命中的 WAF/拦截特征/已用族/有效绕过；action=list 查看；action=matrix 按族（${MATRIX_FAMILIES.join('/')}）生成下一批变体 payload（可传 waf 排序）。被 403/429/验证码拦住时先 note，再 matrix 换变体——不要对同一 payload 反复重试。`,
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['note', 'list', 'matrix'], description: 'note 记录 / list 查看 / matrix 生成变体' },
        host: str('note/list：主机'),
        waf: str('note：识别到的防护（cloudflare/akamai/safedog/360waf/modsecurity/unknown）；matrix 时用于排序'),
        blockedSignature: str('note：拦截特征（状态码、页面关键字、拦截页标题等）'),
        blockedFamilies: strList('note：已被拦的 payload 族'),
        workingBypass: str('note：已验证有效的绕过方式'),
        family: { type: 'string', enum: MATRIX_FAMILIES, description: 'matrix：payload 族' },
        base: str('matrix：可选，把变体套用到这个基准 payload 上'),
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('防护画像：') },
    async execute(args = {}) {
      switch (args.action) {
        case 'note':
          return { defense: store.noteDefense(args) }
        case 'list':
          return { defense: store.listDefense({ host: args.host ?? '' }) }
        case 'matrix': {
          if (!args.family) throw new Error('pt_defense: matrix 需要 family')
          const profile = args.host ? store.listDefense({ host: args.host })[0] : undefined
          return bypassVariants({ family: args.family, base: args.base ?? '', waf: args.waf ?? profile?.waf ?? '' })
        }
        default:
          throw new Error('pt_defense: action must be note, list or matrix')
      }
    },
  }

  const ptCandidate = {
    name: 'pt_candidate',
    description:
      '候选漏洞队列：action=add 登记一条待验证线索（模板命中/CVE/模型猜测）、action=list 查看、action=verdict 给结论。硬约束：confirmed 必须给出真实证据（evidence 至少「命令/payload + 关键回显」，或用 oobId 指向已有回连的探测点）——仅凭版本号/CVE/模板匹配不能确认；refuted 要写否定依据。确认后仍应把可复现请求/输出用 pt_evidence_save 固化。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['add', 'list', 'verdict'], description: 'add 登记 / list 查看 / verdict 定论' },
        id: str('verdict：候选 id'),
        host: str('add/list：目标主机'),
        title: str('add：一句话描述（如 Apache 2.4.49 路径穿越）'),
        source: { type: 'string', enum: ['template', 'cve', 'model', 'guess'], description: 'add：来源' },
        ref: str('add：模板 id / 扫描器输出 / 参考链接'),
        cve: str('add：CVE 编号'),
        state: str('list：按状态过滤（candidate/verifying/confirmed/refuted）'),
        verdict: { type: 'string', enum: ['confirmed', 'refuted', 'inconclusive', 'verifying'], description: 'verdict：结论' },
        evidence: str('verdict：证据摘要（命令/payload + 关键回显）'),
        oobId: str('verdict：带外探测点 id（该探测点必须已有回连）'),
        note: str('verdict：补充说明/修复建议线索'),
        worker: str('add/verdict：可选 worker 标识；给了就会自动记一条过程 step'),
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('候选漏洞：') },
    async execute(args = {}) {
      switch (args.action) {
        case 'add': {
          const row = store.addCandidate(args)
          processLog(store, args, 'note', `candidate: ${row.title} (${row.source}${row.cve ? ' ' + row.cve : ''}) — ${row.state}`)
          return { candidate: row }
        }
        case 'list':
          return { candidates: store.listCandidates({ state: args.state ?? '', host: args.host ?? '' }) }
        case 'verdict': {
          if (!args.id) throw new Error('pt_candidate: verdict 需要 id')
          const row = store.setCandidateVerdict(args)
          processLog(store, args, row.state === 'refuted' ? 'dead-end' : 'note', `candidate ${row.id} → ${row.state}`, row.evidence)
          return { candidate: row }
        }
        default:
          throw new Error('pt_candidate: action must be add, list or verdict')
      }
    },
  }

  const ptEvidenceSave = {
    name: 'pt_evidence_save',
    description:
      '把证据原文（请求/响应、命令输出、日志、PoC 脚本）落盘并计算 sha256，返回路径与哈希。漏洞复现、链推进、报告引用都以它为准——正文写进上下文会被压缩剥掉，落盘不会。',
    parameters: {
      type: 'object',
      properties: {
        name: str('文件名语义（如 poc-upload-rce）'),
        content: str('证据正文（完整请求/响应或命令输出）'),
        note: str('可选备注：采集方式、时间、目标'),
      },
      required: ['name', 'content'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('证据已固化：') },
    async execute(args = {}) {
      return store.saveEvidence(args)
    },
  }

  const ptNext = {
    name: 'pt_next',
    description:
      '本轮该干什么（ARTEX planner 的程序化替代）：读 mission、frontier（intent 队列）、攻击链 ready 步骤、未测资产、待定候选、带外回连，算出一个 decision 和具体下一步动作（带工具名与参数）。每轮开局、每次收口之后都先调它——进度由程序算，不要凭对话或记忆推断。decision=execute 就去做这一条；verify 是去补证据；converge 表示要么 prove 目标、要么补一条全新方向。',
    parameters: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('下一步：') },
    async execute() {
      return nextActions({ store })
    },
  }

  const ptMission = {
    name: 'pt_mission',
    description:
      '任务框架（ARTEX 的 mission）：action=start 建立目标/范围/约束、action=state 看现状与 intent 统计、action=prove 标记目标达成（必须有真实证据，且有未收口 intent 时会被拒绝）、action=report 生成 Markdown 报告、action=stop 中止。一个 mission 对应一次完整的对话式渗透。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['start', 'state', 'prove', 'report', 'stop'], description: 'start/state/prove/report/stop' },
        goal: str('start：一句话目标（如「拿到 https://demo.test 的管理员权限或证明无法拿到」）'),
        scope: strList('start：授权范围（域名/IP/CIDR/站点），后续所有意图都应落在其中'),
        constraints: strList('start：禁止的操作（如「不碰 /admin 删除接口」「不做 DoS」）'),
        goals: strList('start：可选，把目标拆成多条可独立验收的子目标（必须逐个 prove；省略则用 goal 本身作为唯一目标）'),
        title: str('start：可读标题，默认用 goal'),
        replace: bool('start：已有进行中的 mission 时是否重开'),
        evidence: str('prove：达成依据（命令/请求 + 回显，或证据文件 sha256/路径）'),
        note: str('prove/stop：补充说明'),
        force: bool('prove：承认还有未收口 intent 也收尾'),
        reason: str('stop：中止原因'),
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('mission：') },
    async execute(args = {}) {
      switch (args.action) {
        case 'start':
          return { mission: store.startMission(args) }
        case 'state': {
          const mission = store.missionView()
          if (!mission) throw new Error('pt_mission: 还没有 mission；先 action=start')
          return { mission, intents: store.listIntents({ limit: 20 }) }
        }
        case 'prove':
          return { mission: store.proveMission(args) }
        case 'report':
          return store.missionReport()
        case 'stop':
          return { mission: store.stopMission(args) }
        default:
          throw new Error('pt_mission: action must be start, state, prove, report or stop')
      }
    },
  }

  const ptIntent = {
    name: 'pt_intent',
    description:
      '意图队列（ARTEX 的 frontier，一次一个 worker 一条意图）：action=add 派意图（1..8 条，一句话方向；与在跑/在排队的实质重复会被跳过）、action=claim 原子领取下一条（只做它）、action=done 收口并统计这条意图实际写回了多少 facts/assets/findings（写 0 会被点名）、action=list 查看。串行链请用 pt_chain_plan 记步骤，并行维度才用多条 intent。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['add', 'claim', 'done', 'list'], description: 'add/claim/done/list' },
        summaries: strList('add：意图方向（一句话，写清目标资产 + 做什么 + 为什么），最多 8 条'),
        hintIds: strList('add：把这次派的第一条意图关联到这些 hint（hint 会离开 open 集，并连 hint —spawns→ intent）'),
        priority: int('add：优先级（大的先领），默认 0'),
        worker: str('claim/done：worker 标识（默认 chat）。多 worker 并行时每人领一条、各自收口'),
        id: str('done：要收口的 intent id'),
        state: { type: 'string', enum: ['open', 'done', 'exhausted', 'blocked'], description: 'done：收口状态（exhausted=预算/轮次耗尽、blocked=外部故障）' },
        output: str('done：一句话结论（做到了什么 / 卡在哪）'),
        limit: int('list：返回条数，默认 20'),
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('意图队列：') },
    async execute(args = {}) {
      switch (args.action) {
        case 'add':
          return store.addIntents({
            summaries: (args.summaries ?? []).map((summary, index) => ({
              summary,
              hintIds: index === 0 ? (args.hintIds ?? []) : [],
            })),
            priority: args.priority,
          })
        case 'claim':
          return store.claimIntent({ by: String(args.worker ?? '').trim() || 'chat' })
        case 'done':
          if (!args.id) throw new Error('pt_intent: done 需要 id')
          return store.finishIntent({ id: args.id, state: args.state ?? 'done', output: args.output ?? '' })
        case 'list':
          return { intents: store.listIntents({ state: args.state === 'open' || args.state === 'done' || args.state === 'exhausted' || args.state === 'blocked' ? args.state : '', limit: args.limit }) }
        default:
          throw new Error('pt_intent: action must be add, claim, done or list')
      }
    },
  }

  const ptAsset = {
    name: 'pt_asset',
    description:
      '资产图（与意图/事实分开的真值库）：action=add 登记资产（按 type+name 去重合并 props）、action=list 检索（可按 q/type/tested 过滤）、action=mark 标记已测。type 取 root_domain/subdomain/ip/service/app/endpoint/credential/host。资产是共享事实，覆盖度（已测/总数）会进 pt_next 的判定。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['add', 'list', 'mark'], description: 'add/list/mark' },
        assets: {
          type: 'array',
          description: 'add：资产列表',
          items: {
            type: 'object',
            properties: {
              type: { type: 'string', enum: ['root_domain', 'subdomain', 'ip', 'service', 'app', 'endpoint', 'credential', 'host'] },
              name: str('资产标识（域名/URL/IP:port/路径）'),
              host: str('可选：所属主机'),
              port: { type: 'integer', description: '可选：端口' },
              url: str('可选：可访问 URL'),
              props: { type: 'object', additionalProperties: true, description: '可选：指纹/参数/标题等结构化属性' },
            },
            required: ['type', 'name'],
            additionalProperties: false,
          },
        },
        q: str('list：关键字'),
        type: str('list：按类型过滤'),
        tested: bool('list：true=只要已测，false=只要未测'),
        limit: int('list：返回条数，默认 40'),
        id: str('mark：资产 id'),
        worker: str('add/mark：可选 worker 标识；给了就会自动记一条过程 step'),
        intentId: str('可选：归属意图 id'),
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('资产图：') },
    async execute(args = {}) {
      switch (args.action) {
        case 'add': {
          const result = store.addAssets({ assets: args.assets })
          for (const asset of result.created) {
            processLog(store, args, 'asset', `asset: ${asset.type} ${asset.name}`)
          }
          return result
        }
        case 'list':
          return {
            assets: store.listAssets({
              q: args.q ?? '',
              type: args.type ?? '',
              tested: args.tested === undefined ? '' : args.tested,
              limit: args.limit,
            }),
          }
        case 'mark':
          if (!args.id) throw new Error('pt_asset: mark 需要 id')
          return { asset: store.markAsset({ id: args.id, tested: args.tested !== false }) }
        default:
          throw new Error('pt_asset: action must be add, list or mark')
      }
    },
  }

  const ptFinding = {
    name: 'pt_finding',
    description:
      '已确认漏洞（与候选队列分开）：action=add 登记（severity=info/low/medium/high/critical，必须给真实证据，只有版本/模板匹配请用 pt_candidate）、action=list 查看、action=state 改处置状态（fixed/false_positive 等）。报告与复测都读这里。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['add', 'list', 'state'], description: 'add/list/state' },
        title: str('add：漏洞标题'),
        severity: { type: 'string', enum: ['info', 'low', 'medium', 'high', 'critical'], description: 'add：严重度' },
        evidence: str('add：真实证据（命令/payload + 关键回显）'),
        assetId: str('add：关联资产 id（pt_asset 的返回）'),
        chainId: str('add：可选，关联攻击链 id'),
        cvss: { type: 'number', description: 'add：可选 CVSS 分' },
        id: str('state：finding id'),
        state: { type: 'string', enum: ['confirmed', 'fixed', 'false_positive', 'suspected'], description: 'state：新状态' },
        note: str('state：状态变更依据'),
        limit: int('list：返回条数，默认 20'),
        worker: str('add：可选 worker 标识；给了就会自动记一条过程 step'),
        intentId: str('可选：归属意图 id'),
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('漏洞：') },
    async execute(args = {}) {
      switch (args.action) {
        case 'add': {
          const row = store.addFinding(args)
          processLog(store, args, 'finding', `finding[${row.severity}]: ${row.title}`, row.evidence)
          return { finding: row }
        }
        case 'list':
          return { findings: store.listFindings({ state: '', severity: '', limit: args.limit }) }
        case 'state':
          if (!args.id) throw new Error('pt_finding: state 需要 id')
          return { finding: store.setFindingState(args) }
        default:
          throw new Error('pt_finding: action must be add, list or state')
      }
    },
  }

  const ptTrace = {
    name: 'pt_trace',
    description:
      'worker 之间的过程级信息交换（ARTEX 的 activity 库）：action=add 记一条执行过程（试了什么/回了什么，包含死路与 WAF 细节）、action=search 在**其他 worker** 的过程里按关键字检索（自动排除自己那条意图，命中项带 intentId）、action=get 取某条意图的具体步骤全文、action=list 看谁跑过哪些意图。过程 ≠ 事实：事实是结论，过程是别人还能接着挖的原始痕迹。写回时带 worker 参数会自动记一条 step。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['add', 'search', 'get', 'list'], description: 'add/search/get/list' },
        worker: str('worker 标识（如 w1/w2/chat）；add 时决定归属，search/list 时可过滤'),
        intentId: str('可选：所属意图 id；省略时取该 worker 当前 running 的意图'),
        kind: {
          type: 'string',
          enum: ['claim', 'close', 'note', 'probe', 'fact', 'asset', 'finding', 'error', 'dead-end', 'bypass'],
          description: 'add：步骤类型（probe=探测、error=报错、dead-end=死路、bypass=有效绕过）',
        },
        summary: str('add：一句话过程（如「POST /upload 用 .php5 扩展名 → 500，日志报 mime 不匹配」）'),
        detail: str('add：可选全文（原始请求/响应片段、报错栈、payload）'),
        q: str('search：关键字（必填；匹配 summary+detail）'),
        excludeIntent: str('search：排除该意图的过程（通常填自己的意图 id）'),
        kinds: strList('search：只看这些 kind'),
        steps: strList('get：step id 列表；省略则返回该意图全部步骤'),
        limit: int('返回条数，默认 20'),
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('过程库：') },
    async execute(args = {}) {
      switch (args.action) {
        case 'add': {
          const worker = String(args.worker ?? '').trim() || 'chat'
          const intentId = String(args.intentId ?? store.runningIntentOf(worker)?.id ?? '')
          return {
            step: store.logActivity({
              worker,
              intentId,
              kind: args.kind ?? 'note',
              summary: args.summary,
              detail: args.detail ?? '',
            }),
          }
        }
        case 'search':
          return { hits: store.searchActivity({ q: args.q, excludeIntent: args.excludeIntent ?? '', worker: args.worker ?? '', kinds: args.kinds ?? [], limit: args.limit }) }
        case 'get':
          return { intentId: args.intentId ?? '', steps: store.traceSteps({ intentId: args.intentId ?? '', stepIds: args.steps ?? [], limit: args.limit ?? 50 }) }
        case 'list':
          return { traces: store.listTraces({ worker: args.worker ?? '', limit: args.limit }) }
        default:
          throw new Error('pt_trace: action must be add, search, get or list')
      }
    },
  }

  const ptWorker = {
    name: 'pt_worker',
    description:
      '把子 agent 当 worker 用：action=brief 生成一段可直接投给 subagent 的作业说明（身份/范围/claim/写回/过程交换/回报格式）、action=status 看每个 worker 领了哪条意图、走了几步、静默多久、action=reap 把静默超时的 worker 手里的意图放回 frontier（防止僵尸 worker 卡死队列）。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['brief', 'status', 'reap'], description: 'brief/status/reap' },
        worker: str('brief：worker 标识（如 w1），会成为 claim 的 owner'),
        phase: { type: 'string', enum: ['recon', 'sweep', 'deepdive', 'verify'], description: 'brief：按阶段生成合同（默认取 mission.phase）' },
        cat: str('brief：phase=sweep 时的类目（recon/auth/access/injection/file/client/logic/api/infra/iot）'),
        staleMs: int('status/reap：静默多久算卡住，默认 600000（10 分钟）'),
        note: str('brief：可选补充（这个 worker 的偏好/已知线索）'),
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('worker：') },
    async execute(args = {}) {
      switch (args.action) {
        case 'brief': {
          const worker = String(args.worker ?? '').trim()
          if (worker === '') throw new Error('pt_worker: brief 需要 worker（如 w1）')
          const mission = store.missionView()
          if (!mission) throw new Error('pt_worker: 先 pt_mission action=start，worker 才有目标可做')
          const open = store.listIntents({ state: 'open', limit: 10 })
          const phase = String(args.phase ?? mission.phase ?? store.phaseOf()).trim()
          const cat = String(args.cat ?? '').trim()
          const brief = [
            `你是 ARTEX worker「${worker}」。你在一个共享状态上工作，规则是：**一次只做一条意图，做完写回并收口**。`,
            '',
            `## 任务框架（不要改动）`,
            `- 目标: ${mission.goal}`,
            `- 授权范围: ${mission.scope.length ? mission.scope.join(', ') : '(未声明，按 mission 原文)'}`,
            `- 约束（最高优先级，违反即停）: ${mission.constraints.length ? mission.constraints.join('; ') : '(无额外约束)'}`,
            `- 当前阶段: ${phase}${phase === 'sweep' && cat ? ` / ${cat}` : ''}`,
            '',
            workerContract(phase, cat, worker),
            '',
            `## 起手`,
            `1. \`pt_intent action=claim worker=${worker}\` —— 领一条。返回的 intent id 记下来。`,
            `   若返回 reused=true，说明你手上已有一条 running，先做完它。`,
            `2. \`pt_next\` 看一眼全局（可选）：确认你的方向和别人不重复。`,
            '',
            `## 干活`,
            `- 用真实工具（bash/curl/浏览器）执行你所领意图的具体动作，不要只做推理。`,
            `- 动手前先用 \`pt_trace action=search q=<关键字> excludeIntent=<你的 intent id>\` 查别人试过什么；`,
            `  别人的过程是线索不是证据，要自己复现一次才算 observed。`,
            `- 遇到值得记的原始痕迹（报错全文、被过滤的 payload、有效的变形、死路）立刻`,
            `  \`pt_trace action=add worker=${worker} kind=error|probe|dead-end|bypass summary=… detail=…\`。`,
            '',
            `## 写回（写进库才算数）`,
            `- 新资产 → \`pt_asset action=add worker=${worker} assets=[…]\``,
            `- 结论/观察 → \`pt_fact_add worker=${worker} label=… summary=… confidence=observed|inferred evidence=<命令+关键回显>\``,
            `- 真触发过的漏洞 → \`pt_finding action=add worker=${worker} title=… severity=… evidence=…\``,
            `- 只匹配版本/模板/CVE → \`pt_candidate action=add worker=${worker} …\`，**不要**升级成 finding。`,
            `- 拿到凭据 → \`pt_cred action=add worker=${worker} host=… kind=… secret=…\`，不要贴进对话正文。`,
            '',
            `## 收口`,
            `\`pt_intent action=done id=<你的 intent id> worker=${worker} state=done output="<一句话结论>"\``,
            `- 被预算掐断或外部故障没跑成形 → state=exhausted / blocked（别写 done）。`,
            `- done 会统计你这条意图实际写回了多少；写 0 会被点名，说明你的观察没进库。`,
            '',
            `## 回报格式（回给调度者，一行足够）`,
            `\`${worker} | intent <id> | <state> | writes {facts:N,assets:N,findings:N} | <最关键的一条观察或线索>\``,
            '',
            `## 红线`,
            `- 只做你领到的那一条意图；看到别的线索写进 fact 或 trace，交给调度者。`,
            `- 不碰授权范围外的目标；不做破坏性操作（删除/清空/DoS）。`,
            `- 没有真实回显/回连的结论，只能记 inferred，不能当已确认漏洞。`,
            args.note ? `\n## 调度者补充\n${String(args.note)}` : '',
          ]
            .filter((line) => line !== '')
            .join('\n')
          return {
            worker,
            dataDir: store.paths.root,
            mission: { id: mission.id, goal: mission.goal, scope: mission.scope, constraints: mission.constraints },
            openIntents: open.map((intent) => ({ id: intent.id, summary: intent.summary, priority: intent.priority })),
            brief,
          }
        }
        case 'status':
          return { workers: store.workerStatus({ staleMs: args.staleMs ?? 600000 }), dataDir: store.paths.root }
        case 'reap':
          return store.reapStaleWorkers({ staleMs: args.staleMs ?? 600000 })
        default:
          throw new Error('pt_worker: action must be brief, status or reap')
      }
    },
  }

  const ptGraph = {
    name: 'pt_graph',
    description:
      '双图查询（ARTEX 的探索图 + 资产图 + 锚点）：action=nodes 看两边节点计数与边/锚点数、action=coverage 看范围内覆盖度（分母=授权范围资产，已测=标记过或锚定过事实/漏洞）、action=edges/anchors 看原始边与锚点、action=around 绕某个 assetId 或 node（如 intent:intent-4 / fact:fact-8）看血缘：谁产出了它、它落在哪台资产、有哪些子资产。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['nodes', 'coverage', 'edges', 'anchors', 'around'], description: 'nodes/coverage/edges/anchors/around' },
        assetId: str('around：资产 id（pt_asset 的返回）'),
        node: str('around：节点引用，形如 intent:intent-4 / fact:fact-8 / finding:finding-16'),
        limit: int('返回条数，默认 50'),
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('双图：') },
    async execute(args = {}) {
      switch (args.action) {
        case 'coverage':
          return store.coverage()
        case 'nodes': {
          const view = store.graphView({ limit: args.limit })
          return { nodes: view.nodes, edges: view.edges, anchors: view.anchors, coverage: view.coverage }
        }
        case 'edges':
          return { edges: store.graphView({ all: true, limit: args.limit }).edgeList ?? [] }
        case 'anchors':
          return { anchors: store.graphView({ all: true, limit: args.limit }).anchorList ?? [] }
        case 'around': {
          if (!args.assetId && !args.node) throw new Error('pt_graph: around 需要 assetId 或 node')
          return store.graphView({ assetId: args.assetId ?? '', node: args.node ?? '', limit: args.limit })
        }
        default:
          throw new Error('pt_graph: action must be nodes, coverage, edges, anchors or around')
      }
    },
  }

  const ptHint = {
    name: 'pt_hint',
    description:
      '人给的提示（hint）节点：action=add 把用户原话记成 hint（不占 frontier，但会进 pt_next 的 reasons；文本里提到的资产自动挂锚点）、action=list 查看、action=address 手动标为已接手（并连 hint —spawns→ intent）。hint 是"人指的方向"，不是意图；派意图时用 pt_intent add hintIds=[…] 关联，它会自动离开 open 集。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['add', 'list', 'address'], description: 'add/list/address' },
        text: str('add：用户原话（逐字，不要改写）'),
        assetIds: strList('add：可选，强制锚定到这些资产（默认按文本匹配）'),
        id: str('address：hint id'),
        intentId: str('address：接手它的意图 id（会连一条 spawns 边）'),
        state: { type: 'string', enum: ['open', 'addressed'], description: 'list：按状态过滤' },
        worker: str('add：记录者标识，默认 human'),
        limit: int('list：返回条数，默认 20'),
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('hint：') },
    async execute(args = {}) {
      switch (args.action) {
        case 'add':
          return { hint: store.addHint({ text: args.text, assetIds: args.assetIds ?? [], worker: args.worker ?? 'human' }) }
        case 'list':
          return { hints: store.listHints({ state: args.state ?? '', limit: args.limit }) }
        case 'address':
          if (!args.id) throw new Error('pt_hint: address 需要 id')
          return { hint: store.addressHint({ id: args.id, intentId: args.intentId ?? '' }) }
        default:
          throw new Error('pt_hint: action must be add, list or address')
      }
    },
  }

  const ptGoal = {
    name: 'pt_goal',
    description:
      '目标分解（ARTEX 的 goals + prove_goal）：action=add 加一个可独立验收的子目标、action=list 查看、action=prove 用真实证据把某个目标标为达成。pt_mission prove 要求所有目标都已达成（除非 force），所以量化验收标准要拆成多条。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['add', 'list', 'prove'], description: 'add/list/prove' },
        text: str('add：可判真假的一句话目标'),
        id: str('prove：目标 id'),
        evidence: str('prove：达成依据（命令/请求 + 回显，或证据文件 sha256/路径）'),
        force: bool('prove：无证据也标记（不推荐，会记在报告里）'),
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('目标：') },
    async execute(args = {}) {
      switch (args.action) {
        case 'add':
          return { goal: store.addGoal({ text: args.text }), summary: store.goalsSummary() }
        case 'list':
          return { goals: store.listGoals(), summary: store.goalsSummary() }
        case 'prove':
          if (!args.id) throw new Error('pt_goal: prove 需要 id')
          return { goal: store.proveGoal({ id: args.id, evidence: args.evidence ?? '', force: args.force === true }), summary: store.goalsSummary() }
        default:
          throw new Error('pt_goal: action must be add, list or prove')
      }
    },
  }

  const ptPhase = {
    name: 'pt_phase',
    description:
      '阶段状态机：recon（挖面）→ sweep（按类目横扫）→ deepdive（串行利用链）→ report（收口）。action=status 看当前阶段与允许的迁移；action=set 切换（非法迁移会被拒，除非 force）。阶段决定 pt_next 推什么、worker brief 的合同是什么——防止"面还没摸清就开始逐个试 payload"。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['status', 'set'], description: 'status/set' },
        phase: { type: 'string', enum: ['recon', 'sweep', 'deepdive', 'report'], description: 'set：目标阶段' },
        note: str('set：切换理由（会记进 activity）'),
        force: bool('set：允许非常规迁移'),
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('阶段：') },
    async execute(args = {}) {
      if (args.action === 'status') {
        const mission = store.missionView()
        if (!mission) throw new Error('pt_phase: 还没有 mission')
        const current = store.phaseOf()
        const allowed = { recon: ['sweep', 'deepdive'], sweep: ['deepdive', 'report', 'recon'], deepdive: ['sweep', 'report'], report: ['sweep', 'deepdive'] }
        return {
          phase: current,
          note: mission.phaseNote ?? '',
          at: mission.phaseAt ?? 0,
          allowedNext: allowed[current] ?? [],
          coverage: store.coverageStats(),
          goals: store.goalsSummary(),
        }
      }
      if (args.action === 'set') {
        if (!args.phase) throw new Error('pt_phase: set 需要 phase')
        return store.setPhase({ phase: args.phase, note: args.note ?? '', force: args.force === true })
      }
      throw new Error('pt_phase: action must be status or set')
    },
  }

  const ptCoverage = {
    name: 'pt_coverage',
    description:
      '漏洞测试类型矩阵（按「资产 × 类目」计算，防止只打一类就收工）：action=taxonomy 列出全部类型（含适用资产与一句打法）、action=matrix 看明细（可按 assetId/cat/state 过滤）、action=next 取下一批未覆盖的格子、action=stats 按类目看覆盖率、action=mark 标记某个格子或整类（state=tested|na|testing，na 必须写 note 说明为什么不适用）。有未覆盖格子时 pt_next 不许收敛。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['taxonomy', 'matrix', 'next', 'stats', 'mark'], description: 'taxonomy/matrix/next/stats/mark' },
        assetId: str('mark：资产 id；matrix：按资产过滤'),
        classId: str('mark：单个类型 id（见 action=taxonomy）'),
        cat: str('mark：整类批量标记；matrix：按类目过滤'),
        state: {
          type: 'string',
          enum: ['untested', 'testing', 'tested', 'na'],
          description: 'mark：新状态（na 需 note 说明原因）；matrix：按状态过滤',
        },
        note: str('mark：依据/不适用原因（如「无上传功能」）'),
        intentId: str('mark：归属意图 id'),
        skipResolved: bool('mark：整类兜底时只填未定论的格子（不覆盖已单独测过的结论）'),
        quiet: bool('mark：只回标记结果，不回全量覆盖统计（省上下文）'),
        worker: str('mark：worker 标识；给了会记一条过程 step'),
        limit: int('next/matrix：返回条数'),
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: { schema: ANY_OBJECT, render: jsonRender('类型覆盖：') },
    async execute(args = {}) {
      switch (args.action) {
        case 'taxonomy':
          return { categories: store.taxonomySummary() }
        case 'matrix':
          return { cells: store.coverageMatrix({ assetId: args.assetId ?? '', cat: args.cat ?? '', state: args.state ?? '', limit: args.limit }), stats: store.coverageStats() }
        case 'next':
          return { cells: store.uncovered({ limit: args.limit ?? 10 }), stats: store.coverageStats() }
        case 'stats':
          return store.coverageStats()
        case 'mark': {
          const result = store.markCoverage({
            assetId: args.assetId,
            classId: args.classId ?? '',
            cat: args.cat ?? '',
            state: args.state ?? 'tested',
            note: args.note ?? '',
            intentId: args.intentId ?? '',
            skipResolved: args.skipResolved === true,
          })
          processLog(store, args, 'note', `coverage ${result.assetId}: ${result.marked.join(',')} → ${result.state}${args.note ? ` (${args.note})` : ''}`)
          return args.quiet === true ? result : { ...result, stats: store.coverageStats() }
        }
        default:
          throw new Error('pt_coverage: action must be taxonomy, matrix, next, stats or mark')
      }
    },
  }

  const ptRecon = {
    name: 'pt_recon',
    description:
      '静态资产发现（唯一会出站请求的工具）：抓一个页面 + 它同源的 JS bundle，挖出被 SPA 藏起来的接口、参数、功能点与线索（token/密钥/sourcemap/外部域名）。action=scan 只返回结果不动状态；action=save 会把 app/endpoint 资产写进资产图、把线索写成事实，并把该资产的 recon 类目自动标为 tested。运行时（登录后 XHR）请用浏览器驱动页面，再把观测到的请求交给 pt_asset。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['scan', 'save'], description: 'scan=只看结果 / save=写进资产图（默认）' },
        url: str('入口 URL（页面地址）'),
        js: strList('可选：额外要抓的 JS URL（跨域 bundle 时用）'),
        maxScripts: int('最多抓几个同源脚本，默认 20'),
        timeoutMs: int('单请求超时，默认 10000'),
        maxBytes: int('单文件字节上限，默认 1500000'),
        markCoverage: bool('save 时是否把 recon 类目标为 tested，默认 true'),
        worker: str('可选：worker 标识；给了会记一条过程 step'),
      },
      required: ['url'],
      additionalProperties: false,
    },
    noLock: true,
    output: { schema: ANY_OBJECT, render: jsonRender('静态资产发现：') },
    async execute(args = {}) {
      const discovery = await discover({
        url: args.url,
        extraJs: args.js ?? [],
        maxScripts: args.maxScripts ?? 20,
        timeoutMs: args.timeoutMs ?? 10000,
        maxBytes: args.maxBytes ?? 1500000,
      })
      const found = {
        origin: discovery.origin,
        pages: discovery.pages,
        scripts: discovery.scripts,
        endpoints: discovery.endpoints,
        params: discovery.params,
        features: discovery.features.slice(0, 40),
        hints: discovery.hints,
        errors: discovery.errors,
      }
      if ((args.action ?? 'save') === 'scan') return found

      store.load()
      store.acquire()
      let saved
      try {
        store.reloadIfChanged()
        const origin = discovery.origin
        const host = new URL(origin).host
        const title = discovery.pages[0]?.title ?? ''
        const appResult = store.addAssets({
          assets: [
            {
              type: 'app',
              name: origin,
              host,
              url: origin + '/',
              props: {
                title,
                source: 'pt_recon',
                scripts: discovery.scripts.length,
                params: discovery.params.map((param) => param.name).slice(0, 50),
              },
            },
          ],
        })
        const appAssetId = appResult.created[0]?.id ?? appResult.merged[0]?.id ?? ''

        let endpointAssets = { created: [], merged: [] }
        if (discovery.endpoints.length > 0) {
          endpointAssets = store.addAssets({
            assets: discovery.endpoints.slice(0, 300).map((endpoint) => ({
              type: 'endpoint',
              name: endpoint.path,
              host,
              props: {
                methods: endpoint.methods,
                sources: endpoint.sources,
                sample: endpoint.sample,
                source: 'pt_recon',
              },
            })),
          })
        }

        if (discovery.hints.length > 0) {
          store.addFact({
            label: `recon-hints:${host}`,
            summary: `静态产物里有 ${discovery.hints.length} 条线索（token/密钥/外部域名/sourcemap）`,
            host,
            confidence: 'observed',
            evidence: discovery.hints.slice(0, 8).join(' | ').slice(0, 900),
            worker: args.worker ?? '',
          })
        }
        store.addFact({
          label: `recon-surface:${host}`,
          summary: `静态采集：${discovery.endpoints.length} 个接口 / ${discovery.params.length} 个参数 / ${discovery.features.length} 个功能点 / ${discovery.scripts.length} 个 bundle`,
          host,
          confidence: 'observed',
          evidence: discovery.endpoints.slice(0, 10).map((endpoint) => `${endpoint.methods.join('/') || 'ANY'} ${endpoint.path}`).join(' ; '),
          worker: args.worker ?? '',
        })

        let coverage
        if (args.markCoverage !== false && appAssetId !== '') {
          coverage = store.markCoverage({
            assetId: appAssetId,
            cat: 'recon',
            state: 'tested',
            note: `pt_recon 静态采集：${discovery.endpoints.length} 接口 / ${discovery.params.length} 参数 / ${discovery.features.length} 功能点；hints ${discovery.hints.length} 条`,
            skipResolved: true,
          })
        }
        saved = {
          appAssetId,
          endpoints: endpointAssets.created.length,
          endpointsMerged: endpointAssets.merged.length,
          coverage: coverage ?? null,
        }
      } finally {
        store.release()
      }
      processLog(store, args, 'probe', `recon ${discovery.origin}: ${discovery.endpoints.length} endpoints / ${discovery.params.length} params`)
      return { ...found, saved }
    },
  }

  // 只读动作不占锁：pt_oob_poll 可能等 10s，占锁会把其他 worker 全卡住。
  const READ_ONLY_ACTIONS = new Set(['state', 'report', 'list', 'search', 'get', 'show', 'poll', 'status', 'brief', 'nodes', 'coverage', 'edges', 'anchors', 'around', 'taxonomy', 'matrix', 'next', 'stats'])
  const READ_ONLY_TOOLS = new Set(['pt_state', 'pt_next', 'pt_fact_list', 'pt_oob_poll', 'pt_oob_payload'])
  const isReadOnly = (toolName, args) => {
    if (READ_ONLY_TOOLS.has(toolName)) return true
    const action = args?.action
    return typeof action === 'string' && READ_ONLY_ACTIONS.has(action)
  }

  // Wrap every execute:
  //   1. 写操作先取跨进程锁 + 重新加载（子 agent / CLI / MCP 可能同时写同一份状态）
  //   2. 返回前过 lossless()，避免 undefined 被 harness 判成"非无损 JSON"
  return [
    ptState,
    ptNext,
    ptMission,
    ptIntent,
    ptAsset,
    ptFinding,
    ptChainPlan,
    ptChainAdvance,
    ptFactAdd,
    ptFactList,
    ptOobNew,
    ptOobPoll,
    ptOobPayload,
    ptCred,
    ptDefense,
    ptCandidate,
    ptEvidenceSave,
    ptTrace,
    ptWorker,
    ptGraph,
    ptHint,
    ptGoal,
    ptCoverage,
    ptPhase,
    ptRecon,
  ].map((tool) => {
    const run = tool.execute
    return {
      ...tool,
      async execute(args, exec) {
        const readOnly = isReadOnly(tool.name, args) || tool.noLock === true
        store.load()
        if (!readOnly) store.acquire()
        try {
          // 读也要追上别人的提交：rename 是原子的，读到的永远是完整文档。
          store.reloadIfChanged()
          return lossless(await run(args, exec))
        } finally {
          if (!readOnly) store.release()
        }
      },
    }
  })
}
