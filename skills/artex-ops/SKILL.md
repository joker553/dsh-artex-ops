---
name: artex-ops
description: 用对话方式跑 ARTEX 式自主渗透——mission 定目标与范围，pt_next 算出本轮该干什么，intent 队列一次一条地执行，资产/事实/漏洞全部写回可校验的本地状态，盲漏洞用带外探测点取证，最后 prove + 出报告。适用于长链路渗透、盲注入/盲 SSRF/盲 RCE 取证、需要跨会话保住进度的任务。
whenToUse: 用户说「用 ARTEX 方法测 X」「自主渗透这个目标」「多条链要按依赖推进」「盲漏洞要确证」「上次的进度接着做」时；也适用于把任务交给另一个 harness（CLI/MCP）继续跑。
---

# ARTEX ops：对话式自主渗透

一句话：**ARTEX 的做法是「规划者出意图、执行者做一条、写回图谱、再规划」，这里把它的状态机做成工具，我（对话里的 agent）就是那个执行者+规划者。**

状态在 `~/.dsh/artex-ops`（可 `ARTEX_OPS_HOME` 覆盖）：重启、压缩、换 harness 都不丢。

## 0. 开局：把目标说成可验收的 mission

```
pt_mission action=start
  goal: "拿到 https://demo.test 的管理员权限，或证明在当前范围与时间内无法拿到"
  scope: ["demo.test", "10.0.0.0/24"]
  constraints: ["不碰 /admin/delete*", "不做 DoS", "不上传 webshell 到生产目录"]
```

`goal` 必须能判真假。再 `pt_asset action=add` 把已知入口登记进去（站点/接口/IP），这一步决定覆盖度分母。

## 1. 循环：每轮都从 pt_next 开始

```
pt_next
```

返回 `decision` + `actions`（带工具名和参数）。按它走，不要凭对话记忆推断进度：

| decision | 含义 | 下一步 |
|---|---|---|
| `execute` | 有在跑/待领的意图，或有 ready 的链步骤 | 做那一条，然后写回 |
| `verify` | 有候选待定论，或有未登记的回连 | 补证据，不要开新方向 |
| `plan` | 有未测资产 | 派新意图（`pt_intent action=add`） |
| `converge` | 什么都空了 | 证明目标，或补一条**机理不同**的新方向 |
| `bootstrap` / `report` | 没 mission / mission 已收口 | 建 mission / 出报告 |

## 1.5 阶段：recon → sweep → deepdive → report

阶段决定「现在该干什么」，不是装饰。没有阶段时最常见的故障：刚发现两个端点就开始逐个试 payload，面没摸清、覆盖率永远上不去。

```bash
pt_phase action=status        # 当前阶段 + 允许的迁移 + 覆盖/golas 概况
pt_phase action=set phase=sweep note="recon 完：新增 87 端点 / 213 参数"
```

| 阶段 | 该做什么 | pt_next 会推 |
|---|---|---|
| `recon` | 挖面：`pt_recon`（JS/HTML）、浏览器运行时、目录/子域扫描 | **只推 recon 类目**（vcs/swagger/panel/verbose/secret/headers/cookie/listing） |
| `sweep` | 按类目横扫：`pt_coverage next cat=…` → 逐格测 → mark | 推**非 recon** 类目的格子（auth/access/injection/…） |
| `deepdive` | 串行利用链：`pt_chain_plan` → 只做 ready 步 → `pt_chain_advance` | 只推 ready 步骤与候选复验，**不推**覆盖动作 |
| `report` | 收口：`pt_mission prove` + `report` | 只推 prove/report |

迁移约束：`recon` 不能直接跳 `report`；回退（如 `deepdive → sweep`）合法。非法迁移要 `force=true`。

**worker 合同随阶段变**：`pt_worker action=brief worker=w2 phase=sweep cat=injection` 会生成专门写"领哪些格子、na 怎么写理由、只交 candidate 不交 finding"的作业说明；`phase=recon` 的合同明确禁止判洞，`phase=deepdive` 要求链式一步一证，`phase=verify` 要求换路径独立复验。
## 2. 领意图：一次一条

```
pt_intent action=claim          # 领下一条（没有就返回 hint）
pt_intent action=done id=intent-7 state=done output="确认 /api/v1/users 未鉴权，可列全量用户"
```

`done` 会告诉你这条意图实际写回了多少 facts/assets/findings。**写 0 会被点名**——ARTEX 的规则是：写进库才算数，写在对话里的会被压缩掉。

派新意图时写清"目标资产 + 做什么 + 为什么"，一次 ≤8 条，且不要与在跑/在排队的方向重复（工具会跳过重复项）：

```
pt_intent action=add summaries=[
  "测 https://demo.test/api/v1 的鉴权缺失（IDOR/BOLA），用两个不同身份的 token 对比",
  "测 /upload 的扩展名与 Content-Type 绕过，目标：拿到可访问的解析执行路径"
]
```

## 3. 写回：三种写回别串

| 观察到的东西 | 工具 |
|---|---|
| 资产本身（子域/服务/端点/参数/指纹/凭据位置） | `pt_asset action=add` |
| 探索结论（"这个接口未鉴权""这个参数被过滤"） | `pt_fact_add`（带 evidence + `observed`/`inferred`） |
| **真触发过的漏洞** | `pt_finding add`（severity + evidence；版本/模板匹配一律走 `pt_candidate`） |

```
pt_fact_add label=users-api-no-auth summary="/api/v1/users 无鉴权返回全量用户" \
  host=demo.test confidence=observed \
  evidence="curl -s https://demo.test/api/v1/users -> 200 [{\"id\":1,\"email\":\"a@b.c\"},...]"
```

## 3.5 多 worker：过程级交换（ARTEX 的 activity 库）

一个 worker 一条意图的边界不变，但**过程可以互相看**——很多有价值的观察（某个报错、某段响应、某个隐藏参数）出现在执行过程里，未必已经写成事实。

```bash
# 每个 worker 带自己的标识领意图
pt_intent claim worker=w1
pt_intent claim worker=w2

# 写回时带 worker → 自动留一条过程 step（归属由它当前 running 的意图推断）
pt_fact_add label=upload-php5-500 summary="POST /upload .php5 -> 500 mime 报错" worker=w1 ...

# 过程 ≠ 事实：原始报错、试过的死路、有效的变形，直接记下来
pt_trace action=add worker=w1 kind=error \
  summary="mime 校验抛异常（finfo 返回 text/x-php）" \
  detail="PHP Warning: finfo_file(): unsupported image type in upload.php line 42"

# 在别人的过程里按关键字检索（自动排除自己那条意图，命中项带 intentId）
pt_trace action=search q=finfo excludeIntent=intent-3

# 锁定某条意图取步骤全文；或看谁跑过什么
pt_trace action=get intentId=intent-2
pt_trace action=list
```

纪律：

- **过程可采信为线索，不可当证据**：别人的 step 告诉你"往这试"，你仍要自己触发才写 `observed` 事实。
- **排除自己的意图**：`excludeIntent` 填自己手上的 intent id，否则搜出来的全是自己刚写的。
- **kind 用对**：`probe` 探测、`error` 报错、`dead-end` 死路、`bypass` 有效绕过、`note` 其它。死路也值得记——它能省掉下一个 worker 半天。
- **写回量按归属统计**：`pt_intent done` 用 activity 归属算 writes，多 worker 并行不会串账（没带 worker 的旧记录才回落 baseline 差值）。

## 3.6 用子 agent 当 worker（真正的并行）

一个 subagent 就是一个 worker：它有自己的会话与工具，**一次领一条意图**，写回后收口。调度者（我）只负责发意图、发作业说明、看汇总。

```bash
# 1) 调度者先备好 frontier
pt_intent add summaries=["w1: 探测 /api 未鉴权","w2: 探测 /upload 校验"]

# 2) 生成可直接投喂 subagent 的作业说明（含 mission 范围/约束与整套纪律）
pt_worker action=brief worker=w1
pt_worker action=brief worker=w2
```

把 `brief` 原文作为 subagent 的任务描述丢进去（`subagent` 工具，**不要 fork**——worker 不需要继承整段对话，越干净越听话）。每个 worker 自己：

```
pt_intent claim worker=wN            → 拿到 intent id
（先 pt_trace search --exclude-intent 自己那条，看别人试过什么）
（真实探测：bash/curl/浏览器）
pt_fact_add worker=wN …              → 自动留 step
pt_trace add worker=wN kind=…        → 原始报错/死路/有效变形
pt_intent done id=… worker=wN        → 写回量按归属结算
```

调度者侧的三个动作：

| 动作 | 用途 |
|---|---|
| `pt_worker action=status` | 每个 worker 领了哪条、走了几步、静默多久（步骤少而久=在"想"不在"试"，该 steer 或 kill） |
| `pt_worker action=reap` | 静默超时的 worker 手里的意图**放回 frontier**（僵尸 worker 不会卡死队列） |
| `pt_next` | 看 `workers[]`：几个在跑、各自多少步；`>1` 时会提示用 trace 互查 |

**并发写安全**：所有入口（插件/CLI/MCP/子 agent）对同一份 `state.json` 都是"读-改-写"，因此写操作会拿 `state.json.lock` 并在写前重载别人的提交；只读动作不占锁（否则 `pt_oob_poll` 等 10s 会把全员卡住）。锁 20s 自动判定陈旧、8s 拿不到直接报错，不会静默丢更新。

## 3.7 双图：别只记结论，要让关系可查

写回时多花一秒，图就自己长出来：

```bash
# 资产只交原始信息，父子关系由程序推
pt_asset action=add assets=[
  {"type":"root_domain","name":"demo.test"},
  {"type":"subdomain","name":"api.demo.test","host":"api.demo.test"},
  {"type":"endpoint","name":"/api/v1/users","host":"api.demo.test"}
]

# 事实带 host → 自动锚到最具体的那台资产；漏洞带 assetId → 自动锚 + 连 proves 边
pt_fact_add label=users-no-auth host=api.demo.test worker=w1 …
pt_finding action=add assetId=<endpoint id> worker=w1 …

# 查血缘与覆盖
pt_graph action=around assetId=<endpoint id>   # 父是谁、子是谁、被哪些节点锚过
pt_graph action=around node=intent:intent-4    # 这条意图产出了什么、证出了什么
pt_graph action=coverage                       # 分母=授权范围；锚定过的资产算已测
```

意义：

- `intent —yields→ fact` / `intent —proves→ finding` / `asset —contains→ asset` 让"哪个方向派生了什么"可反查，而不是靠我复述。
- 覆盖度有了分母：`coverage.inScope` 只算授权范围内资产，`untested` 直接喂给 `pt_next` 的 `plan` 分支。
- 报告里的"资产覆盖"与"证据索引"都从这里取数，所以**不写 host/assetId 就等于放弃可追溯性**。

## 3.8 hint（人说的话）与多目标

**hint 就是我（用户）在对话里打的字。** 它不是意图，不进 frontier，但必须被看见、被接手。

```bash
pt_hint action=add text="优先看 /admin 的 cookie 鉴权，别在 /upload 上耗"
pt_hint action=list state=open
pt_intent action=add summaries=["按提示测 /admin：伪造 role=admin cookie 是否越权"] hintIds=[hint-4]
```

- `pt_next` 会把未接手的 hint 原文放进 `reasons`，并给出"转成意图"的动作；有 open hint 时**不允许收敛**。
- hint 文本里提到的资产会自动挂锚点（人指的方向落到具体资产），派意图时连 `hint —spawns→ intent`，于是能反查"人的哪句话变成了哪条执行"。
- 记 hint 要**逐字**，不要改写成"用户希望……"——改写会丢掉原意，也会让后续对不上。

**多目标**：mission 可以拆成多个可独立验收的子目标，每个都要自己的证据。

```bash
pt_mission action=start goal="拿到管理员权限或证明不可得" \
  goals=["确认 /api/v1/users 的鉴权状态","拿到一个可用的管理员会话"]
pt_goal action=list
pt_goal action=prove id=goal-2 evidence="伪造 Cookie role=admin -> /admin 200"
pt_mission action=prove evidence="两个子目标均有实测依据（见证据索引）"   # 有一条没达成会被拒
```

没显式写 `goals` 时，系统会用 `goal` 生成一条 `derived` 目标，允许用 mission 级证据直接结清——单目标任务不必多走一步空证明。
## 3.9 类型覆盖：不许只打一类就收工

`pt_coverage` 是内置的「资产 × 漏洞类型」矩阵（10 个类目、64 个类型，每类带一句打法）。**只要有格子没测，`pt_next` 就不许收敛**——这是"覆盖到位、不遗漏"的机器保证。

```bash
pt_coverage action=taxonomy                 # 看全部类型（含适用资产 + 打法提示）
pt_coverage action=stats                    # 按类目看覆盖率
pt_coverage action=next limit=10            # 下一批该测的格子（recon 优先排）

# 真测过（哪怕结论是"不存在"）→ tested，note 写依据
pt_coverage action=mark assetId=asset-3 classId=sqli state=tested note="' and 1=2 无差异；布尔/时间均无响应"

# 确实不适用 → na，必须写理由（不写会被拒，等于默认豁免）
pt_coverage action=mark assetId=asset-3 classId=upload-bypass state=na note="该资产无上传功能"

# 一整类都扫过（如注入类全试了）→ 按 cat 批量
pt_coverage action=mark assetId=asset-3 cat=injection state=tested note="sql/nosql/cmdi/ssti/xxe/ssrf 逐项确认"
```

纪律：

- **先 `next` 再动手**：它按类目优先级排序，避免又在 sqli 上磨第五遍。
- **一个类目一次活**：把同族格子塞进一条 intent（如"注入类横扫"），不要一个格子一条 intent。
- **`tested` 不等于"有洞"**：测过没发现也要标，否则永远收敛不了；有洞就走 `pt_candidate` / `pt_finding`。
- **`na` 是结论**：写清"为什么这个资产上不存在该面"，报告里会带出来。
- 覆盖率进 `pt_next` 的 `classCoverage`，也进报告的"类型覆盖"段。
## 3.10 隐藏接口：从 JS bundle 里把面挖出来

现代系统首页只有一个壳，接口/路由/功能点都在 bundle 里。`pt_recon` 就是干这个的（**唯一会出站**的工具：只访问给定 URL 与其同源脚本）。

```bash
pt_recon action=scan url=https://target.example/            # 只看结果
pt_recon action=save url=https://target.example/ js=["https://cdn.example/app.js"]   # 写资产图 + 自动标 recon tested
```

它从 HTML + JS 里挖四类东西：

| 产出 | 来源举例 |
|---|---|
| **接口** | `fetch('/api/v2/orders')`、`axios.post('/login')`、`path: '/orders/:id'`、字符串字面量 `/api/v2/admin/users`、`<form action>` |
| **参数** | 接口 URL 的 query key（page/size/q/verbose…），直接进资产 `props.params` |
| **功能点** | `<a href>`+文案、`<form>`、`<button>` 文案、前端路由表、`#/route` |
| **线索** | `localStorage.setItem('access_token')`、`Authorization`、`apiKey/secret`、sourcemap、外域地址 |

纪律：

- **静态只是第一层**：登录后才会出现的 XHR 抓不到。第二层用浏览器驱动（`playwright` 的 navigate + network 请求列表），把观测到的请求用 `pt_asset add` 登记；第三层才是按接口逐个测。
- **sourcemap 优先**：`//# sourceMappingURL=` 命中就把 `.map` 拉下来，能直接还原路由与参数名（比读压缩代码高效一个数量级）。
- **把发现接进覆盖矩阵**：`save` 会自动把该 app 的 recon 类目标 tested；新出现的 endpoint 会自动成为新的「资产 × 类型」格子，`pt_next` 会接着推。
- 别把 JS 里的字符串当接口：命中后先用 HEAD/GET 验一次存在性，404 的用 `pt_coverage mark state=na` 记掉，别留在 `tested` 里充数。
## 3.11 扫描器桥接：nuclei → 矩阵

模板扫一遍，把"扫过的类目"变成覆盖记录，人只处理剩下的空白：

```bash
nuclei -u https://target -json -o nuclei.jsonl
pt_nuclei action=ingest file=nuclei.jsonl          # 或 action=map 先预览
```

- 命中 → 对应「资产 × 类型」格子标 `tested`（note 写模板 id 与命中地址）+ 生成 `pt_candidate`；
- **CVE 类模板**只生成候选、不动矩阵（没有稳定的类目归属）；
- 同一 (host, template) 幂等，重复跑不会堆候选；
- 候选 ≠ 漏洞：仍需换路径独立复验，再 `pt_candidate verdict=confirmed`。
## 3.12 业务逻辑洞：不变量驱动

逻辑洞不是"发 payload"，是"验证业务规则"。流程：

1. `pt_biz action=playbook domain=<行业>` 取清单（电商/SaaS/金融/社区）；
2. `pt_biz action=model` 记下本目标的角色/实体/规则原话（从定价页、会员条款、结算流程里抄）；
3. 挑适用的不变量 `pt_biz action=invariant items=[...]`；
4. 用 `pt_biz action=mutate` 把真实请求变异成金额/数量/币种/重复参数/换方法/并发重放变体，逐条打；
5. `pt_biz action=test state=violated|holds|inconclusive evidence=...`——**violated 必须有回显**。

约束：`pt_next` 会把未验证的不变量推到决策里；`violated` 会自动把对应矩阵格子标 tested，所以不要为了刷覆盖乱判 violated，否则等于自己伪造证据。
## 3.13 资产发现：静态 / sourcemap / HAR

```bash
pt_recon action=save url=https://target/     # 页面 + 同源 bundle + 动态 chunk + sourcemap 源码
pt_recon action=import file=target.har       # 浏览器导出 HAR：登录后的全量请求
```

- 递归：跟 `import('...')` 与 `*.js` 字面量（`depth` 默认 2、`maxScripts` 默认 40）；
- sourcemap：命中 `sourceMappingURL` 就拉 `.map`，把 `sourcesContent` 当源码再挖一遍；
- HAR：path 去重 + method 归并 + query/body 字段变参数 + 鉴权头记 hint；
- 都不执行 JS：真运行时（XHR、WS、GraphQL）只能靠浏览器 + HAR 补。
## 4. 串行链：用断言钉住依赖

真攻击链有前后依赖，别并行下发：

```
pt_chain_plan title="demo.test 从上传到 RCE" host=demo.test steps=[
  {title:"确认上传点可写", post:["fact:upload-writable"]},
  {title:"带外确认命令执行", pre:["fact:upload-writable"], post:["oob:oob-3"]},
  {title:"落 shell 取凭据", pre:["oob:oob-3"], post:["cred:demo.test"]},
  {title:"凭据横向到 10.0.0.23", pre:["cred:demo.test"], post:["fact:lateral-10.0.0.23"]}
]

pt_chain_advance chainId=chain-1 ord=1 evidence="curl -F file=@a.php /upload -> 200 /u/a.php"
```

后置断言不成立 → 返回 `missing` 且不推进；确实走不通才 `force=true`（记为 `unverified`，报告里会单列）。**ready 由断言算，不按序号排**。

## 5. 盲漏洞：先有探测点，再谈结论

```
pt_oob_new kind=http note="盲 SSRF：url 参数"
pt_oob_payload id=oob-3 family=ssrf        # 也可 xxe/rce/sqli/jndi/log4j
# 把 payload 放进真实请求
pt_oob_poll id=oob-3 waitMs=3000
```

有回连 → `pt_fact_add confidence=observed`（label 建议 `oob-hit:<id>`），链上用 `oob:<id>` 断言，随后才 `pt_candidate verdict=confirmed` 或 `pt_finding add`。没回连只能说"未观测到回连"。

> 远程目标的回连可达性：`oob.bindHost` 需 `0.0.0.0`，`oob.publicHost` 填目标可达地址（LAN IP / 隧道域名 / NAT 映射）。**这一步没配好，会把"回连不到"误判成"没有漏洞"。**

## 6. 被拦：换变体，不重发

```
pt_defense action=note host=demo.test waf=cloudflare blockedSignature="403 + cf-ray" blockedFamilies=["sqli"]
pt_defense action=matrix family=sql waf=cloudflare base="1' UNION SELECT 1--"
```

## 7. 候选 → 已确认

```
pt_candidate action=add host=demo.test title="Apache 2.4.49 路径穿越" source=cve cve=CVE-2021-41773
pt_candidate action=verdict id=cand-2 verdict=confirmed evidence="--path-as-is /cgi-bin/.%2e/.%2e/etc/passwd -> root:x:0:0" oobId=oob-3
```

无证据的 `confirmed` 会被拒（`refuted` 要写依据）。

## 8. 收尾

```
pt_next                     # 确认 decision=converge
pt_evidence_save name=poc-upload-rce content="<完整请求/响应>" note="<采集方式>"
pt_mission action=prove evidence="拿到 demo.test 管理员权限：/api/v1/users 全量泄露 + admin token 复用成功；证据 sha256 50d1…"
pt_mission action=report    # 生成 Markdown：漏洞/链路/覆盖/未验证/证据索引
```

**结论不超证据**：没复现的写"未确认"，`force` 跳过的步骤报告里单列为"未验证"，候选没定论就留着。

## 9. 换 harness 也能接着跑

同一套状态，三种入口：

```bash
# CLI（任何 shell / agent harness）
node bin/artex-ops.mjs next
node bin/artex-ops.mjs intent add --summary "测 /api 的 IDOR" --summary "测上传绕过"
node bin/artex-ops.mjs fact --label upload-writable --summary "..." --evidence "curl ... -> 200"
node bin/artex-ops.mjs report

# MCP（Claude Desktop / Cursor / Codex / DSH 的 dsh-mcp-client 都吃）
node bin/artex-ops-mcp.mjs      # stdio JSON-RPC，工具名与插件一致
```

所以「对话里让我用 ARTEX 方法测」和「把这条链交给另一个 agent 继续」用的是同一份状态与同一套纪律。

## 10. 自检清单（收尾前逐条）

- `pt_next` 的 `gates` 里 `openIntents=0`、`readySteps=0`、`untestedAssets=0`、`pendingCandidates=0`
- 每条已确认漏洞都能在 `pt_mission action=report` 的证据索引里找到 sha256
- 用了 `force` 的步骤在报告"未验证"段落里出现
- 扫过 WAF 的主机都有 `pt_defense` 记录
- 凭据都在 `pt_cred action=list`（掩码）里，不靠对话记忆
