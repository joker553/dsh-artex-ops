# dsh-artex-ops

> ⚠️ **仅限授权使用 / Authorized use only**
> 本工具面向**已获得书面授权的渗透测试、红队演练、CTF 与自有靶场**。请勿用于任何未授权的系统。
> 使用者须自行确认授权范围与当地法律，并承担全部使用后果；作者不提供任何担保，也不对使用本工具造成的任何后果负责。
> 详见文末 [免责声明与使用条款](#免责声明与使用条款)。

把 **ARTEX 那套「规划者出意图 → 执行者做一条 → 写回图谱 → 再规划」** 做成可移植的状态层：一个 Cordis 插件（DeepSeekRuntime）、一个独立 CLI、一个 MCP server，共用同一份引擎与同一份磁盘状态。

- **可移植**：纯 `node:*` 内置模块，零第三方依赖；`node install.mjs` 在任意装了 DSH 的机器上一键挂载；换 harness（任何 MCP 客户端 / 任意 shell agent）读同一份 `state.json` 接着跑。
- **对话即测试**：`pt_next` 把「本轮该干什么」算成程序结论（不是模型自由发挥），`pt_intent claim/done` 一次一条意图，盲漏洞必须 `pt_oob_new/poll` 拿到回连，结论不够证据的调用会被工具直接拒绝。

## 从 GitHub 安装

```bash
git clone https://github.com/joker553/dsh-artex-ops.git
cd dsh-artex-ops
node install.mjs                 # 自动探测 DSH home / profile，装包 + 挂 bundles + 写 patch + 装技能
```

改完 `lib/` 不用重启 DeepSeekRuntime：宿主外壳会重启实现子进程并按 catalog 差量重注册工具。
## 三种用法（同一引擎）

| 形态 | 入口 | 适用 |
|---|---|---|
| **DSH 插件** | `node install.mjs` → 重启/热重组 | 在 DeepSeekRuntime 对话里直接用 `pt_*` 工具 |
| **CLI** | `node bin/artex-ops.mjs <cmd>` | 任意 shell / 任意 agent harness；脚本化、可 cron、可 CI |
| **MCP server** | `node bin/artex-ops-mcp.mjs`（stdio JSON-RPC） | Claude Desktop / Cursor / Codex / DSH 的 `dsh-mcp-client` |

状态落在 `~/.dsh/artex-ops`（`ARTEX_OPS_HOME` 或 `--data`/`config.dataDir` 可覆盖），三种形态互认，**换入口不换进度**。

## 安装

```bash
# 任意机器（Node 20+，已装 DSH）
node install.mjs                                   # 自动探测 DSH home 与 profile（desktop/web/headless/tui）
node install.mjs --profile web --link              # 指定 profile，做软链接（改源码即生效）
node install.mjs --data D:/ops-data --dry-run      # 自定义数据目录，只看计划不落盘
node install.mjs --uninstall                       # 卸载（保留数据目录）
```

它只做四件事，且都会先备份：拷包到 `<dshHome>/plugins/dsh-artex-ops`、在 profile 的 `node_modules` 里放置副本/软链、改 `package.json`（dependency + `dsh.profile.bundles`）、在 `cordis.patch.yml` 写一个带 `>>> dsh-artex-ops managed block <<<` 标记的 insert 块（重跑幂等，不会出现两份 insert）。技能 `artex-ops` 同步到 `<dshHome>/skills`。

> 插件代码改动需要宿主重启才生效（ESM 模块缓存）；只改配置/patch 由 `dsh-hmr` 热重组。首次安装时若宿主已在运行，一次重启即可。

## 25 个工具

**循环骨架（ARTEX 本体）**

| 工具 | 作用 | 硬约束 |
|---|---|---|
| `pt_next` | 本轮该干什么：decision + 具体动作（带工具名与参数） | 由状态机算，不靠模型自觉 |
| `pt_mission` | start/state/prove/report/stop：目标、范围、约束、达成依据、报告 | `prove` 需证据，且有未收口意图会被拒 |
| `pt_intent` | add/claim/done/list：意图队列，一次一条 | `claim` 已有 running 时返回同一条；`done` 统计真实写回量，0 写回被点名 |
| `pt_asset` | add/list/mark：资产真值库（7 类节点 + 属性 + 已测标记） | 覆盖度进 `pt_next` 判定 |
| `pt_finding` | add/list/state：**已确认**漏洞（severity + evidence） | 无证据拒收；可疑一律走候选队列 |
| `pt_trace` | add/search/get/list：worker 间的**过程级**交换（试了什么、回了什么，含死路与报错） | `search` 必填 `q`；`excludeIntent` 排除自己那条；写回带 `worker` 自动留 step |
| `pt_worker` | brief（生成可投给 subagent 的作业说明）/ status（谁领了哪条、几步、静默多久）/ reap（僵尸 worker 的意图放回 frontier） | 子 agent 即 worker；reap 只动 `running` |
| `pt_graph` | nodes/coverage/edges/anchors/around：双图查询——资产包含边、探索血缘、锚点、覆盖度（分母=授权范围） | 只读；`around` 需 assetId 或 node |
| `pt_hint` | add/list/address：**用户原话**即 hint 节点（不进 frontier，进 `pt_next`；文本提到的资产自动挂锚点） | 派意图时 `hintIds` 才算出它被接手 |
| `pt_goal` | add/list/prove：把目标拆成多个可独立验收的子目标，逐个 prove | 未全部达成时 `pt_mission prove` 被拒（单条 derived 目标可用 mission 证据结清） |
| `pt_coverage` | taxonomy/matrix/next/stats/mark：**资产 × 漏洞类型**矩阵（10 类目 / 64 类型），每格可 tested/na/testing | 有未覆盖格子时 `pt_next` 不许收敛；`na` 必须写理由 |

**攻击链 / 事实**

| 工具 | 作用 | 硬约束 |
|---|---|---|
| `pt_chain_plan` | 建/改攻击链（≤24 步，每步 pre/post 断言） | 同名步骤重规划保留已完成状态 |
| `pt_chain_advance` | 推进下一步并校验 post | 断言不成立返回 `missing` 且不推进；`force` 只记 `unverified` |
| `pt_fact_add` / `pt_fact_list` | 事实板（label + evidence + observed/inferred） | 同 label 合并 |
| `pt_evidence_save` | 证据落盘 + sha256 | 正文非空 |

**带外 / 身份 / 防护 / 候选**

| 工具 | 作用 | 硬约束 |
|---|---|---|
| `pt_oob_new` / `pt_oob_poll` / `pt_oob_payload` | 探测点、回连、8 族即用 payload | 回连自动归属；未监听协议在 note 标明 |
| `pt_cred` | add/list/show：口令/cookie/JWT/sshkey/hash/token | 列表只回掩码，明文仅 `show` |
| `pt_defense` | note/list/matrix：WAF 画像 + 6 族变体（按 WAF 排序） | 同 payload 别重发 |
| `pt_candidate` | add/list/verdict：候选漏洞队列 | `confirmed` 需 evidence 或已回连 `oobId` |

链断言语法：`fact:<label>`、`oob:<id|token>`、`cred:<host>`、`defense:<host>`、`candidate:<id>:confirmed`，前缀 `!` 表示要求不存在。

## 与 ARTEX 的对应关系（架构映射）

| ARTEX（Go 版） | 这里（插件/CLI/MCP） | 落地方式 |
|---|---|---|
| `explorations` + `exploration_nodes/edges` | `mission` + `intents` + `chains` | 一次 mission 一条推进线；intent 是 frontier；chain 是串行依赖 |
| `assets`（全局共享真值） | `assets` | 7 类节点 + `props` + `tested`；覆盖度进 `pt_next` |
| `planner`（事件驱动、共享 todolist） | `pt_next` + chain `pre/post` 断言 | 决策由纯函数算（含硬底线）；链进度由断言求值，不靠模型自觉 |
| `worker` 领一条意图、写回即停 | `pt_intent claim --worker wN` / `done` | 一人一条 running；`done` 结算写回量 |
| `activity`（过程库，每步一条） | `activity` + `pt_trace` | 每步带 `worker/intentId/seq/kind/summary/detail` |
| `search_all_worker_traces(q)` | `pt_trace search q --exclude-intent <自己>` | 关键字搜 summary+detail，命中带 intentId，自动排除自己 |
| `list_worker_traces` / `get_worker_trace(intent_id, step_ids)` | `pt_trace list` / `pt_trace get` | 先看谁跑过，再取某条意图的步骤全文 |
| `WriteCounts`（facts/assets/findings 分计） | `intent.writes` | 按 activity 归属统计，多 worker 不串账 |
| `prove_goal` 逐个达成 → 任务收口 | `pt_mission prove` | 需证据；有未收口 intent 会被拒 |
| `findings` + 流量证据 | `pt_finding` + `pt_candidate` + `pt_evidence_save` | 候选/确认分离；确认需真实证据或已回连 OOB；证据落盘带 sha256 |
| `exploration_edges`（spawns/derived_from/yields/proves） | `edges[]` | 写回时自动连：`intent —yields→ fact`、`intent —proves→ finding`；资产侧 `asset —contains→ asset` |
| `exploration_anchors(node_id, asset_id)` | `anchors[]` | 事实按 host → 最具体资产（精确>后缀>包含）；漏洞按 assetId；于是"方向↔资产"双向可查 |
| 覆盖度（范围内资产 + 已测高亮） | `pt_graph action=coverage` | 分母=授权范围内资产；已测=标记过 **或** 被事实/漏洞锚定过 |

### 双图与锚点：怎么落地

```
资产图（全局真值）                            探索图（本任务推进）
root_domain demo.test                       intent-4 ──yields──▶ fact-8
   └─contains─ subdomain api.demo.test      intent-4 ──proves──▶ finding-16
        └─contains─ endpoint /api/v1/users
                    ▲                              │
                    └────── anchors ───────────────┘
                    finding:16 → asset(endpoint)   fact:8 → asset(subdomain)
```

- **父子由程序算**：`pt_asset add` 只交 `type/name/host`，`inferParentId()` 按"子域挂根域、服务/端点挂同 host 的 app/host"补 `parentId` 并连 `contains` 边；显式 `parentId` 优先。
- **锚点自动挂**：`pt_fact_add` 用 `host` 反查资产（**精确 > 后缀 > 包含**，避免 `api.demo.test` 被父域 `demo.test` 抢走），`pt_finding` 用 `assetId`。锚点即"这条结论落在哪台资产上"。
- **双向可查**：`pt_graph action=around assetId=<端点>` 看它被哪些节点锚过、父是谁、子是谁；`around node=intent:4` 看它产出了什么、证出了什么。
- **覆盖度因此有了分母**：`coverage.inScope` 只算授权范围内的资产，锚定过的资产视为已测——这就是"范围内资产 + 已测高亮"的可计算版本，`pt_next` 的 `plan` 分支用的就是它。

### 多 worker 的过程级交换，具体怎么实现

1. **归属**：每条 step 写 `worker` + `intentId` + `seq`（该 worker 在该意图内的第几步）。没有归属的过程等于噪音，因此只记带 `worker` 的。
2. **写回自动留痕**：`pt_fact_add` / `pt_asset add` / `pt_finding add` / `pt_cred add` / `pt_candidate add|verdict` / `pt_chain_advance` 只要带 `worker`，就自动落一条 step（kind 分别为 `fact/asset/finding/bypass/note/dead-end`）；`intentId` 省略时取该 worker 当前 running 的意图。
3. **过程 ≠ 事实**：事实是结论（进断言、进报告）；过程是"试了什么、回了什么"，包含报错与死路。原始报错用 `pt_trace add kind=error detail="<栈/响应>"` 记，别硬塞进 fact。
4. **检索排除自己**：`pt_trace search q=<关键字> excludeIntent=<自己手上的 intent>`——不排除的话搜到的全是自己刚写的。
5. **采信边界**：别人的 step 只作线索，要自己触发一次才写 `observed` 事实，否则会出现"二手证据"污染结论。
6. **写回量按归属**：`pt_intent done` 优先用 activity 归属算 `writes`，多 worker 并行时不会把别人的写回算到自己头上；没有 activity 的旧数据回落到 baseline 差值。

## 对话式测试长什么样

```
你：用 ARTEX 方法测 http://demo.test，目标是拿到管理员权限或证明拿不到
我：pt_mission start(goal, scope, constraints)
    pt_next → decision=plan（3 个未测资产）
    pt_intent add [测 /api 鉴权, 测 /upload 校验]
    pt_intent claim → intent-5
    bash: curl -s http://demo.test/api/v1/users        ← 真实探测
    pt_fact_add(observed) + pt_asset mark(tested)
    pt_intent done → writes {facts:1}
    pt_intent claim → intent-6
    bash: 上传探针 + 访问回读                          ← 真实探测
    pt_candidate add(上传→RCE) → 回读未执行 → verdict=refuted
    pt_intent done → writes {facts:2}
    pt_finding add(未鉴权泄露, high, evidence) + pt_evidence_save
    pt_next → decision=converge → pt_mission prove + report
```

`decision=converge` 只在「没有 ready 步骤 / 没有待执行意图 / 没有未测资产 / 没有待定候选」时出现——这是 `pt_next` 给的分岔口，不是模型「觉得差不多了」。

### 本机实测（fixture，非真实目标）

`test/fixture-server.mjs` 起一个本地演示靶（`/api/v1/users` 故意无鉴权、`/upload` 接受任意扩展名但 `/u/*.php` 不解析），完整跑一遍闭环：

```bash
node test/fixture-server.mjs 18099 &
CLI="node bin/artex-ops.mjs"; D="--data $TEMP/artex-live-demo"
$CLI mission start $D --goal "拿到 http://127.0.0.1:18099 的管理员权限，或证明不可得" --scope http://127.0.0.1:18099
$CLI asset add $D --assets '[{"type":"app","name":"http://127.0.0.1:18099"},{"type":"endpoint","name":"/api/v1/users"},{"type":"endpoint","name":"/upload"}]'
$CLI next $D                 # decision=plan
$CLI intent add $D --summary "测 /api/v1/users 的鉴权" --summary "测 /upload 的校验"
$CLI intent claim $D         # → intent-5
curl -s http://127.0.0.1:18099/api/v1/users
$CLI fact $D --label demo-users-api-no-auth --summary "..." --evidence "curl ... -> 200 [...]" --confidence observed
$CLI intent done $D --id intent-5 --state done --output "确认未鉴权"
...
$CLI report $D               # Markdown：漏洞/覆盖/证据索引/达成依据
```

实测结果：`覆盖 3/3`、`intent done 2/0 blocked`、`finding high ×1`（未鉴权泄露 admin 用户）、`candidate refuted ×1`（上传可写但不解析，**没有**被报成 RCE）、证据 sha256 `53ddaf390e9f174d…`。`pt_next` 在「app 资产未测」时坚持 `plan`，补测后才放行 `converge`。

## 配置

`cordis.patch.yml` 里 `config`（或 CLI `--data`、MCP 环境变量）：

| 字段 | 默认 | 说明 |
|---|---|---|
| `enabled` | `true` | 关掉后不注册工具 |
| `dataDir` | `$ARTEX_OPS_HOME` → `$DSH_HOME/artex-ops` → `~/.dsh/artex-ops` | 状态根目录 |
| `debug` | `false` | 宿主侧诊断日志 |
| `oob.port` | `18080` | HTTP 监听；被占用自动退临时端口 |
| `oob.bindHost` | `127.0.0.1` | 远程目标回连需 `0.0.0.0` |
| `oob.publicHost` | 绑定地址（0.0.0.0 时取首个非内网 IP） | 写进 payload 的 host |
| `oob.publicPort` | 实际端口 | NAT/端口映射后的对外端口 |
| `oob.dnsDomain` | 空 | 有通配域名时用 `<token>.<domain>` |
| `oob.dns.enabled` / `port` | `false` / `53` | DNS 应答器（需权限） |

MCP 侧对应环境变量：`ARTEX_OPS_HOME`、`ARTEX_OPS_OOB_PORT`、`ARTEX_OPS_OOB_HOST`、`ARTEX_OPS_OOB_PUBLIC_HOST`。

**远程目标最容易踩的坑**：默认只绑 `127.0.0.1`。没配 `bindHost/publicHost` 时，目标回连不到你，盲漏洞会被误判成"不存在"。

## 数据布局

```
<dataDir>/
├── state.json                 # mission/intents/assets/chains/facts/oobs/creds/defense/candidates/findings/evidence 索引（原子写）
├── secrets/<cred-id>.secret   # 凭据明文
├── oob/hits.ndjson            # 每次回连的完整记录（协议/路径/来源/头/体）
└── evidence/<ts>-<slug>.txt   # 证据原文（索引里带 sha256）
```

`state.json` 损坏时改名为 `.corrupt-<ts>` 后重建，不会静默丢库。

## 自测

```bash
node test/selftest.mjs        # 84 项：schema 校验、真实回连、链断言拒绝、意图生命周期、prove 门槛、CLI、MCP 握手、多 worker 过程交换、阶段机
node test/install-check.mjs   # 安装位：patch/manifest/解析/apply 25 工具 + CLI 从安装目录可执行
node test/hot-reload.mjs      # 宿主外壳：catalog 注册、调用往返、lib 改动后重启子进程并重注册
```

## 边界

- **唯一会出站的是 `pt_recon`**（只访问你给的 URL 与它同源的 JS），其余工具零出站。
- 回连监听默认只绑 `127.0.0.1`；公网可达性、域名解析、端口映射由使用者自行配置。
- 插件不做提权/横向的实际动作，只提供状态机、payload 构造、证据链与覆盖核算。
- 使用范围、授权与合规由使用者负责。

## 下一步

| 项 | 做法 |
|---|---|
| 后渗透主机层 | `hosts` 表 + `pt_host`（注册/路由/pivot 拓扑），命令仍走宿主 shell |
| 手法记忆 | `tactics`（fingerprint → 链模板），`pt_chain_plan` 可引用模板，全链 satisfied 时沉淀 |
| 扫描器桥接 | nuclei `-json` 输出批量灌 `pt_candidate`，再由 agent 逐条真触发 |

## 许可

本项目代码以 **MIT** 发布，见 [LICENSE](LICENSE)。

架构参考了 **ARTEX**（AGPL-3.0）、**ARTEX-God**（AGPL-3.0）、**Cairn**（AGPL-3.0）与 **norma SDK**（Apache-2.0）的公开设计；**代码为本仓库独立实现（JavaScript/Node），未复制其源码**，各自许可仅约束其自身代码。若你要基于上述项目二次开发，请遵守对应许可（AGPL-3.0 要求衍生作品同样开源、网络服务须提供源码）。详见 [参考项目与出处](#6-参考项目与出处及其各自许可)。

---

# 免责声明与使用条款

> 本节是作者对使用者的**使用约定**，与 MIT 许可证并行：许可证授予你代码权利，本节界定**预期用途与责任边界**。

## 1. 允许使用范围（仅限授权）

本工具**仅**可用于下列场景，且必须事先取得**书面授权**或属于你**自有资产**：

- ✅ 已签署授权书的渗透测试 / 红队演练（授权书写明目标、时间窗、禁止操作）；
- ✅ CTF、靶场、漏洞复现环境、你本机搭建的测试服务；
- ✅ 安全产品、检测规则、Agent 编排方案的研发与自测；
- ✅ 阅读、学习、研究本项目源码（个人学习、学术研究、代码审阅）。

## 1.1 禁止事项

- ❌ 对**未授权**系统进行扫描、探测、利用或数据获取（无论是否"只是看看"）；
- ❌ 对关键信息基础设施、医疗 / 交通 / 能源 / 工控等可能危及人身安全的系统做任何测试；
- ❌ 数据窃取、勒索、破坏、拒绝服务、植入持久化等任何破坏性活动；
- ❌ 伪造授权、绕过客户约定的范围或时间窗、把测试成果用于敲诈或交易；
- ❌ 任何违反所在国家/地区法律法规的用途。

> 技术上可行 ≠ 允许执行。范围之外的任何测试，即使工具支持，也不得进行。

## 2. 工具会做什么（请事先知情）

- `pt_recon` **会向目标发起 HTTP 请求**（页面 + 同源 JS），并在本地保存抓到的内容片段；
- `pt_oob_*` 会在本机**开启回调监听**（默认 `127.0.0.1`），用于确认盲漏洞；若你把它暴露到公网，回调可能被任何来源访问；
- 工具会**在本地明文保存**凭据（`secrets/`）与证据（`evidence/`），请自行做好磁盘加密与访问控制；
- 工具会**驱动你本机的 shell**（经宿主 bash/pwsh 工具）执行你或模型生成的命令。**命令的后果由执行者承担。**

## 3. 无担保

本工具按 **"AS IS"** 提供，不附带任何明示或默示担保，包括但不限于适销性、特定用途适用性与不侵权担保。作者不保证工具无缺陷、不保证检测结果准确、不保证对任何特定目标有效。

## 4. 责任限制

在适用法律允许的最大范围内，**作者与贡献者不对任何直接、间接、偶然、特殊、惩罚性或后果性损害承担责任**，包括但不限于：数据丢失或泄露、业务中断、系统损坏、法律责任、第三方索赔、名誉或经济损失——无论其如何产生、基于何种责任理论，即使已被告知可能发生此类损害。

**你使用本工具即表示你已理解并接受：一切使用后果由你自行承担。**

## 5. 合规提示

使用者须自行遵守所在国家/地区关于网络安全、数据保护、隐私与计算机犯罪的全部法律法规（例如中国大陆的《网络安全法》《数据安全法》《个人信息保护法》《刑法》第 285/286 条等），以及目标所在司法辖区的法律。**授权范围之外的任何测试，即使技术上可行，也不得进行。**

## 6. 参考项目与出处（及其各自许可）

本项目的**架构与工程取舍**参考了下列公开项目，但**代码为本仓库独立实现（JavaScript / Node ESM），未复制其源码**：

| 项目 | 链接 | 许可 | 参考了什么 |
|---|---|---|---|
| **ARTEX** | `Autumn-27/ARTEX`（原仓库当前不可公开访问；其 README 记载为 AGPL-3.0） | **AGPL-3.0** | 核心范式：planner 出意图 / worker 领一条、双图（资产图 + 探索图）与锚点、activity 过程级交换、planner 共享 todolist 稳定串行链 |
| **ARTEX-God** | https://github.com/Xiao1an/ARTEX-God | **AGPL-3.0** | 二开增强思路（资产合集 / FOFA 同步、IoT 与 SATCOM 技能、拦截规则收紧），也是本项目对照实现的目标 |
| **Cairn** | https://github.com/oritera/Cairn | **AGPL-3.0** | 任务编排与工具层抽象的思路 |
| **norma SDK** | https://github.com/Autumn-27/norma | **Apache-2.0** | `agentcore / tool / permission / harness / memory / transcript` 的分层概念（本插件**不依赖**该 SDK，只用其分层思想） |

说明：

- 上述项目的许可**仅约束其自身代码**。本仓库不包含它们的源码、不链接其二进制，因此本仓库自身以 **MIT** 发布（见 [LICENSE](LICENSE)）。
- 若你打算基于上述项目的代码做二次开发/分发，请遵守对应许可。**AGPL-3.0 的关键义务**：衍生作品须同样以 AGPL-3.0 开源；若以网络服务形式提供，须向使用者公开对应完整源码。
- 上游 ARTEX 的条款比本项目更严格（其 README 明确"不得用于任何线上系统或网站"）。本项目**不沿用**该条款，而采用上文「仅限授权范围内使用」的框架；若你希望与上游保持完全一致的许可与条款，把根目录 `LICENSE` 替换为 AGPL-3.0 全文、并把本节与第 1 节一并调整即可。
- 若你是上述项目的作者并认为本项目的署名/引用方式需要调整，请开 issue，会立即处理。

## 7. 报告问题

若你发现本工具存在可能被滥用的缺陷、或希望收窄某项能力（如默认关闭出站、强制审批），请开 issue，作者会优先处理。
