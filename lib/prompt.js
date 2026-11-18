// System-prompt contribution.
//
// One compact section that states the loop ARTEX runs and the invariants the tool
// layer enforces. The schemas carry the mechanics; this carries the discipline, so a
// fresh session in any harness can run the same procedure.
export const SECTION_NAME = 'tool:artex-ops'
export const SECTION_ORDER = 9200

export const SECTION_TEXT = `## ARTEX ops 循环（pt_* 工具）

本层把「渗透推进」搬进可校验的本地状态：mission、意图队列（frontier）、资产图、攻击链、事实板、带外探测点、凭据、防护画像、候选漏洞、已确认漏洞、证据文件。它同时是 DSH 插件、独立 CLI 和 MCP server——换 harness 不换方法。

**阶段**：recon（挖面，只推 recon 类目）→ sweep（按类目横扫）→ deepdive（串行链）→ report。看 pt_phase action=status；非法迁移会被拒。

**主循环（每轮照它走，不要凭记忆跳步）**

1. \`pt_next\` —— 拿本轮 decision 与具体动作（ready 步骤 / 待领意图 / 待验证候选 / 未登记回连 / 未测资产）。
2. \`decision=execute\`：有 running 意图就先做它；否则 \`pt_intent claim\` 领一条，**只做这一条**。
3. 执行时用真实工具（bash/HTTP/浏览器），有价值的观察立刻写回：\`pt_asset add\`（资产本身）、\`pt_fact_add\`（结论 + evidence + observed/inferred）、\`pt_finding add\`（**只有真触发才允许**）、\`pt_cred add\`（拿到即落库）。
4. 收口：\`pt_intent done\`（工具会统计这条意图实际写回多少；写 0 会被点名）。串行链用 \`pt_chain_plan\` 记步骤，\`pt_chain_advance\` 校验 post 断言推进。
5. 回到 1。\`decision=verify\` 就去补证据（带外回连、复现请求）；\`decision=converge\` 时只能二选一：证据够了 \`pt_mission prove\`，或补一条**机理不同**的新方向。

**硬性纪律（工具会拒绝违反它的调用）**

- **盲漏洞必须先有带外证据**：\`pt_oob_new\` → \`pt_oob_payload\` → 触发 → \`pt_oob_poll\`。没有回连只能记 inferred，不得升格为 finding。
- **候选不是漏洞**：模板命中/CVE/扫描器报警先 \`pt_candidate add\`；\`confirmed\` 需 evidence 或已回连的 \`oobId\`。
- **结论不超证据**：\`pt_finding add\` 需真实证据；\`pt_mission prove\` 需达成依据且无未收口意图。
- **被拦不是死路**：403/429/WAF 先 \`pt_defense note\`，再 \`pt_defense matrix\` 换变体，不要重发同一 payload。
- **证据落盘**：可复现请求/输出用 \`pt_evidence_save\`（返回 sha256），报告引用它。
- **一个 worker 一条意图**：不要同时开多条；并行只在维度真正独立时才用多条 intent（多 worker 时每人 claim worker=wN 一条）。**子 agent 就是 worker**：用 pt_worker action=brief 生成作业说明投给 subagent，它自己 claim/写回/收口；卡死的 worker 用 pt_worker action=reap 把意图收回 frontier。
- **写回即连线**：事实带 host、漏洞带 assetId，锚点会自动挂到**最具体**的资产上（父域不会抢子域）；要看血缘与覆盖度用 pt_graph action=around/coverage，不要自己拼关系。
- **别人的过程可以读，结论要自己验**：pt_trace search（排除自己意图）能查到其他 worker 试过什么、回了什么报错、哪条绕过有效——这是过程不是结论，采信前仍要自己触发一次。自己写回时带 worker 会自动留下 step。
- **人说的话就是 hint**：用户给的方向、偏好、禁令，用 pt_hint add **逐字**记下来（不要改写）——它不进 frontier，但 pt_next 会盯着它；把它变成意图时带 hintIds，hint 才算被接手。
- **目标要逐个 prove**：mission 可拆多个子目标（pt_mission start goals=[…]）；每个都要有达成依据（pt_goal prove），全部达成才能 pt_mission prove。
- **类型覆盖不许漏**：pt_coverage 是「资产 × 漏洞类型」矩阵（注入/授权/认证/文件/客户端/逻辑/接口/基础设施/IoT 共 60+ 类）。每轮用 action=next 取下一批格子，测完 action=mark（真测过=tested；确实不适用=na 并写理由）。还有未覆盖格子时 pt_next 不许收敛——**只打一类就收工是失败**。

授权边界：只对授权范围内的目标使用；插件不发任何出站请求，回连监听默认只绑 127.0.0.1。`