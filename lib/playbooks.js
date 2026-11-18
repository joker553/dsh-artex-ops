// 业务逻辑洞的「不变量清单」+ 变异生成器。
//
// 逻辑洞和注入类不同：它不靠 payload 命中，而靠**业务规则被违反**。所以这里给两样东西：
//   1. 分行业的规则清单（每条规则 = 一个可证伪的不变量 + 具体验证配方 + 判定信号）；
//   2. 请求变异器（金额/数量/币种/ID/重复/并发/乱序），把"想到"变成"能试"。
//
// 行业清单是"起点"不是"全部"：真正决定成败的是把目标自己的业务规则（定价页、会员条款、
// 结算流程）抄进 pt_biz model/invariant —— 这一步必须由人或浏览器观察来补。

const numericTampers = (field, value) => {
  const base = Number.isFinite(Number(value)) ? Number(value) : 100
  return [
    ['zero', 0],
    ['negative', -Math.abs(base) || -1],
    ['tiny', 0.01],
    ['huge', 1e9],
    ['float-noise', base + 0.0001],
    ['string-number', String(base)],
    ['scientific', '1e-9'],
    ['null', null],
  ].map(([kind, mutated]) => ({ kind: `${field}:${kind}`, patch: { [field]: mutated } }))
}

export const PLAYBOOKS = {
  ecommerce: {
    name: '电商 / 交易',
    invariants: [
      {
        id: 'price-server-side',
        statement: '最终金额必须由服务端按商品与规则计算，客户端价格只作展示',
        classId: 'price-tamper',
        recipe: ['正常下单抓包', '把 price/amount/total 改成 0.01、-1、1e9', '把 currency 换成低价币种', '把 quantity 改成 0 / 负数'],
        detect: '实付金额与商品价×数量不一致，或负数导致余额增加',
      },
      {
        id: 'coupon-single-use',
        statement: '同一优惠券/积分只能核销一次，且不可与互斥活动叠加',
        classId: 'race-condition',
        recipe: ['并发提交同一券码 20 次', '券码使用后再重放原请求', '叠加两个互斥活动', '用完券再改数量重算'],
        detect: '多次核销成功、折扣叠加超过上限、余额/积分被重复累加',
      },
      {
        id: 'inventory-nonnegative',
        statement: '库存/额度不会被超卖或超发',
        classId: 'race-condition',
        recipe: ['库存=1 时并发下单', '下单不支付再下单', '退款后库存回滚再超卖'],
        detect: '成功单数 > 库存；超卖后仍能支付',
      },
      {
        id: 'order-state-machine',
        statement: '订单状态只能按既定状态机前进，不能跳步或倒退',
        classId: 'workflow-bypass',
        recipe: ['未支付直接调发货/完成接口', '已取消订单再调支付', '跳过风控/审批步骤直接进下一状态'],
        detect: '非法状态迁移被接受',
      },
    ],
  },
  saas: {
    name: 'SaaS / 多租户',
    invariants: [
      {
        id: 'tenant-isolation',
        statement: '任何资源只能被其所属租户读写',
        classId: 'tenant-isolation',
        recipe: ['A 租户 token 访问 B 租户资源 id', '把 tenantId/orgId 改成对方值', '导出/搜索接口不加租户过滤'],
        detect: '跨租户读到或写到数据',
      },
      {
        id: 'seat-limit',
        statement: '席位/配额不可通过重复邀请、并发邀请或删除重建突破',
        classId: 'workflow-bypass',
        recipe: ['并发邀请到超出套餐数', '邀请后立刻删除再邀请', '用 API 直接建成员绕过 UI 限制'],
        detect: '成员数超过套餐上限且仍可用',
      },
      {
        id: 'trial-reset',
        statement: '试用/额度不可通过改邮箱、改域名、删号重建重置',
        classId: 'enumeration',
        recipe: ['同邮箱大小写/别名(+tag)', '删除工作区重建', '换邀请链接重开'],
        detect: '试用期或免费额度被重置',
      },
      {
        id: 'role-escalation',
        statement: '成员不能给自己或他人提升到高于自身角色的权限',
        classId: 'bfla',
        recipe: ['改请求里的 role 字段', '用成员 token 调管理员接口', '邀请时指定高权限角色'],
        detect: '越级授权成功',
      },
    ],
  },
  finance: {
    name: '金融 / 支付 / 积分',
    invariants: [
      {
        id: 'balance-conservation',
        statement: '任何操作前后总账守恒（转入+转出+手续费=0）',
        classId: 'workflow-bypass',
        recipe: ['并发转账', '转账金额为负', '手续费字段篡改', '同一笔回调重放'],
        detect: '余额凭空增加或重复入账',
      },
      {
        id: 'callback-idempotent',
        statement: '支付回调必须幂等，重复通知只入账一次',
        classId: 'race-condition',
        recipe: ['重放同一回调 10 次', '改 orderNo 但保留签名', '并发回调'],
        detect: '重复入账 / 重复发货',
      },
      {
        id: 'refund-limit',
        statement: '退款总额不得超过实付，且不可重复退',
        classId: 'workflow-bypass',
        recipe: ['部分退款后再全额退', '并发退款', '退款后撤销再退'],
        detect: '退款总额 > 实付',
      },
      {
        id: 'rounding-abuse',
        statement: '金额精度与舍入不可被利用（分/厘、四舍五入方向）',
        classId: 'price-tamper',
        recipe: ['0.001 元转账多次', '汇率换算后取整', '负数尾差'],
        detect: '累计出现正收益',
      },
    ],
  },
  community: {
    name: '社区 / 内容 / 增长',
    invariants: [
      {
        id: 'like-once',
        statement: '同一用户对同一对象只能点赞/投票一次',
        classId: 'race-condition',
        recipe: ['并发点赞', '取消后立刻重赞', '换接口（Web/App/小程序）重复'],
        detect: '计数被刷高',
      },
      {
        id: 'invite-self',
        statement: '邀请/推荐不能自己邀自己或环形互邀',
        classId: 'workflow-bypass',
        recipe: ['自己邀请自己', 'A→B→A 环形', '小号批量领奖励'],
        detect: '奖励被同一人反复领取',
      },
      {
        id: 'content-moderation-bypass',
        statement: '发布内容必须经过审核，且审核后不可被绕过修改',
        classId: 'workflow-bypass',
        recipe: ['先发正常内容过审，再编辑正文', '用草稿/定时发布绕审核', '改 MIME/编码绕过检测'],
        detect: '未审核内容对外可见',
      },
      {
        id: 'rate-limit-per-identity',
        statement: '频控按真实身份而非可伪造标识（IP/设备号/UA）',
        classId: 'rate-limit-missing',
        recipe: ['换 X-Forwarded-For', '换设备号', '换 UA 连续请求'],
        detect: '频控被绕过',
      },
    ],
  },
}

/** 把一条请求模板变异成一批可执行变体（只生成描述，不直接发请求）。 */
export function mutateRequest({ method = 'POST', url = '', headers = {}, body = {} } = {}) {
  const variants = []
  const bodyObject = body && typeof body === 'object' ? body : {}
  const numericKeys = Object.keys(bodyObject).filter((key) => Number.isFinite(Number(bodyObject[key])))
  for (const key of numericKeys) {
    for (const item of numericTampers(key, bodyObject[key])) {
      variants.push({
        kind: item.kind,
        method,
        url,
        body: { ...bodyObject, ...item.patch },
        note: `数值变异：${key} → ${JSON.stringify(item.patch[key])}`,
      })
    }
  }
  // 结构化污染：重复参数、数组化、原型链
  if (numericKeys.length > 0) {
    const key = numericKeys[0]
    variants.push({ kind: 'param-pollution', method, url, body: `...&${key}=${bodyObject[key]}&${key}=0`, note: '重复参数，看服务端取第一个还是最后一个' })
    variants.push({ kind: 'array-wrap', method, url, body: { ...bodyObject, [key]: [bodyObject[key], 0] }, note: '把标量改成数组，常见类型混淆' })
  }
  variants.push({ kind: 'method-swap', method: method === 'POST' ? 'PUT' : 'POST', url, body: bodyObject, note: '换方法看鉴权/校验是否一致' })
  variants.push({ kind: 'concurrent-replay', method, url, body: bodyObject, note: '同一请求并发 20 次（验证竞态/幂等），用 xargs -P 或 for 循环' })
  variants.push({ kind: 'replay-after-state', method, url, body: bodyObject, note: '状态变更后重放原请求（验证幂等）' })
  return variants
}
