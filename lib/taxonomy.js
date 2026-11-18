// Vulnerable-class taxonomy: the checklist that makes "覆盖到位" computable.
//
// Each class carries the asset types it applies to and a one-line testing hint, so
// coverage can be computed per (asset × class) cell instead of relying on the model
// remembering to try SSRF after it got excited about SQLi. `pt_coverage` reads this
// table; `pt_next` refuses to converge while in-scope cells are still untested.
//
// Fields: id, name(zh), cat, appliesTo[], hint
// Categories are ordered roughly by "cheap to test / high signal first" so the
// suggested next cells start with the ones that pay off earliest.

export const CATEGORIES = {
  recon: '暴露面与信息泄露',
  auth: '认证与会话',
  access: '授权与越权',
  injection: '注入类',
  file: '文件与路径',
  client: '客户端与浏览器',
  logic: '业务逻辑与并发',
  api: '接口与协议',
  infra: '基础设施与配置',
  iot: 'IoT / 移动端',
}

const WEB = ['app', 'endpoint']
const SERVICE = ['app', 'endpoint', 'service']
const HOSTISH = ['app', 'endpoint', 'service', 'host', 'subdomain', 'ip']
const ANY = ['app', 'endpoint', 'service', 'host', 'subdomain', 'ip', 'root_domain']

/** [id, name, cat, appliesTo, hint] */
const RAW = [
  // ── recon / 暴露面 ────────────────────────────────────────────────────────
  ['vcs-exposure', '.git/.svn/备份文件暴露', 'recon', WEB, 'GET /.git/config、/.svn/entries、/www.zip、/backup.sql；对照 404 基线判真假'],
  ['swagger-exposure', '接口文档/调试端点暴露', 'recon', WEB, '/swagger-ui、/v2/api-docs、/openapi.json、/graphql?introspection；拿到接口面就等于拿到攻击面'],
  ['exposed-panel', '管理/监控面板暴露', 'recon', WEB, '/admin、/actuator、/debug、/console、/phpmyadmin、/manager/html'],
  ['verbose-error', '报错信息泄露', 'recon', WEB, '畸形参数/非法类型触发 500，看栈、路径、SQL 片段、内网地址'],
  ['secrets-in-js', '前端产物里的密钥/内网地址', 'recon', WEB, '抓 JS chunk，grep apiKey/secret/token/internal host；再拿这些去试签名/接口'],
  ['security-headers', '安全响应头缺失', 'recon', WEB, 'HSTS/CSP/X-Frame-Options/Referrer-Policy；缺失本身可作为低危并提示点击劫持风险'],
  ['cookie-flags', 'Cookie 安全属性', 'recon', WEB, 'Set-Cookie 是否 HttpOnly/Secure/SameSite；会话 cookie 缺 HttpOnly 直接升级为可利用链'],
  ['directory-listing', '目录列举', 'recon', WEB, '常见 /static/、/uploads/、/files/；能列目录就可能直接拿到上传物或备份'],

  // ── 认证与会话 ────────────────────────────────────────────────────────────
  ['auth-bypass', '认证绕过', 'auth', WEB, '路径大小写//、分号、%2e、X-Forwarded-For、X-Original-URL、重复 Cookie、空密码、数组型参数'],
  ['default-creds', '默认/弱口令', 'auth', SERVICE, 'admin/admin、admin/123456、产品文档默认口令；小字典即可，不爆破'],
  ['jwt-attacks', 'JWT 缺陷', 'auth', WEB, 'alg=none、HS256 弱密钥、kid 注入、jku/x5u 指向自建、过期校验缺失'],
  ['session-flaws', '会话缺陷', 'auth', WEB, '注销不失效、会话固定、cookie 里放 role/tenant 等可篡改字段'],
  ['password-reset-flaw', '找回密码逻辑', 'auth', WEB, 'token 可预测/不过期/不绑定用户、Host 头投毒、响应里回显 token'],
  ['mfa-bypass', 'MFA 绕过', 'auth', WEB, '直接访问后置接口、响应篡改 mfa=false、验证码复用/无限重试、备用码枚举'],
  ['rate-limit-missing', '登录/敏感接口无频控', 'auth', WEB, '对登录、发码、查询做低频重复（≤5 次），确认是否存在锁定/限速'],

  // ── 授权与越权 ────────────────────────────────────────────────────────────
  ['idor-bola', 'IDOR / 对象级越权', 'access', WEB, '换 id/uuid/orderNo 访问他人资源；用两个身份对照，避免把"本来公开"误判'],
  ['bfla', '功能级越权', 'access', WEB, '低权身份直接调管理接口（/admin/*、/internal/*），看是否只靠前端隐藏'],
  ['forced-browsing', '未授权访问/强制浏览', 'access', WEB, '去掉鉴权头直接访问、直连后端端口、猜 /api/internal、/actuator/env'],
  ['mass-assignment', '批量赋值', 'access', WEB, '提交 role/isAdmin/tenantId/balance 等未声明字段，看是否被写库'],
  ['tenant-isolation', '多租户隔离缺失', 'access', WEB, '切换 tenant/org/company 标识访问他人数据；SaaS 头号风险'],

  // ── 注入 ─────────────────────────────────────────────────────────────────
  ['sqli', 'SQL 注入', 'injection', SERVICE, "' and 1=1-- / 1=2 对比；报错、布尔、时间三种；带外用 pt_oob_payload family=sqli"],
  ['nosqli', 'NoSQL 注入', 'injection', SERVICE, '{"$ne":null}、{"$gt":""}、数组型参数、$where；Mongo 后端常见'],
  ['cmdi', '命令注入', 'injection', SERVICE, ';id、|id、$(id)、`id`、%0a；无回显走 OAST（rce payload）'],
  ['ssti', '模板注入', 'injection', SERVICE, '{{7*7}}、${7*7}、<%= 7*7 %>、#{7*7}；命中后按引擎找 RCE 链'],
  ['xxe', 'XXE', 'injection', SERVICE, '外部实体回连、参数实体、XInclude；SVG/DOCX/SOAP 都是入口'],
  ['ssrf', 'SSRF', 'injection', SERVICE, 'url/uri/path/webhook 参数；先打 pt_oob_new，再试 127.0.0.1/169.254.169.254/内网段'],
  ['xpath-injection', 'XPath 注入', 'injection', SERVICE, "') or 1=1 or ('a'='a；XML 查询型功能"],
  ['ldap-injection', 'LDAP 注入', 'injection', SERVICE, '*)(uid=*、)(|(cn=*；目录服务登录/查询'],
  ['header-injection', 'CRLF / 响应头注入', 'injection', SERVICE, '%0d%0aSet-Cookie:、%0d%0aLocation:；看是否进响应头/日志'],
  ['deserialization', '不安全反序列化', 'injection', SERVICE, 'Java(POST body ac ed 00 05)、PHP(O:)、Python pickle、.NET ViewState；先判指纹再打'],
  ['jndi-injection', 'JNDI / Log4Shell', 'injection', SERVICE, '${jndi:ldap://...}、${jndi:dns://...}；任何回显/日志的输入点都值得试'],

  // ── 文件与路径 ────────────────────────────────────────────────────────────
  ['upload-bypass', '上传限制绕过', 'file', WEB, '扩展名大小写/.php5/.phtml、Content-Type、双扩展、.htaccess、图片马；回读确认是否解析'],
  ['path-traversal', '路径穿越', 'file', WEB, '../../etc/passwd、..%2f、双重编码、绝对路径、Windows ..\\'],
  ['lfi', '本地文件包含', 'file', WEB, '?file=../../etc/passwd、php://filter/convert.base64-encode/resource=index'],
  ['backup-file', '源码/备份文件', 'file', WEB, 'index.php~、index.php.bak、.index.php.swp、app.zip、db.sql'],

  // ── 客户端 ───────────────────────────────────────────────────────────────
  ['xss-reflected', '反射型 XSS', 'client', WEB, '参数回显进 HTML/属性/JS/URL；按上下文选 payload，注意 CSP'],
  ['xss-stored', '存储型 XSS', 'client', WEB, '评论/昵称/工单/文件名；回显点可能在另一个角色的页面上'],
  ['xss-dom', 'DOM XSS', 'client', WEB, 'location.hash/search → innerHTML/eval；用浏览器看 sink，不只看服务端响应'],
  ['csrf', 'CSRF', 'client', WEB, '敏感操作是否校验 token/Origin/SameSite；GET 改状态要重点看'],
  ['open-redirect', '开放重定向', 'client', WEB, 'redirect/next/returnUrl=//evil；常与 OAuth 组合成 token 窃取'],
  ['cors-misconfig', 'CORS 配置错误', 'client', WEB, 'Origin 反射 + credentials:true；用它跨站读接口数据'],
  ['clickjacking', '点击劫持', 'client', WEB, '缺 X-Frame-Options/CSP frame-ancestors 且页面有敏感操作'],
  ['prototype-pollution', '原型链污染', 'client', SERVICE, '__proto__/constructor.prototype 注入；Node 服务端与前端库都可能'],
  ['postmessage', 'postMessage 不安全', 'client', WEB, '监听 message 无 origin 校验、或向 * 发送敏感数据'],

  // ── 业务逻辑与并发 ────────────────────────────────────────────────────────
  ['race-condition', '竞态条件', 'logic', WEB, '同一请求并发 20 次：领券/兑换/转账/签到；看是否超额或重复成功'],
  ['price-tamper', '价格/数量篡改', 'logic', WEB, '改 price/amount/count 为负或 0，或前端价与后端价不一致'],
  ['workflow-bypass', '流程绕过', 'logic', WEB, '跳过步骤直接调最终接口、状态机倒退、审批接口可重放'],
  ['enumeration', '用户/资源枚举', 'logic', WEB, '登录/注册/找回的响应差异、耗时差异、状态码差异'],
  ['otp-bruteforce', '验证码/OTP 可爆破', 'logic', WEB, '4-6 位无频控即可爆破；先确认无锁定再动手（低频验证）'],

  // ── 接口与协议 ────────────────────────────────────────────────────────────
  ['graphql-abuse', 'GraphQL 滥用', 'api', WEB, 'introspection、批量查询绕过限流、嵌套查询 DoS、字段级越权'],
  ['websocket-authz', 'WebSocket 鉴权缺失', 'api', WEB, '握手只校验 cookie 但消息不看权限；订阅他人频道'],
  ['http-smuggling', 'HTTP 请求走私', 'api', SERVICE, 'CL/TE 冲突、TE 混淆；需要前后端解析差异，慎用（低频）'],
  ['host-header', 'Host 头攻击', 'api', WEB, '改 Host/X-Forwarded-Host 看是否进重置链接、缓存键、路由'],
  ['cache-poisoning', '缓存投毒/欺骗', 'api', WEB, '未键控头（X-Forwarded-Host）注入响应；先确认缓存层存在'],
  ['method-tampering', 'HTTP 方法篡改', 'api', WEB, 'PUT/DELETE/PATCH 是否有鉴权；OPTIONS 泄露允许方法'],
  ['api-old-version', '旧版本/影子接口', 'api', WEB, '/v1 vs /v2、/api vs /internal、移动端专用接口鉴权更松'],
  ['excessive-exposure', '过度数据暴露', 'api', WEB, '响应里多给的字段（password hash/token/internal id）；能直接用于下一步'],

  // ── 基础设施与配置 ────────────────────────────────────────────────────────
  ['tls-weak', 'TLS/证书问题', 'infra', HOSTISH, '过期/自签/弱套件/不支持 HSTS；也可作为中间人前置条件'],
  ['open-datastore', '数据存储未授权', 'infra', ['ip', 'host', 'service'], '6379 redis、27017 mongo、9200 es、3306/5432 弱口令或空口令'],
  ['container-api', '容器/编排 API 暴露', 'infra', ['ip', 'host', 'service'], '2375 docker、10250 kubelet、6443 api-server、/var/run 挂载'],
  ['cloud-metadata', '云元数据可达', 'infra', SERVICE, '169.254.169.254/latest/meta-data、100.100.100.200（阿里云）；配合 SSRF'],

  // ── IoT / 移动端 ─────────────────────────────────────────────────────────
  ['mqtt-anon', 'MQTT 匿名/越权', 'iot', ['service', 'host', 'app'], '1883/8883 匿名连接、主题通配订阅、跨设备 publish 权限'],
  ['iot-default-creds', 'IoT 设备默认口令', 'iot', ['service', 'host', 'ip'], '摄像头/路由/摄像头 SDK 默认口令、未鉴权配置页'],
  ['apk-exported', 'APK 导出组件/明文存储', 'iot', ['app'], 'exported=true 的 Activity/Receiver、SharedPreferences 明文、硬编码密钥'],
]

export const CLASSES = RAW.map(([id, name, cat, appliesTo, hint]) => ({ id, name, cat, appliesTo, hint }))

export const CLASS_BY_ID = new Map(CLASSES.map((item) => [item.id, item]))

/** Classes applicable to one asset type, in a stable order. */
export function classesFor(assetType) {
  return CLASSES.filter((item) => item.appliesTo.includes(assetType))
}

export const COVERAGE_STATES = ['untested', 'testing', 'tested', 'na']
