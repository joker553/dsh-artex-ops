#!/usr/bin/env node
// 提交前敏感信息自检：扫描本次暂存（git diff --cached）的文件内容。
//
// 目标只有一个：别把 token / 私钥 / 真实口令 / 本地状态（state.json、secrets/、evidence/）
// 提交进仓库。命中即失败，并打印"文件:行号 + 掩码后的片段"。
//
// 放行规则（避免测试夹具里的假值反复挡路）：
//   • 文件里含 `secret-scan: allow-file` 的，跳过该文件；
//   • 命中值本身含有 lab / fake / example / dummy / placeholder / test 字样，视为演示值放行。
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'

const BINARY_EXT = /\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|tar|7z|exe|dll|so|dylib|woff2?|ttf|mp4|sqlite|db)$/i

const PATTERNS = [
  ['github-token', /\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/],
  ['aws-access-key', /\bAKIA[0-9A-Z]{16}\b/],
  ['private-key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['slack-token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ['openai-key', /\bsk-[A-Za-z0-9]{32,}\b/],
  ['bearer-token', /\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._-]{20,}/i],
  ['literal-credential', /\b(password|passwd|secret|token|api[_-]?key)\b\s*[:=]\s*['"`][^'"`\s]{6,}['"`]/i],
  ['cookie-session', /\bset-cookie\s*:\s*[a-z0-9_.-]+=[^;'"\s]{8,}/i],
]

const ALLOW_VALUE = /lab|fake|example|dummy|placeholder|sample|test/i

function stagedFiles() {
  const out = execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACM'], { encoding: 'utf8' })
  return out.split(/\r?\n/).filter(Boolean)
}

function mask(line) {
  return line.replace(/([A-Za-z0-9_-]{6})[A-Za-z0-9_.\-]{6,}/g, '$1***').slice(0, 160)
}

const problems = []
for (const file of stagedFiles()) {
  if (BINARY_EXT.test(file)) continue
  let content
  try {
    content = fs.readFileSync(file, 'utf8')
  } catch {
    continue
  }
  // 豁免只对 test/ 下的夹具生效：生产代码里加这行不算数
  if (file.startsWith('test/') && content.includes('secret-scan: allow-file')) continue
  const lines = content.split(/\r?\n/)
  lines.forEach((line, index) => {
    for (const [name, pattern] of PATTERNS) {
      const match = line.match(pattern)
      if (!match) continue
      if (ALLOW_VALUE.test(match[0])) continue
      problems.push({ file, line: index + 1, name, snippet: mask(line.trim()) })
    }
  })
  // 本地状态/证据不该进仓库
  if (/(^|\/)(state\.json|secrets|evidence|missions|oob)\//.test(file) || /API-KEYS|\.credentials/.test(file)) {
    problems.push({ file, line: 0, name: 'local-state', snippet: '本地状态/凭据/证据文件不应提交' })
  }
}

if (problems.length === 0) {
  console.log(`secret-scan: 通过（检查了 ${stagedFiles().length} 个暂存文件）`)
  process.exit(0)
}

console.error('secret-scan: 发现可疑敏感信息，已阻止提交：')
for (const item of problems) {
  console.error(`  [${item.name}] ${item.file}:${item.line}  ${item.snippet}`)
}
console.error('处理方式：删除/替换成占位符；确有需要的测试夹具请加注释 `secret-scan: allow-file` 或把值改成含 lab/fake 的演示值。')
process.exit(1)
