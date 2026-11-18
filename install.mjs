#!/usr/bin/env node
// Portable installer for dsh-artex-ops.
//
// Works on any machine with Node 20+ and a DSH installation: no hard-coded paths,
// no pnpm network step, no junction requirement (copy is the default; `--link` uses a
// symlink/junction when you want to edit the source in place).
//
//   node install.mjs                     # auto-detect DSH home + profile, copy, wire
//   node install.mjs --profile web       # target another profile explicitly
//   node install.mjs --link --data D:/ops-data
//   node install.mjs --dry-run           # print the plan, change nothing
//   node install.mjs --uninstall         # remove patch entry / bundle / deps / copy
//
// What it touches (all backed up with a timestamp suffix before editing):
//   <dshHome>/plugins/dsh-artex-ops              installed copy of this package
//   <profile>/node_modules/dsh-artex-ops         copy or symlink the runtime resolves
//   <profile>/package.json                       dependencies + dsh.profile.bundles
//   <profile>/cordis.patch.yml                   managed insert block (marked)
//   <dshHome>/skills/artex-ops/SKILL.md          the conversational playbook
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const PKG = 'dsh-artex-ops'
const SKILL = 'artex-ops'
const MARK_START = '# >>> dsh-artex-ops managed block (install.mjs) — 删除本块即卸载 >>>'
const MARK_END = '# <<< dsh-artex-ops <<<'

const here = path.dirname(fileURLToPath(import.meta.url))
const argv = process.argv.slice(2)

function flag(name, fallback = undefined) {
  const index = argv.indexOf(`--${name}`)
  if (index === -1) return fallback
  const next = argv[index + 1]
  return next === undefined || next.startsWith('--') ? true : next
}

const opts = {
  dshHome: path.resolve(String(flag('dsh-home') ?? process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh'))),
  profile: flag('profile'),
  dataDir: flag('data'),
  link: flag('link') === true,
  dryRun: flag('dry-run') === true,
  uninstall: flag('uninstall') === true,
}

function log(message) {
  process.stdout.write(`${message}\n`)
}

function stamp() {
  return new Date().toISOString().replace(/[:.]/g, '-')
}

function backup(file) {
  if (!fs.existsSync(file)) return
  const target = `${file}.bak-${stamp()}`
  if (opts.dryRun) {
    log(`  [dry-run] would back up ${file} → ${path.basename(target)}`)
    return
  }
  fs.copyFileSync(file, target)
  log(`  backup: ${path.basename(target)}`)
}

function detectProfile() {
  const profilesDir = path.join(opts.dshHome, 'profiles')
  if (!fs.existsSync(profilesDir)) {
    throw new Error(`找不到 ${profilesDir}：这不是一个 DSH home。用 --dsh-home 指定正确路径。`)
  }
  if (opts.profile) return String(opts.profile)
  for (const candidate of ['desktop', 'web', 'headless', 'tui']) {
    if (fs.existsSync(path.join(profilesDir, candidate, 'package.json'))) return candidate
  }
  const first = fs
    .readdirSync(profilesDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && fs.existsSync(path.join(profilesDir, entry.name, 'package.json')))
    .map((entry) => entry.name)[0]
  if (!first) throw new Error(`在 ${profilesDir} 下没有找到任何 profile（需要含 package.json 的目录）`)
  return first
}

function copyPackage(from, to) {
  const skip = new Set(['node_modules', '.git', '.github', 'data'])
  if (opts.dryRun) {
    log(`  [dry-run] would copy ${from} → ${to}`)
    return
  }
  fs.mkdirSync(to, { recursive: true })
  fs.cpSync(from, to, {
    recursive: true,
    force: true,
    filter: (src) => {
      const rel = path.relative(from, src)
      if (rel === '') return true
      return !skip.has(rel.split(path.sep)[0])
    },
  })
}

function linkOrCopy(from, to) {
  if (fs.existsSync(to)) {
    const stat = fs.lstatSync(to)
    if (stat.isSymbolicLink()) fs.unlinkSync(to)
    else fs.rmSync(to, { recursive: true, force: true })
  }
  if (opts.dryRun) {
    log(`  [dry-run] would ${opts.link ? 'link' : 'copy'} ${from} → ${to}`)
    return
  }
  if (opts.link) {
    fs.mkdirSync(path.dirname(to), { recursive: true })
    fs.symlinkSync(from, to, process.platform === 'win32' ? 'junction' : 'dir')
    return
  }
  copyPackage(from, to)
}

function stripManagedBlock(text) {
  let out = text
  const start = out.indexOf(MARK_START)
  if (start !== -1) {
    const end = out.indexOf(MARK_END, start)
    const stop = end === -1 ? out.length : end + MARK_END.length
    out = `${out.slice(0, start)}${out.slice(stop)}`
  }
  // Also drop an unmarked block that inserts this plugin (an earlier manual install),
  // so re-running the installer never leaves two inserts for the same id.
  const lines = out.split(/\r?\n/)
  const kept = []
  for (let i = 0; i < lines.length; i++) {
    if (/^- insert:\s*$/.test(lines[i])) {
      const chunk = [lines[i]]
      let j = i + 1
      while (j < lines.length && (/^\s+\S/.test(lines[j]) || lines[j].trim() === '')) {
        chunk.push(lines[j])
        j++
      }
      const joined = chunk.join('\n')
      if (joined.includes(`id: ${PKG}`) || joined.includes(`name: ${PKG}`)) {
        // Drop trailing comment lines that describe this plugin.
        while (kept.length > 0) {
          const last = kept[kept.length - 1]
          if (/^\s*$/.test(last) || (last.trim().startsWith('#') && /artex-ops|ARTEX ops/i.test(last))) {
            kept.pop()
            continue
          }
          break
        }
        i = j - 1
        continue
      }
      kept.push(...chunk)
      i = j - 1
      continue
    }
    kept.push(lines[i])
  }
  return kept.join('\n').replace(/\n{3,}/g, '\n\n')
}

function managedBlock() {
  const config = ['        enabled: true']
  if (typeof opts.dataDir === 'string') config.push(`        dataDir: '${String(opts.dataDir).replace(/\\/g, '/')}'`)
  config.push('        oob:')
  config.push('          port: 18080')
  config.push('          bindHost: 127.0.0.1')
  return [
    MARK_START,
    '# 包：<dshHome>/plugins/dsh-artex-ops（供 DSH 插件 / 独立 CLI / MCP 三种用法）',
    '# 数据：<dshHome>/artex-ops 或 config.dataDir（state.json + secrets/ + oob/ + evidence/）',
    '# 远程目标：oob.bindHost 改 0.0.0.0 且 oob.publicHost 设为目标可达地址，否则回连不到本机。',
    '- insert:',
    `    - id: ${PKG}`,
    `      name: ${PKG}`,
    '      config:',
    ...config,
    MARK_END,
  ].join('\n')
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
}

function main() {
  const profile = detectProfile()
  const profileDir = path.join(opts.dshHome, 'profiles', profile)
  const profilePkg = path.join(profileDir, 'package.json')
  const patchFile = path.join(profileDir, 'cordis.patch.yml')
  const pluginRoot = path.join(opts.dshHome, 'plugins', PKG)
  const runtimeTarget = path.join(profileDir, 'node_modules', PKG)
  const skillDir = path.join(opts.dshHome, 'skills', SKILL)
  const skillSrc = path.join(here, 'skills', SKILL, 'SKILL.md')

  log(`ARTEX ops installer${opts.dryRun ? ' (dry-run)' : ''}`)
  log(`  dsh home : ${opts.dshHome}`)
  log(`  profile  : ${profile}  (${profileDir})`)
  log(`  source   : ${here}`)
  log(`  data dir : ${typeof opts.dataDir === 'string' ? opts.dataDir : path.join(opts.dshHome, 'artex-ops')}`)
  log('')

  if (opts.uninstall) {
    log('卸载：')
    if (fs.existsSync(patchFile)) {
      backup(patchFile)
      const text = stripManagedBlock(fs.readFileSync(patchFile, 'utf8'))
      if (!opts.dryRun) fs.writeFileSync(patchFile, `${text.replace(/\s+$/, '')}\n`, 'utf8')
      log('  已移除 cordis.patch.yml 中的 insert 块')
    }
    backup(profilePkg)
    const pkg = readJson(profilePkg)
    if (pkg.dependencies) delete pkg.dependencies[PKG]
    if (pkg.dsh?.profile?.bundles) pkg.dsh.profile.bundles = pkg.dsh.profile.bundles.filter((name) => name !== PKG)
    if (!opts.dryRun) writeJson(profilePkg, pkg)
    log('  已从 package.json 移除 dependency 与 bundle 条目')
    if (fs.existsSync(runtimeTarget)) {
      if (!opts.dryRun) fs.rmSync(runtimeTarget, { recursive: true, force: true })
      log(`  已移除 ${runtimeTarget}`)
    }
    if (fs.existsSync(skillDir)) {
      if (!opts.dryRun) fs.rmSync(skillDir, { recursive: true, force: true })
      log(`  已移除技能 ${skillDir}`)
    }
    log(`  保留数据目录（如需清理请手动删除）：${typeof opts.dataDir === 'string' ? opts.dataDir : path.join(opts.dshHome, PKG)}`)
    log('  重启 DSH（或等一次 HMR 重组）后生效。')
    return
  }

  // 1. install a self-contained copy under <dshHome>/plugins
  log('1) 安装包本体：')
  if (path.resolve(here) === path.resolve(pluginRoot)) {
    log(`  已在目标位置，跳过复制：${pluginRoot}`)
  } else {
    copyPackage(here, pluginRoot)
    log(`  ${pluginRoot}`)
  }

  // 2. make it resolvable from the profile
  log('2) 挂到 profile 的 node_modules：')
  linkOrCopy(pluginRoot, runtimeTarget)
  log(`  ${runtimeTarget} (${opts.link ? 'symlink' : 'copy'})`)

  // 3. profile manifest: dependency + bundle
  log('3) 更新 profile manifest：')
  backup(profilePkg)
  const pkg = readJson(profilePkg)
  pkg.dependencies = pkg.dependencies ?? {}
  const rel = path.relative(profileDir, pluginRoot).split(path.sep).join('/')
  pkg.dependencies[PKG] = opts.link ? `link:${rel}` : `file:${rel}`
  pkg.dsh = pkg.dsh ?? {}
  pkg.dsh.profile = pkg.dsh.profile ?? {}
  pkg.dsh.profile.bundles = pkg.dsh.profile.bundles ?? []
  if (!pkg.dsh.profile.bundles.includes(PKG)) pkg.dsh.profile.bundles.push(PKG)
  if (!opts.dryRun) writeJson(profilePkg, pkg)
  log(`  dependencies.${PKG} = ${pkg.dependencies[PKG]}；bundles += ${PKG}`)

  // 4. patch layer
  log('4) 写入 patch 层：')
  backup(patchFile)
  const existing = fs.existsSync(patchFile) ? fs.readFileSync(patchFile, 'utf8') : '# Your patch layer for this dsh profile\n'
  const cleaned = stripManagedBlock(existing).replace(/\s+$/, '')
  const head = cleaned === '[]' || cleaned === '' ? '' : `${cleaned}\n\n`
  const body = `${head}${managedBlock()}`
  if (!opts.dryRun) fs.writeFileSync(patchFile, `${body.replace(/\s+$/, '')}\n`, 'utf8')
  log(`  ${patchFile}`)

  // 5. skill
  log('5) 安装技能：')
  if (fs.existsSync(skillSrc)) {
    if (!opts.dryRun) {
      fs.mkdirSync(skillDir, { recursive: true })
      fs.copyFileSync(skillSrc, path.join(skillDir, 'SKILL.md'))
    }
    log(`  ${path.join(skillDir, 'SKILL.md')}`)
  } else {
    log('  跳过（skills/artex-ops/SKILL.md 不存在）')
  }

  log('')
  log('完成。生效方式：profile 开着 dsh-hmr 时改完即热重组；否则重启 DSH。')
  log('提示：若之后 pnpm 协调把 profile/node_modules/dsh-artex-ops 清掉（DSH 插件管理器会按 lockfile 回收），')
  log('      重跑本脚本即可恢复；依赖已声明为 file:/link:，不会重新联网。')
  log('其它用法：')
  log(`  CLI : node ${path.join(pluginRoot, 'bin', 'artex-ops.mjs')} next`)
  log(`  MCP : node ${path.join(pluginRoot, 'bin', 'artex-ops-mcp.mjs')}   （stdio JSON-RPC）`)
  log(`  自检: node ${path.join(pluginRoot, 'test', 'selftest.mjs')}`)
}

try {
  main()
} catch (error) {
  process.stderr.write(`install failed: ${error?.message ?? error}\n`)
  process.exit(1)
}
