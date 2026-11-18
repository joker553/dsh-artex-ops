// Post-install verification: patch shape, profile manifest, module resolution, a real
// apply() from the installed location, and the two portable entry points (CLI + MCP)
// running out of that same location.
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { pathToFileURL } from 'node:url'
import assert from 'node:assert/strict'
import yaml from 'file:///C:/Users/young/.dsh/profiles/desktop/node_modules/js-yaml/index.js'

const dshHome = 'C:/Users/young/.dsh'
const profileDir = `${dshHome}/profiles/desktop`

// The profile patch uses dsh's `!!js` tag for live expressions; plain js-yaml
// rejects unknown tags, so register it as a scalar before validating structure.
const JsTag = new yaml.Type('tag:yaml.org,2002:js', { kind: 'scalar', construct: (data) => data })
const schema = yaml.DEFAULT_SCHEMA.extend([JsTag])

const doc = yaml.load(fs.readFileSync(`${profileDir}/cordis.patch.yml`, 'utf8'), { schema })
assert.ok(Array.isArray(doc), 'patch must be a YAML array')
const inserts = doc.filter((entry) => entry && Array.isArray(entry.insert)).flatMap((entry) => entry.insert)
const mine = inserts.find((entry) => entry.id === 'dsh-artex-ops')
assert.ok(mine, 'patch insert missing for dsh-artex-ops')
assert.equal(inserts.filter((entry) => entry.id === 'dsh-artex-ops').length, 1, 'exactly one insert for the plugin')
console.log(`patch: ${doc.length} entries | inserts: ${inserts.map((e) => e.id).join(', ')}`)
console.log(`  ours: ${JSON.stringify(mine)}`)

const pkg = JSON.parse(fs.readFileSync(`${profileDir}/package.json`, 'utf8'))
assert.ok(pkg.dependencies['dsh-artex-ops'], 'dependency entry missing')
assert.ok(pkg.dsh.profile.bundles.includes('dsh-artex-ops'), 'bundle entry missing')
assert.equal(pkg.dsh.profile.bundles.filter((name) => name === 'dsh-artex-ops').length, 1, 'duplicate bundle entry')
console.log(`manifest: dependency=${pkg.dependencies['dsh-artex-ops']} | bundles: ${pkg.dsh.profile.bundles.join(', ')}`)

const require = createRequire(`${profileDir}/package.json`)
const entry = require.resolve('dsh-artex-ops')
console.log(`resolved: ${entry}`)

const mod = await import(pathToFileURL(entry).href)
assert.equal(mod.name, 'dsh-artex-ops')
assert.deepEqual(mod.inject, ['tools'])

const tools = new Map()
const sections = []
const disposers = []
mod.apply(
  {
    tools: {
      register(definition) {
        assert.equal(typeof definition.output.render, 'function', `${definition.name} missing render`)
        tools.set(definition.name, definition)
        return () => tools.delete(definition.name)
      },
    },
    effect(factory) {
      const dispose = factory()
      if (typeof dispose === 'function') disposers.push(dispose)
      return dispose
    },
    inject(_deps, callback) {
      return callback({ systemPrompt: { section: (section) => sections.push(section) } })
    },
    get: () => undefined,
  },
  { dataDir: path.join(os.tmpdir(), 'artex-ops-installcheck'), oob: { port: 0 } },
)

// The shell registers tools from the implementation child's catalog, so the set
// arrives asynchronously: wait for it before asserting.
for (let i = 0; i < 150 && tools.size < 24; i++) await new Promise((resolve) => setTimeout(resolve, 100))

assert.equal(tools.size, 27, `expected 27 tools, got ${tools.size}`)
assert.equal(sections.length, 1)
assert.equal(sections[0].name, 'tool:artex-ops')
console.log(`apply from installed path: ${tools.size} tools, 1 prompt section (${sections[0].name})`)
console.log(`  names: ${[...tools.keys()].join(', ')}`)

const state = await tools.get('pt_state').execute({}, { signal: undefined })
assert.equal(typeof state.dataDir, 'string')
const next = await tools.get('pt_next').execute({}, { signal: undefined })
assert.equal(next.decision, 'bootstrap')
console.log(`pt_state/pt_next ok: dataDir=${state.dataDir} decision=${next.decision}`)

// Portable entry points, resolved from the install location.
const binDir = path.dirname(entry)
const cli = path.join(binDir, 'bin', 'artex-ops.mjs')
const mcp = path.join(binDir, 'bin', 'artex-ops-mcp.mjs')
assert.ok(fs.existsSync(cli), 'CLI entry missing')
assert.ok(fs.existsSync(mcp), 'MCP entry missing')
const cliRun = spawnSync(process.execPath, [cli, 'tools', '--data', path.join(os.tmpdir(), 'artex-ops-installcheck')], { encoding: 'utf8' })
assert.equal(cliRun.status, 0, `CLI failed: ${cliRun.stderr}`)
const catalog = JSON.parse(cliRun.stdout)
assert.equal(catalog.length, 27)
console.log(`CLI from install dir: ${catalog.length} tools listed`)
console.log(`  first: ${catalog.slice(0, 4).map((tool) => tool.name).join(', ')} …`)

for (const dispose of disposers) {
  try {
    await dispose()
  } catch {}
}
try {
  fs.rmSync(path.join(os.tmpdir(), 'artex-ops-installcheck'), { recursive: true, force: true })
} catch {}
console.log('INSTALL CHECK OK')
