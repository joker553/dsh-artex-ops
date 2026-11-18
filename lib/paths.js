// Path resolution for dsh-artex-ops.
// Everything the plugin owns lives under one data dir so a profile reset is a
// single directory move: state.json (the model), secrets/ (credential material),
// oob/ (out-of-band hit log), evidence/ (hashed artifacts).
import os from 'node:os'
import path from 'node:path'

/** DSH home: $DSH_HOME when set, else ~/.dsh — the same root the harness uses. */
export function dshHome() {
  const fromEnv = process.env.DSH_HOME
  if (typeof fromEnv === 'string' && fromEnv.trim() !== '') return path.resolve(fromEnv.trim())
  return path.join(os.homedir(), '.dsh')
}

/** Absolute data dir for this plugin, honoring an explicit config override. */
export function resolveDataDir(config = {}) {
  const raw = typeof config?.dataDir === 'string' ? config.dataDir.trim() : ''
  const dir = raw !== '' ? path.resolve(raw) : path.join(dshHome(), 'artex-ops')
  return {
    root: dir,
    state: path.join(dir, 'state.json'),
    secrets: path.join(dir, 'secrets'),
    oob: path.join(dir, 'oob'),
    oobLog: path.join(dir, 'oob', 'hits.ndjson'),
    evidence: path.join(dir, 'evidence'),
  }
}

/** First non-internal IPv4, used as the default OOB public host. */
export function defaultPublicHost() {
  const nets = os.networkInterfaces()
  for (const name of Object.keys(nets)) {
    for (const entry of nets[name] ?? []) {
      if (entry.family === 'IPv4' && !entry.internal) return entry.address
    }
  }
  return '127.0.0.1'
}
