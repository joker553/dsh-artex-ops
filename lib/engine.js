// One engine, three faces.
//
// The DSH plugin, the standalone CLI and the MCP server all construct this object,
// so the tool bodies (and therefore the state contract) are identical no matter how
// the agent reaches them. That is what makes the package portable: the same logic
// runs inside DeepSeekRuntime, inside any MCP client, or from a shell.
import { Store } from './store.js'
import { OobServer } from './oob.js'
import { buildTools } from './tools.js'

export function createEngine(config = {}) {
  const store = new Store(config)
  store.load()
  const oob = new OobServer({ store, paths: store.paths, config, log: () => {} })
  const tools = buildTools({ store, oob, config })
  const byName = new Map(tools.map((tool) => [tool.name, tool]))

  return {
    store,
    oob,
    tools,
    config,
    /** Tool catalog in MCP shape (name/description/inputSchema). */
    catalog() {
      return tools.map((tool) => ({
        name: tool.name,
        description: tool.description,
        inputSchema: tool.parameters ?? { type: 'object', properties: {} },
      }))
    },
    names() {
      return tools.map((tool) => tool.name)
    },
    /**
     * Execute one tool by name. Returns a JSON-serializable value.
     * @param {string} name
     * @param {object} args
     * @param {{signal?: AbortSignal}} [exec]
     */
    async call(name, args = {}, exec = { signal: undefined }) {
      const tool = byName.get(name)
      if (!tool) throw new Error(`unknown tool ${JSON.stringify(name)}; known: ${[...byName.keys()].join(', ')}`)
      return tool.execute(args ?? {}, exec)
    },
    async close() {
      await oob.close()
    },
    get dataDir() {
      return store.paths.root
    },
  }
}
