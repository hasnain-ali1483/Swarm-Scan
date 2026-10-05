// ─── Preset queries for the GraphQL console (Task 9-a) ───────────────────────
// The console is the primary data flow: whatever it executes feeds the canvas
// when the result carries a `graph` field.

export interface GqlPreset {
  key: string;
  label: string;
  query: string;
}

function graphQuery(args: string): string {
  return `query {
  graph(${args}) {
    nodes { id kind label sub severity band status }
    edges { id source target kind }
    stats { nodes edges targets scans agents findings chains }
  }
}`;
}

export const DEFAULT_QUERY = `# SwarmScan output plane — the correlator's attack graph as data:
# targets → scans → agents → findings → attack chains.
# Edit freely, then Run (⌘/Ctrl + Enter).
${graphQuery("limit: 60")}`;

export const PRESETS: GqlPreset[] = [
  { key: "full", label: "Full graph", query: graphQuery("limit: 60") },
  { key: "critical", label: "Critical only", query: graphQuery('severity: "critical", limit: 200') },
  { key: "confirmed", label: "Confirmed only", query: graphQuery('band: "confirmed"') },
  { key: "ssrf", label: "SSRF agent subgraph", query: graphQuery('agentKey: "ssrf"') },
  {
    key: "scans",
    label: "Scans list",
    query: `query {
  scans(limit: 25) { id target status profile findingCount requestCount startedAt }
}`,
  },
  {
    key: "stats",
    label: "Platform stats",
    query: `query {
  stats { scans findings confirmed chains evidence avgConfidence }
}`,
  },
  { key: "sdl", label: "Schema SDL", query: "query {\n  schemaSDL\n}" },
];

/** Inspector drill-down query — fetches the prose detail for one node. */
export const NODE_QUERY = `query Node($id: ID!) {
  node(id: $id) { id kind label sub severity band status detail }
}`;
