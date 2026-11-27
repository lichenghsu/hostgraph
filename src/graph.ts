import type { Edge, Node } from "@xyflow/react";

// Mirrors crates/hostgraph-core/src/model.rs (serde JSON shape).

export type Proto = "tcp" | "udp";
export type Exposure = "loopback" | "specific" | "any";

export type HgNode = { id: string } & (
  | { kind: "interface"; name: string }
  | { kind: "bridge"; name: string }
  | { kind: "firewall_zone"; name: string }
  | { kind: "port"; proto: Proto; port: number; exposure: Exposure }
  | { kind: "process"; pid: number; name: string }
  | { kind: "container"; id: string; name: string; runtime: string }
  | { kind: "pod"; namespace: string; name: string }
);

export type HgEdge = { from: string; to: string } & (
  | { kind: "exposes" }
  | { kind: "listens_on"; addr: string }
  | { kind: "forwards_to" }
  | { kind: "attached_to" }
);

export type HgGraph = { nodes: HgNode[]; edges: HgEdge[] };

export type NodeData = { label: string; sub?: string; hg: HgNode };

// Columns left to right follow inbound traffic: outside -> zone -> port -> owner -> bridge.
const COLUMN: Record<HgNode["kind"], number> = {
  interface: 0,
  firewall_zone: 0,
  port: 1,
  process: 2,
  container: 2,
  pod: 2,
  bridge: 3,
};
const COL_WIDTH = 260;
const ROW_HEIGHT = 56;

function describe(n: HgNode): { label: string; sub?: string } {
  switch (n.kind) {
    case "port":
      return { label: `${n.proto}/${n.port}`, sub: n.exposure };
    case "process":
      return { label: n.name, sub: `pid ${n.pid}` };
    case "container":
      return { label: n.name, sub: n.runtime };
    case "pod":
      return { label: n.name, sub: n.namespace };
    default:
      return { label: n.name };
  }
}

function sortKey(n: HgNode): [string, number] {
  switch (n.kind) {
    case "port":
      return [n.proto, n.port];
    case "process":
      return [n.name.toLowerCase(), n.pid];
    default:
      return [n.name.toLowerCase(), 0];
  }
}

function compare(a: HgNode, b: HgNode): number {
  const [sa, na] = sortKey(a);
  const [sb, nb] = sortKey(b);
  return sa < sb ? -1 : sa > sb ? 1 : na - nb;
}

/** Turn the core graph into React Flow nodes and edges with a column layout. */
export function toFlow(g: HgGraph): { nodes: Node<NodeData>[]; edges: Edge[] } {
  const rows = new Map<number, number>();
  const nodes = [...g.nodes].sort(compare).map((n): Node<NodeData> => {
    const col = COLUMN[n.kind];
    const row = rows.get(col) ?? 0;
    rows.set(col, row + 1);
    return {
      id: n.id,
      type: "hg",
      position: { x: col * COL_WIDTH, y: row * ROW_HEIGHT },
      data: { ...describe(n), hg: n },
    };
  });

  const edges = g.edges.map((e, i): Edge => {
    // ListensOn points process -> port in the model; draw it port -> process
    // so every edge flows left to right with inbound traffic.
    const [source, target] = e.kind === "listens_on" ? [e.to, e.from] : [e.from, e.to];
    return {
      id: `e${i}`,
      source,
      target,
      label: e.kind === "listens_on" ? e.addr : undefined,
      className: `edge-${e.kind}`,
    };
  });

  return { nodes, edges };
}
