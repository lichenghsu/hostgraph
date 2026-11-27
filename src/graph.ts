import { MarkerType, type Edge, type Node } from "@xyflow/react";

// Mirrors crates/hostgraph-core/src/model.rs (serde JSON shape).

export type Proto = "tcp" | "udp";
export type Exposure = "loopback" | "specific" | "any";

export type HgNode = { id: string } & (
  | { kind: "interface"; name: string }
  | { kind: "bridge"; name: string }
  | { kind: "firewall_zone"; name: string; target: string; sources: string[] }
  | { kind: "port"; proto: Proto; port: number; exposure: Exposure | null }
  | { kind: "port_range"; proto: Proto; from: number; to: number }
  | { kind: "process"; pid: number; name: string }
  | { kind: "container"; container_id: string; name: string; runtime: string; image: string }
  | { kind: "pod"; namespace: string; name: string }
);

export type HgEdge = { from: string; to: string } & (
  | { kind: "exposes"; via: string }
  | { kind: "listens_on"; addr: string }
  | { kind: "forwards_to"; container_port: number }
  | { kind: "attached_to" }
  | { kind: "in_zone" }
);

export type FindingKind = "open_no_listener" | "open_loopback_only" | "listener_not_allowed";
export type Finding = { node: string; kind: FindingKind; message: string };

export type HgGraph = {
  nodes: HgNode[];
  edges: HgEdge[];
  findings: Finding[];
  warnings: string[];
};

export type Filters = {
  search: string;
  hideLoopback: boolean;
  hideIdle: boolean;
  onlyFindings: boolean;
  showLabels: boolean;
};

export const defaultFilters: Filters = {
  search: "",
  hideLoopback: false,
  hideIdle: false,
  onlyFindings: false,
  showLabels: false,
};

export type NodeData = {
  label: string;
  sub?: string;
  hg: HgNode;
  findings: Finding[];
};

export const FINDING_TITLE: Record<FindingKind, string> = {
  open_no_listener: "Open, nothing listening",
  open_loopback_only: "Open, but loopback only",
  listener_not_allowed: "Listening, firewall blocks",
};

// Columns left to right follow inbound traffic:
// interface -> zone -> port -> process / container -> container network
function column(n: HgNode): number {
  switch (n.kind) {
    case "interface":
      return 0;
    case "bridge":
      // Host bridges sit with interfaces; container networks go last
      return n.id.startsWith("if:") ? 0 : 4;
    case "firewall_zone":
      return 1;
    case "port":
    case "port_range":
      return 2;
    case "process":
    case "container":
    case "pod":
      return 3;
  }
}

const COL_WIDTH = 280;
const ROW_HEIGHT = 46;

export function describe(n: HgNode): { label: string; sub?: string } {
  switch (n.kind) {
    case "port":
      return { label: `${n.proto}/${n.port}`, sub: n.exposure ?? "no listener" };
    case "port_range":
      return { label: `${n.proto}/${n.from}-${n.to}`, sub: "range" };
    case "process":
      return { label: n.name, sub: `pid ${n.pid}` };
    case "container":
      return { label: n.name, sub: `${n.runtime} · ${n.image}` };
    case "pod":
      return { label: n.name, sub: n.namespace };
    case "firewall_zone":
      return { label: n.name, sub: `zone · ${n.target}` };
    case "bridge":
      return { label: n.name, sub: n.id.startsWith("if:") ? "bridge" : "container network" };
    case "interface":
      return { label: n.name, sub: "interface" };
  }
}

function portKey(n: HgNode): [number, number] {
  if (n.kind === "port") return [n.proto === "tcp" ? 0 : 1, n.port];
  if (n.kind === "port_range") return [n.proto === "tcp" ? 0 : 1, n.from];
  return [2, 0];
}

function edgeLabel(e: HgEdge): string | undefined {
  switch (e.kind) {
    case "listens_on":
      return e.addr;
    case "exposes":
      return e.via;
    case "forwards_to":
      return `→ :${e.container_port}`;
    default:
      return undefined;
  }
}

/** Pick the nodes to show for the given filters. */
function visibleIds(g: HgGraph, f: Filters, findingIds: Set<string>): Set<string> {
  const neighbors = new Map<string, string[]>();
  for (const e of g.edges) {
    (neighbors.get(e.from) ?? neighbors.set(e.from, []).get(e.from)!).push(e.to);
    (neighbors.get(e.to) ?? neighbors.set(e.to, []).get(e.to)!).push(e.from);
  }

  // 1. Ports and ranges are the spine: filter them first
  const ports = g.nodes.filter((n) => {
    if (n.kind !== "port" && n.kind !== "port_range") return false;
    if (f.onlyFindings && !findingIds.has(n.id)) return false;
    if (f.hideLoopback && n.kind === "port" && n.exposure === "loopback" && !findingIds.has(n.id)) return false;
    if (f.hideIdle && !(neighbors.get(n.id)?.length ?? 0)) return false;
    return true;
  });
  const keep = new Set(ports.map((n) => n.id));

  // 2. Everything else stays only if it touches a visible port
  //    (interfaces reach ports through their zone)
  for (const n of g.nodes) {
    if (keep.has(n.id) || n.kind === "port" || n.kind === "port_range") continue;
    if (n.kind === "interface" || (n.kind === "bridge" && n.id.startsWith("if:"))) continue;
    if ((neighbors.get(n.id) ?? []).some((m) => keep.has(m))) keep.add(n.id);
  }
  // Container networks hang off containers
  for (const n of g.nodes) {
    if (n.kind === "bridge" && !n.id.startsWith("if:") && (neighbors.get(n.id) ?? []).some((m) => keep.has(m))) {
      keep.add(n.id);
    }
  }
  for (const n of g.nodes) {
    if (n.kind === "interface" || (n.kind === "bridge" && n.id.startsWith("if:"))) {
      const zones = (neighbors.get(n.id) ?? []).filter((m) => keep.has(m));
      if (zones.length || (!f.onlyFindings && !f.search)) keep.add(n.id);
    }
  }

  // 3. Search narrows to matching nodes and their direct neighbors
  const q = f.search.trim().toLowerCase();
  if (q) {
    const hits = g.nodes.filter((n) => keep.has(n.id) && matches(n, q)).map((n) => n.id);
    const narrowed = new Set(hits);
    for (const id of hits) for (const m of neighbors.get(id) ?? []) if (keep.has(m)) narrowed.add(m);
    return narrowed;
  }
  return keep;
}

function matches(n: HgNode, q: string): boolean {
  const { label, sub } = describe(n);
  return `${label} ${sub ?? ""} ${n.id}`.toLowerCase().includes(q);
}

/**
 * Turn the core graph into React Flow nodes and edges.
 *
 * Layout: the port column is the spine, sorted by proto and number. Every
 * other column places each node at the average height of the nodes it links
 * to, then pushes nodes down to avoid overlap, which keeps edges short.
 * `pinned` holds positions the user dragged nodes to.
 */
export function toFlow(
  g: HgGraph,
  f: Filters,
  pinned: Map<string, { x: number; y: number }>,
): { nodes: Node<NodeData>[]; edges: Edge[] } {
  const findingsBy = new Map<string, Finding[]>();
  for (const x of g.findings) (findingsBy.get(x.node) ?? findingsBy.set(x.node, []).get(x.node)!).push(x);

  const keep = visibleIds(g, f, new Set(findingsBy.keys()));
  const shown = g.nodes.filter((n) => keep.has(n.id));
  const edges = g.edges.filter((e) => keep.has(e.from) && keep.has(e.to));

  const links = new Map<string, string[]>();
  for (const e of edges) {
    (links.get(e.from) ?? links.set(e.from, []).get(e.from)!).push(e.to);
    (links.get(e.to) ?? links.set(e.to, []).get(e.to)!).push(e.from);
  }

  const y = new Map<string, number>();
  const ports = shown.filter((n) => column(n) === 2);
  ports.sort((a, b) => {
    const [pa, na] = portKey(a);
    const [pb, nb] = portKey(b);
    return pa - pb || na - nb;
  });
  ports.forEach((n, i) => y.set(n.id, i * ROW_HEIGHT));

  // Place columns outward from the spine so each sees placed neighbors
  for (const col of [1, 3, 0, 4]) {
    const nodes = shown.filter((n) => column(n) === col);
    const want = new Map<string, number>();
    for (const n of nodes) {
      const ys = (links.get(n.id) ?? []).map((m) => y.get(m)).filter((v): v is number => v !== undefined);
      want.set(n.id, ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : Infinity);
    }
    nodes.sort((a, b) => want.get(a.id)! - want.get(b.id)! || a.id.localeCompare(b.id));
    let next = 0;
    for (const n of nodes) {
      const w = want.get(n.id)!;
      const at = Math.max(next, Number.isFinite(w) ? w : next);
      y.set(n.id, at);
      next = at + ROW_HEIGHT;
    }
  }

  const flowNodes = shown.map(
    (n): Node<NodeData> => ({
      id: n.id,
      type: "hg",
      position: pinned.get(n.id) ?? { x: column(n) * COL_WIDTH, y: y.get(n.id) ?? 0 },
      data: { ...describe(n), hg: n, findings: findingsBy.get(n.id) ?? [] },
    }),
  );

  const flowEdges = edges.map((e, i): Edge => {
    // ListensOn points process -> port in the model; flip it so every edge
    // runs left to right with inbound traffic.
    const flip = e.kind === "listens_on";
    return {
      id: `e${i}-${e.kind}`,
      source: flip ? e.to : e.from,
      target: flip ? e.from : e.to,
      label: f.showLabels ? edgeLabel(e) : undefined,
      className: `edge-${e.kind}`,
      animated: e.kind === "forwards_to",
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
      data: { hg: e },
    };
  });

  return { nodes: flowNodes, edges: flowEdges };
}

/** Human-readable connections of one node, for the details panel. */
export function connections(g: HgGraph, id: string): { dir: "in" | "out"; other: string; text: string }[] {
  const byId = new Map(g.nodes.map((n) => [n.id, n]));
  const name = (nid: string) => {
    const n = byId.get(nid);
    return n ? describe(n).label : nid;
  };
  const verb: Record<HgEdge["kind"], string> = {
    exposes: "exposes",
    listens_on: "listens on",
    forwards_to: "forwards to",
    attached_to: "attached to",
    in_zone: "in zone",
  };
  return g.edges
    .filter((e) => e.from === id || e.to === id)
    .map((e) => {
      const out = e.from === id;
      const extra = edgeLabel(e);
      const text = out
        ? `${verb[e.kind]} ${name(e.to)}`
        : `${name(e.from)} ${verb[e.kind]} this`;
      return { dir: out ? "out" : "in", other: out ? e.to : e.from, text: extra ? `${text} (${extra})` : text };
    });
}
