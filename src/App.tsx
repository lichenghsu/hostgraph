import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import {
  Background,
  Controls,
  Handle,
  MiniMap,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import "./App.css";
import {
  FINDING_TITLE,
  connections,
  defaultFilters,
  describe,
  toFlow,
  type Filters,
  type FindingKind,
  type HgGraph,
  type NodeData,
} from "./graph";

function HgNodeView({ data, selected }: NodeProps<Node<NodeData>>) {
  const hg = data.hg;
  const classes = ["hg-node", `kind-${hg.kind}`];
  if (hg.kind === "port") classes.push(`exposure-${hg.exposure ?? "none"}`);
  if (data.findings.length) classes.push("has-finding");
  if (selected) classes.push("selected");
  return (
    <div className={classes.join(" ")} title={data.findings.map((f) => f.message).join("\n") || undefined}>
      <Handle type="target" position={Position.Left} />
      <div className="hg-label">
        {data.label}
        {data.findings.length > 0 && <span className="badge">!</span>}
      </div>
      {data.sub && <div className="hg-sub">{data.sub}</div>}
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const nodeTypes = { hg: HgNodeView };
const EMPTY: HgGraph = { nodes: [], edges: [], findings: [], warnings: [] };

function Canvas() {
  const [graph, setGraph] = useState<HgGraph>(EMPTY);
  const [filters, setFilters] = useState<Filters>(defaultFilters);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  // Root scans prompt for a password each time, so they are opt-in
  const [asRoot, setAsRoot] = useState(false);
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<NodeData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const pinned = useRef(new Map<string, { x: number; y: number }>());
  const { fitView, setCenter, getNode } = useReactFlow();

  const refresh = useCallback(async (privileged: boolean) => {
    // The Rust backend exists only inside the Tauri webview, not a plain browser tab.
    if (!isTauri()) {
      setError("No Tauri backend: run `pnpm tauri dev` and use the app window, not the browser.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      setGraph(await invoke<HgGraph>("get_graph", { privileged }));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh(false);
  }, [refresh]);

  // Re-layout whenever data or filters change; dragged nodes keep their spot
  useEffect(() => {
    const flow = toFlow(graph, filters, pinned.current);
    setNodes(flow.nodes.map((n) => ({ ...n, selected: n.id === selected })));
    setEdges(flow.edges);
    requestAnimationFrame(() => fitView({ padding: 0.1, duration: 200 }));
    // selection changes alone must not re-layout
  }, [graph, filters, setNodes, setEdges, fitView]);

  const focus = useCallback(
    (id: string) => {
      setSelected(id);
      setNodes((ns) => ns.map((n) => ({ ...n, selected: n.id === id })));
      const n = getNode(id);
      if (n) setCenter(n.position.x + 80, n.position.y + 20, { zoom: 1.2, duration: 300 });
    },
    [getNode, setCenter, setNodes],
  );

  const set = <K extends keyof Filters>(k: K, v: Filters[K]) => setFilters((f) => ({ ...f, [k]: v }));

  const stats = useMemo(() => {
    const count = (k: string) => graph.nodes.filter((n) => n.kind === k).length;
    return { ports: count("port"), procs: count("process"), ctrs: count("container"), zones: count("firewall_zone") };
  }, [graph]);

  return (
    <div className="app">
      <div className="canvas">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={(_, n) => setSelected(n.id)}
          onPaneClick={() => setSelected(null)}
          onNodeDragStop={(_, n) => pinned.current.set(n.id, n.position)}
          nodesConnectable={false}
          minZoom={0.05}
        >
          <Background />
          <Controls />
          <MiniMap pannable zoomable />
          <Panel position="top-left" className="toolbar">
            <button onClick={() => refresh(asRoot)} disabled={loading}>
              {loading ? "Scanning…" : "Refresh"}
            </button>
            <label title="Read process owners as root via pkexec; asks for your password on each scan">
              <input
                type="checkbox"
                checked={asRoot}
                disabled={loading}
                onChange={(e) => {
                  setAsRoot(e.target.checked);
                  refresh(e.target.checked);
                }}
              />
              As root
            </label>
            <input
              type="search"
              placeholder="Search port, process, zone…"
              value={filters.search}
              onChange={(e) => set("search", e.target.value)}
            />
            <label>
              <input type="checkbox" checked={filters.hideLoopback} onChange={(e) => set("hideLoopback", e.target.checked)} />
              Hide loopback
            </label>
            <label>
              <input type="checkbox" checked={filters.hideIdle} onChange={(e) => set("hideIdle", e.target.checked)} />
              Hide unlinked ports
            </label>
            <label>
              <input type="checkbox" checked={filters.onlyFindings} onChange={(e) => set("onlyFindings", e.target.checked)} />
              Findings only
            </label>
            <label>
              <input type="checkbox" checked={filters.showLabels} onChange={(e) => set("showLabels", e.target.checked)} />
              Edge labels
            </label>
            <button
              onClick={() => {
                pinned.current.clear();
                setFilters((f) => ({ ...f }));
              }}
              title="Forget dragged positions"
            >
              Re-layout
            </button>
          </Panel>
          <Panel position="bottom-center" className="legend">
            <i className="dot exposure-any" /> any
            <i className="dot exposure-specific" /> specific
            <i className="dot exposure-loopback" /> loopback
            <i className="dot exposure-none" /> no listener
            <i className="dot kind-firewall_zone" /> zone
            <i className="dot kind-process" /> process
            <i className="dot kind-container" /> container
          </Panel>
        </ReactFlow>
      </div>
      <Sidebar
        graph={graph}
        selected={selected}
        error={error}
        stats={stats}
        onFocus={focus}
      />
    </div>
  );
}

function Sidebar(props: {
  graph: HgGraph;
  selected: string | null;
  error: string | null;
  stats: { ports: number; procs: number; ctrs: number; zones: number };
  onFocus: (id: string) => void;
}) {
  const { graph, selected, error, stats, onFocus } = props;
  const node = graph.nodes.find((n) => n.id === selected);
  const grouped = useMemo(() => {
    const m = new Map<FindingKind, typeof graph.findings>();
    for (const f of graph.findings) (m.get(f.kind) ?? m.set(f.kind, []).get(f.kind)!).push(f);
    return m;
  }, [graph]);

  return (
    <aside className="sidebar">
      {error && <div className="error">{error}</div>}

      <section>
        <h2>Host</h2>
        <p className="muted">
          {stats.ports} ports · {stats.procs} processes · {stats.ctrs} containers · {stats.zones} zones
        </p>
      </section>

      {node && (
        <section>
          <h2>{describe(node).label}</h2>
          <p className="muted">{node.kind.replace("_", " ")}</p>
          <dl>
            {Object.entries(node)
              .filter(([k]) => k !== "kind")
              .map(([k, v]) => (
                <div key={k}>
                  <dt>{k}</dt>
                  <dd>{Array.isArray(v) ? v.join(", ") || "—" : String(v ?? "—")}</dd>
                </div>
              ))}
          </dl>
          <h3>Connections</h3>
          <ul className="links">
            {connections(graph, node.id).map((c, i) => (
              <li key={i}>
                <button className="link" onClick={() => onFocus(c.other)}>
                  {c.text}
                </button>
              </li>
            ))}
          </ul>
          {graph.findings
            .filter((f) => f.node === node.id)
            .map((f, i) => (
              <p key={i} className={`finding finding-${f.kind}`}>
                {f.message}
              </p>
            ))}
        </section>
      )}

      <section>
        <h2>Findings ({graph.findings.length})</h2>
        {graph.findings.length === 0 && <p className="muted">No gaps between firewall and listeners.</p>}
        {[...grouped].map(([kind, list]) => (
          <details key={kind} open>
            <summary className={`finding-${kind}`}>
              {FINDING_TITLE[kind]} ({list.length})
            </summary>
            <ul className="links">
              {list.map((f, i) => (
                <li key={i}>
                  <button className="link" onClick={() => onFocus(f.node)} title={f.message}>
                    {f.message}
                  </button>
                </li>
              ))}
            </ul>
          </details>
        ))}
      </section>

      {graph.warnings.length > 0 && (
        <section>
          <h2>Warnings</h2>
          <ul className="muted">
            {graph.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </section>
      )}

      <section>
        <p className="muted small">
          Read-only. Without "As root", ports owned by other users show no process. Docker is skipped unless dockerd is
          already running.
        </p>
      </section>
    </aside>
  );
}

export default function App() {
  return (
    <ReactFlowProvider>
      <Canvas />
    </ReactFlowProvider>
  );
}
