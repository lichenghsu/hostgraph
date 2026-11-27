import { useCallback, useEffect, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import {
  Background,
  Controls,
  Handle,
  MiniMap,
  Panel,
  Position,
  ReactFlow,
  useEdgesState,
  useNodesState,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import "./App.css";
import { toFlow, type HgGraph, type NodeData } from "./graph";

function HgNodeView({ data }: NodeProps<Node<NodeData>>) {
  const hg = data.hg;
  const exposure = hg.kind === "port" ? ` exposure-${hg.exposure}` : "";
  return (
    <div className={`hg-node kind-${hg.kind}${exposure}`}>
      <Handle type="target" position={Position.Left} />
      <div className="hg-label">{data.label}</div>
      {data.sub && <div className="hg-sub">{data.sub}</div>}
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const nodeTypes = { hg: HgNodeView };

function App() {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<NodeData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    // The Rust backend exists only inside the Tauri webview, not a plain browser tab.
    if (!isTauri()) {
      setError("No Tauri backend: run `pnpm tauri dev` and use the app window, not the browser.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const flow = toFlow(await invoke<HgGraph>("get_graph"));
      setNodes(flow.nodes);
      setEdges(flow.edges);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [setNodes, setEdges]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <div className="app">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodesConnectable={false}
        fitView
        minZoom={0.1}
      >
        <Background />
        <Controls />
        <MiniMap pannable zoomable />
        <Panel position="top-left" className="toolbar">
          <button onClick={refresh} disabled={loading}>
            {loading ? "Scanning…" : "Refresh"}
          </button>
          <span className="legend">
            <i className="dot exposure-any" /> any
            <i className="dot exposure-specific" /> specific
            <i className="dot exposure-loopback" /> loopback
          </span>
          {error && <span className="error">{error}</span>}
        </Panel>
      </ReactFlow>
    </div>
  );
}

export default App;
