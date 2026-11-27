use serde::Serialize;

/// Transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

/// Kind of a node in the graph, each variant carrying its own fields
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NodeKind {
    Interface {
        name: String,
    },
    Bridge {
        name: String,
    },
    FirewallZone {
        name: String,
    },
    Port {
        proto: Proto,
        port: u16,
    },
    Process {
        pid: i32,
        name: String,
    },
    Container {
        id: String,
        name: String,
        runtime: String,
    },
    Pod {
        namespace: String,
        name: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub id: String,
    #[serde(flatten)]
    pub kind: NodeKind,
}

/// Kind of an edge in the graph, describing the relationship between two nodes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Exposes,    // zone -> port
    ListensOn,  // process -> port
    ForwardsTo, // port -> container (DNAT)
    AttachedTo, // container -> bridge
}

#[derive(Debug, Clone, Serialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
}

#[derive(Debug, Default, Serialize)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

impl Graph {
    /// Add a node; each ID must be unique.
    pub fn add_node(&mut self, id: String, kind: NodeKind) {
        if !self.nodes.iter().any(|n| n.id == id) {
            self.nodes.push(Node { id, kind });
        }
    }

    /// Add an edge; an identical (from, to, kind) edge is added only once.
    pub fn add_edge(&mut self, from: &str, to: &str, kind: EdgeKind) {
        if self
            .edges
            .iter()
            .any(|e| e.from == from && e.to == to && e.kind == kind)
        {
            return;
        }
        self.edges.push(Edge {
            from: from.to_string(),
            to: to.to_string(),
            kind,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_for_frontend() {
        let mut g = Graph::default();
        g.add_node(
            "port:tcp:22".into(),
            NodeKind::Port {
                proto: Proto::Tcp,
                port: 22,
            },
        );
        g.add_node(
            "proc:1234".into(),
            NodeKind::Process {
                pid: 1234,
                name: "sshd".into(),
            },
        );
        g.add_edge("proc:1234", "port:tcp:22", EdgeKind::ListensOn);

        let json = serde_json::to_string(&g).unwrap();
        assert!(json.contains(r#""kind":"port","proto":"tcp","port":22"#));
        assert!(json.contains(r#""kind":"listens_on""#));
    }
}
