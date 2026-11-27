use std::net::IpAddr;

use serde::Serialize;

/// Transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Proto::Tcp),
            "udp" => Some(Proto::Udp),
            _ => None,
        }
    }
}

/// Who can reach a socket, judged from its bind address.
/// Ordered narrowest to widest, so `max()` gives the widest exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    /// 127.0.0.0/8 or ::1: this host only
    Loopback,
    /// One specific interface address, e.g. a LAN IP or a bridge gateway
    Specific,
    /// 0.0.0.0 or ::: every interface
    Any,
}

impl Exposure {
    pub fn of(addr: IpAddr) -> Self {
        // Unwrap IPv4-mapped IPv6 such as ::ffff:127.0.0.1
        let addr = match addr {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
            v4 => v4,
        };
        if addr.is_unspecified() {
            Exposure::Any
        } else if addr.is_loopback() {
            Exposure::Loopback
        } else {
            Exposure::Specific
        }
    }
}

/// Kind of a node in the graph, each variant carrying its own fields
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NodeKind {
    Interface {
        name: String,
    },
    /// A Linux bridge on the host, or a container network
    Bridge {
        name: String,
    },
    FirewallZone {
        name: String,
        /// firewalld target: "default", "ACCEPT", "DROP", "%%REJECT%%"
        target: String,
        /// Source CIDRs bound to the zone
        sources: Vec<String>,
    },
    Port {
        proto: Proto,
        port: u16,
        /// Widest exposure among all sockets bound to this port;
        /// None when nothing on the host listens on it
        exposure: Option<Exposure>,
    },
    /// A firewall port range such as 1714-1764
    PortRange {
        proto: Proto,
        from: u16,
        to: u16,
    },
    Process {
        pid: i32,
        name: String,
    },
    Container {
        /// Short container ID (named so it does not clash with `Node::id`
        /// when the kind is flattened into the node JSON)
        container_id: String,
        name: String,
        runtime: String,
        image: String,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EdgeKind {
    /// zone -> port or port range; `via` is "port", "service:<name>" or "rule"
    Exposes { via: String },
    /// process -> port, bound on `addr`
    ListensOn { addr: IpAddr },
    /// port -> container (published port / DNAT)
    ForwardsTo { container_port: u16 },
    /// container -> bridge or container network
    AttachedTo,
    /// interface or bridge -> firewall zone
    InZone,
}

#[derive(Debug, Clone, Serialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    #[serde(flatten)]
    pub kind: EdgeKind,
}

/// A mismatch between firewall rules and what actually listens
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// The firewall opens a port, but nothing listens on it
    OpenNoListener,
    /// The firewall opens a port, but the listener binds loopback only
    OpenLoopbackOnly,
    /// Something listens on every interface, but no zone allows it
    ListenerNotAllowed,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub node: String,
    pub kind: FindingKind,
    pub message: String,
}

#[derive(Debug, Default, Serialize)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub findings: Vec<Finding>,
    /// Collectors that failed or were skipped, e.g. "docker: not running"
    pub warnings: Vec<String>,
}

/// Node ID of a single port, shared by every collector
pub fn port_id(proto: Proto, port: u16) -> String {
    format!("port:{}:{port}", proto.as_str())
}

/// Node ID of a network interface or host bridge
pub fn iface_id(name: &str) -> String {
    format!("if:{name}")
}

impl Graph {
    /// Add a node; a node whose ID already exists is left unchanged.
    pub fn add_node(&mut self, id: String, kind: NodeKind) {
        if !self.has_node(&id) {
            self.nodes.push(Node { id, kind });
        }
    }

    pub fn has_node(&self, id: &str) -> bool {
        self.nodes.iter().any(|n| n.id == id)
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
            port_id(Proto::Tcp, 22),
            NodeKind::Port {
                proto: Proto::Tcp,
                port: 22,
                exposure: Some(Exposure::Any),
            },
        );
        g.add_node(
            "proc:1234".into(),
            NodeKind::Process {
                pid: 1234,
                name: "sshd".into(),
            },
        );
        g.add_edge(
            "proc:1234",
            "port:tcp:22",
            EdgeKind::ListensOn {
                addr: "0.0.0.0".parse().unwrap(),
            },
        );

        let json = serde_json::to_string(&g).unwrap();
        assert!(json.contains(r#""kind":"port","proto":"tcp","port":22,"exposure":"any""#));
        assert!(json.contains(r#""kind":"listens_on","addr":"0.0.0.0""#));
        assert!(json.contains(r#""findings":[]"#));
    }

    #[test]
    fn node_fields_do_not_clash_with_node_id() {
        // Flattened kinds share the JSON object with `id`; a field named `id`
        // would silently overwrite it.
        let n = Node {
            id: "ctr:podman:abc".into(),
            kind: NodeKind::Container {
                container_id: "abc".into(),
                name: "web".into(),
                runtime: "podman".into(),
                image: "nginx".into(),
            },
        };
        let v: serde_json::Value = serde_json::to_value(&n).unwrap();
        assert_eq!(v["id"], "ctr:podman:abc");
    }

    #[test]
    fn exposure_from_addr() {
        let of = |s: &str| Exposure::of(s.parse().unwrap());
        assert_eq!(of("0.0.0.0"), Exposure::Any);
        assert_eq!(of("::"), Exposure::Any);
        assert_eq!(of("127.0.0.53"), Exposure::Loopback);
        assert_eq!(of("::1"), Exposure::Loopback);
        assert_eq!(of("::ffff:127.0.0.1"), Exposure::Loopback);
        assert_eq!(of("192.168.1.10"), Exposure::Specific);
        assert_eq!(of("fe80::1"), Exposure::Specific);
        assert!(Exposure::Loopback < Exposure::Specific && Exposure::Specific < Exposure::Any);
    }
}
