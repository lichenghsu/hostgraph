use std::net::IpAddr;

use serde::Serialize;

/// Transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
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
    Bridge {
        name: String,
    },
    FirewallZone {
        name: String,
    },
    Port {
        proto: Proto,
        port: u16,
        /// Widest exposure among all sockets bound to this port
        exposure: Exposure,
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
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EdgeKind {
    /// zone -> port
    Exposes,
    /// process -> port, bound on `addr`
    ListensOn { addr: IpAddr },
    /// port -> container (DNAT)
    ForwardsTo,
    /// container -> bridge
    AttachedTo,
}

#[derive(Debug, Clone, Serialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    #[serde(flatten)]
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
                exposure: Exposure::Any,
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
