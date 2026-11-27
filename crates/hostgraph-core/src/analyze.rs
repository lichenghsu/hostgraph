use std::collections::{BTreeSet, HashMap, HashSet};

use crate::model::{EdgeKind, Exposure, Finding, FindingKind, Graph, NodeKind, Proto};

/// Start of the Linux default ephemeral port range. UDP sockets bound here
/// are almost always client sockets (DNS, mDNS, QUIC), not services.
const EPHEMERAL_START: u16 = 32768;

/// Compare firewall rules with what listens and record mismatches in
/// `g.findings`. Does nothing when no firewall zone was collected.
pub fn run(g: &mut Graph) {
    let accept_zones: Vec<&str> = g
        .nodes
        .iter()
        .filter_map(|n| match &n.kind {
            NodeKind::FirewallZone { name, target, .. } if target == "ACCEPT" => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let has_zones = g.nodes.iter().any(|n| matches!(n.kind, NodeKind::FirewallZone { .. }));
    if !has_zones {
        return;
    }

    // target node id -> zone names that expose it
    let mut exposed_by: HashMap<&str, BTreeSet<&str>> = HashMap::new();
    // A port is served if any socket is bound to it (exposure is set even
    // when the owning process is unknown) or it forwards to a container.
    let mut served: HashSet<&str> = g
        .nodes
        .iter()
        .filter(|n| matches!(n.kind, NodeKind::Port { exposure: Some(_), .. }))
        .map(|n| n.id.as_str())
        .collect();
    for e in &g.edges {
        match e.kind {
            EdgeKind::Exposes { .. } => {
                let zone = e.from.strip_prefix("zone:").unwrap_or(&e.from);
                exposed_by.entry(e.to.as_str()).or_default().insert(zone);
            }
            EdgeKind::ForwardsTo { .. } => {
                served.insert(e.from.as_str());
            }
            _ => {}
        }
    }

    let ranges: Vec<(&str, Proto, u16, u16)> = g
        .nodes
        .iter()
        .filter_map(|n| match n.kind {
            NodeKind::PortRange { proto, from, to } if exposed_by.contains_key(n.id.as_str()) => {
                Some((n.id.as_str(), proto, from, to))
            }
            _ => None,
        })
        .collect();

    let zones_str = |set: &BTreeSet<&str>| set.iter().copied().collect::<Vec<_>>().join(", ");
    let mut findings = Vec::new();
    let mut served_in_range: HashSet<&str> = HashSet::new();

    for n in &g.nodes {
        let NodeKind::Port { proto, port, exposure } = n.kind else { continue };
        let id = n.id.as_str();
        let label = format!("{}/{port}", proto.as_str());
        let is_served = served.contains(id);
        let direct = exposed_by.get(id);
        let range = ranges.iter().find(|(_, p, f, t)| *p == proto && (*f..=*t).contains(&port));
        if is_served {
            if let Some((rid, ..)) = range {
                served_in_range.insert(rid);
            }
        }

        match (direct, is_served) {
            (Some(zones), false) => findings.push(Finding {
                node: id.into(),
                kind: FindingKind::OpenNoListener,
                message: format!("Zone {} opens {label}, but nothing listens on it", zones_str(zones)),
            }),
            (Some(zones), true) if exposure == Some(Exposure::Loopback) => findings.push(Finding {
                node: id.into(),
                kind: FindingKind::OpenLoopbackOnly,
                message: format!(
                    "Zone {} opens {label}, but it is bound to loopback only, so other hosts cannot reach it",
                    zones_str(zones)
                ),
            }),
            (None, true)
                if exposure == Some(Exposure::Any)
                    && range.is_none()
                    && !(proto == Proto::Udp && port >= EPHEMERAL_START) =>
            {
                let mut message = format!("{label} listens on all interfaces, but no zone opens it");
                if !accept_zones.is_empty() {
                    message += &format!("; only reachable via accept-all zones: {}", accept_zones.join(", "));
                }
                findings.push(Finding { node: id.into(), kind: FindingKind::ListenerNotAllowed, message });
            }
            _ => {}
        }
    }

    for (rid, proto, from, to) in &ranges {
        if !served_in_range.contains(rid) {
            findings.push(Finding {
                node: rid.to_string(),
                kind: FindingKind::OpenNoListener,
                message: format!(
                    "Zone {} opens {}/{from}-{to}, but nothing listens in that range",
                    zones_str(&exposed_by[rid]),
                    proto.as_str()
                ),
            });
        }
    }

    g.findings = findings;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::port_id;

    fn port(g: &mut Graph, proto: Proto, p: u16, exposure: Option<Exposure>) -> String {
        let id = port_id(proto, p);
        g.add_node(id.clone(), NodeKind::Port { proto, port: p, exposure });
        id
    }

    fn zone(g: &mut Graph, name: &str, target: &str) -> String {
        let id = format!("zone:{name}");
        g.add_node(id.clone(), NodeKind::FirewallZone { name: name.into(), target: target.into(), sources: vec![] });
        id
    }

    fn listen(g: &mut Graph, port: &str, addr: &str) {
        g.add_node("proc:1".into(), NodeKind::Process { pid: 1, name: "x".into() });
        g.add_edge("proc:1", port, EdgeKind::ListensOn { addr: addr.parse().unwrap() });
    }

    fn expose(g: &mut Graph, zone: &str, target: &str) {
        g.add_edge(zone, target, EdgeKind::Exposes { via: "port".into() });
    }

    fn kinds(g: &Graph) -> Vec<(String, FindingKind)> {
        g.findings.iter().map(|f| (f.node.clone(), f.kind)).collect()
    }

    #[test]
    fn no_zones_no_findings() {
        let mut g = Graph::default();
        let p = port(&mut g, Proto::Tcp, 80, Some(Exposure::Any));
        listen(&mut g, &p, "0.0.0.0");
        run(&mut g);
        assert!(g.findings.is_empty());
    }

    #[test]
    fn detects_each_gap() {
        let mut g = Graph::default();
        let z = zone(&mut g, "public", "default");

        let ok = port(&mut g, Proto::Tcp, 22, Some(Exposure::Any));
        listen(&mut g, &ok, "0.0.0.0");
        expose(&mut g, &z, &ok);

        let unused = port(&mut g, Proto::Tcp, 8080, None);
        expose(&mut g, &z, &unused);

        let lo = port(&mut g, Proto::Tcp, 5432, Some(Exposure::Loopback));
        listen(&mut g, &lo, "127.0.0.1");
        expose(&mut g, &z, &lo);

        let blocked = port(&mut g, Proto::Tcp, 3000, Some(Exposure::Any));
        listen(&mut g, &blocked, "0.0.0.0");

        // Ephemeral UDP client socket: ignored
        let client = port(&mut g, Proto::Udp, 45000, Some(Exposure::Any));
        listen(&mut g, &client, "0.0.0.0");

        run(&mut g);
        assert_eq!(
            kinds(&g),
            [
                (unused, FindingKind::OpenNoListener),
                (lo, FindingKind::OpenLoopbackOnly),
                (blocked, FindingKind::ListenerNotAllowed),
            ]
        );
    }

    #[test]
    fn ranges_cover_listeners_and_report_unused() {
        let mut g = Graph::default();
        let z = zone(&mut g, "public", "default");
        g.add_node("range:udp:1714-1764".into(), NodeKind::PortRange { proto: Proto::Udp, from: 1714, to: 1764 });
        expose(&mut g, &z, "range:udp:1714-1764");
        g.add_node("range:tcp:9000-9010".into(), NodeKind::PortRange { proto: Proto::Tcp, from: 9000, to: 9010 });
        expose(&mut g, &z, "range:tcp:9000-9010");

        // Listener inside the udp range: allowed, and the range is in use
        let kde = port(&mut g, Proto::Udp, 1716, Some(Exposure::Any));
        listen(&mut g, &kde, "::");

        run(&mut g);
        assert_eq!(kinds(&g), [("range:tcp:9000-9010".to_string(), FindingKind::OpenNoListener)]);
    }

    #[test]
    fn listener_with_unknown_owner_counts_as_served() {
        let mut g = Graph::default();
        let z = zone(&mut g, "public", "default");
        // Root-owned sshd: socket seen, process not readable, so no ListensOn edge
        let ssh = port(&mut g, Proto::Tcp, 22, Some(Exposure::Any));
        expose(&mut g, &z, &ssh);
        run(&mut g);
        assert!(g.findings.is_empty());
    }

    #[test]
    fn mentions_accept_zones() {
        let mut g = Graph::default();
        zone(&mut g, "trusted", "ACCEPT");
        let p = port(&mut g, Proto::Tcp, 3000, Some(Exposure::Any));
        listen(&mut g, &p, "0.0.0.0");
        run(&mut g);
        assert!(g.findings[0].message.ends_with("accept-all zones: trusted"));
    }
}
