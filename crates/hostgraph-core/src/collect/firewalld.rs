use std::collections::{BTreeMap, HashMap};

use serde::de::DeserializeOwned;
use zbus::OwnedVariant;
use zbus::zvariant::{DynamicType, Type};

use crate::model::{iface_id, port_id, EdgeKind, Graph, NodeKind, Proto};

const DEST: &str = "org.fedoraproject.FirewallD1";
const PATH: &str = "/org/fedoraproject/FirewallD1";
const IFACE_MAIN: &str = "org.fedoraproject.FirewallD1";
const IFACE_ZONE: &str = "org.fedoraproject.FirewallD1.zone";

/// Runtime settings of one active firewalld zone
#[derive(Debug, Default, Clone)]
struct Zone {
    name: String,
    target: String,
    /// The default zone also takes every interface no zone claims
    is_default: bool,
    interfaces: Vec<String>,
    sources: Vec<String>,
    services: Vec<String>,
    /// (port or "from-to", protocol)
    ports: Vec<(String, String)>,
    /// Rich rules as strings
    rules: Vec<String>,
}

/// Add active firewalld zones (plus the default zone) and the ports each
/// one opens.
///
/// Reads runtime state over the system D-Bus; this needs no root on a
/// default polkit setup. Interface nodes must already be in the graph for
/// InZone edges to appear.
pub async fn collect(g: &mut Graph) -> Result<(), String> {
    let conn = zbus::Connection::system().await.map_err(|e| e.to_string())?;

    let active: HashMap<String, HashMap<String, Vec<String>>> =
        call(&conn, IFACE_ZONE, "getActiveZones", &()).await?;
    // Sorted for stable output
    let mut active: BTreeMap<_, _> = active.into_iter().collect();

    // Interfaces with no explicit zone fall into the default zone, which is
    // not listed as active unless something is bound to it.
    let default: String = call(&conn, IFACE_MAIN, "getDefaultZone", &()).await?;
    active.entry(default.clone()).or_default();

    let mut zones = Vec::new();
    let mut services: HashMap<String, Vec<(String, String)>> = HashMap::new();

    for (name, binding) in active {
        let s: HashMap<String, OwnedVariant> =
            call(&conn, IFACE_ZONE, "getZoneSettings2", &(name.as_str(),)).await?;

        let zone = Zone {
            target: string(&s, "target").unwrap_or_else(|| "default".into()),
            is_default: name == default,
            interfaces: binding.get("interfaces").cloned().unwrap_or_default(),
            sources: binding.get("sources").cloned().unwrap_or_default(),
            services: strings(&s, "services"),
            ports: pairs(&s, "ports"),
            rules: strings(&s, "rules_str"),
            name,
        };

        let rule_services = zone.rules.iter().filter_map(|r| attr(r, "service name"));
        for svc in zone.services.iter().cloned().chain(rule_services) {
            if services.contains_key(&svc) {
                continue;
            }
            // An unknown service resolves to no ports rather than failing the zone
            let ports = match call::<_, HashMap<String, OwnedVariant>>(
                &conn,
                IFACE_MAIN,
                "getServiceSettings2",
                &(svc.as_str(),),
            )
            .await
            {
                Ok(s) => pairs(&s, "ports"),
                Err(_) => Vec::new(),
            };
            services.insert(svc, ports);
        }

        zones.push(zone);
    }

    build(&zones, &services, g);
    Ok(())
}

async fn call<B, R>(conn: &zbus::Connection, iface: &str, method: &str, body: &B) -> Result<R, String>
where
    B: serde::Serialize + DynamicType,
    R: DeserializeOwned + Type,
{
    let msg = conn
        .call_method(Some(DEST), PATH, Some(iface), method, body)
        .await
        .map_err(|e| format!("{method}: {e}"))?;
    msg.body().deserialize::<R>().map_err(|e| format!("{method}: {e}"))
}

fn string(m: &HashMap<String, OwnedVariant>, key: &str) -> Option<String> {
    let v = m.get(key)?.try_clone().ok()?;
    String::try_from(v).ok()
}

fn strings(m: &HashMap<String, OwnedVariant>, key: &str) -> Vec<String> {
    m.get(key)
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::<String>::try_from(v).ok())
        .unwrap_or_default()
}

fn pairs(m: &HashMap<String, OwnedVariant>, key: &str) -> Vec<(String, String)> {
    m.get(key)
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::<(String, String)>::try_from(v).ok())
        .unwrap_or_default()
}

/// Turn zones into graph nodes and edges.
fn build(zones: &[Zone], services: &HashMap<String, Vec<(String, String)>>, g: &mut Graph) {
    let claimed: Vec<&String> = zones.iter().flat_map(|z| &z.interfaces).collect();
    let unclaimed: Vec<String> = g
        .nodes
        .iter()
        .filter_map(|n| match &n.kind {
            NodeKind::Interface { name } | NodeKind::Bridge { name }
                if n.id.starts_with("if:") && !claimed.contains(&name) =>
            {
                Some(name.clone())
            }
            _ => None,
        })
        .collect();

    for z in zones {
        let zone_id = format!("zone:{}", z.name);
        g.add_node(
            zone_id.clone(),
            NodeKind::FirewallZone {
                name: z.name.clone(),
                target: z.target.clone(),
                sources: z.sources.clone(),
            },
        );

        let implicit = if z.is_default { unclaimed.as_slice() } else { &[] };
        for iface in z.interfaces.iter().chain(implicit) {
            let id = iface_id(iface);
            // Zones may list interfaces that do not exist right now
            if g.has_node(&id) {
                g.add_edge(&id, &zone_id, EdgeKind::InZone);
            }
        }

        for (port, proto) in &z.ports {
            expose(g, &zone_id, port, proto, "port");
        }

        for svc in &z.services {
            for (port, proto) in services.get(svc).into_iter().flatten() {
                expose(g, &zone_id, port, proto, &format!("service:{svc}"));
            }
        }

        for rule in z.rules.iter().filter(|r| accepts(r)) {
            let via = match attr(rule, "source address") {
                Some(src) => format!("rule:{src}"),
                None => "rule".to_string(),
            };
            if let Some((port, proto)) = rule_port(rule) {
                expose(g, &zone_id, &port, &proto, &via);
            }
            if let Some(svc) = attr(rule, "service name") {
                for (port, proto) in services.get(&svc).into_iter().flatten() {
                    expose(g, &zone_id, port, proto, &via);
                }
            }
        }
    }
}

/// Add an Exposes edge from a zone to a port ("22") or range ("1714-1764").
fn expose(g: &mut Graph, zone_id: &str, port: &str, proto: &str, via: &str) {
    let Some(proto) = Proto::parse(proto) else { return };
    let (from, to) = match port.split_once('-') {
        Some((a, b)) => (a.parse::<u16>(), b.parse::<u16>()),
        None => (port.parse::<u16>(), port.parse::<u16>()),
    };
    let (Ok(from), Ok(to)) = (from, to) else { return };

    let id = if from == to {
        let id = port_id(proto, from);
        // Keeps the exposure from the sockets collector if it ran first
        g.add_node(id.clone(), NodeKind::Port { proto, port: from, exposure: None });
        id
    } else {
        let id = format!("range:{}:{from}-{to}", proto.as_str());
        g.add_node(id.clone(), NodeKind::PortRange { proto, from, to });
        id
    };
    g.add_edge(zone_id, &id, EdgeKind::Exposes { via: via.to_string() });
}

fn accepts(rule: &str) -> bool {
    rule.split_whitespace().any(|t| t == "accept")
}

/// Value of `key="value"` in a rich rule.
fn attr(rule: &str, key: &str) -> Option<String> {
    let start = rule.find(&format!("{key}=\""))? + key.len() + 2;
    let len = rule[start..].find('"')?;
    Some(rule[start..start + len].to_string())
}

/// The `port port="X" protocol="Y"` element of a rich rule, if present.
/// Skips forward-port and source-port, which use the same attribute names.
fn rule_port(rule: &str) -> Option<(String, String)> {
    let at = rule.find(" port port=\"")?;
    let rest = &rule[at + 1..];
    Some((attr(rest, "port")?, attr(rest, "protocol")?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Exposure;

    fn zone(name: &str) -> Zone {
        Zone { name: name.into(), target: "default".into(), ..Default::default() }
    }

    fn exposes(g: &Graph) -> Vec<(String, String, String)> {
        g.edges
            .iter()
            .filter_map(|e| match &e.kind {
                EdgeKind::Exposes { via } => Some((e.from.clone(), e.to.clone(), via.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn default_zone_takes_unclaimed_interfaces() {
        let mut g = Graph::default();
        for name in ["wlo1", "eno2"] {
            g.add_node(iface_id(name), NodeKind::Interface { name: name.into() });
        }
        let mut block = zone("block");
        block.interfaces = vec!["wlo1".into()];
        let mut ws = zone("FedoraWorkstation");
        ws.is_default = true;

        build(&[block, ws], &HashMap::new(), &mut g);

        let in_zone: Vec<_> = g.edges.iter().map(|e| (e.from.as_str(), e.to.as_str())).collect();
        assert_eq!(in_zone, [("if:wlo1", "zone:block"), ("if:eno2", "zone:FedoraWorkstation")]);
    }

    #[test]
    fn parses_rich_rules() {
        let r = r#"rule family="ipv4" source address="192.168.122.0/24" port port="5432" protocol="tcp" accept"#;
        assert!(accepts(r));
        assert_eq!(attr(r, "source address").as_deref(), Some("192.168.122.0/24"));
        assert_eq!(rule_port(r), Some(("5432".into(), "tcp".into())));

        let fwd = r#"rule family="ipv4" forward-port port="80" protocol="tcp" to-port="8080""#;
        assert_eq!(rule_port(fwd), None);
        assert!(!accepts(r#"rule service name="ssh" reject"#));
    }

    #[test]
    fn builds_zone_ports_services_and_rules() {
        let mut g = Graph::default();
        g.add_node(iface_id("wlo1"), NodeKind::Interface { name: "wlo1".into() });
        // Already listening: firewall must not overwrite its exposure
        g.add_node(
            port_id(Proto::Tcp, 22),
            NodeKind::Port { proto: Proto::Tcp, port: 22, exposure: Some(Exposure::Any) },
        );

        let mut z = zone("public");
        z.interfaces = vec!["wlo1".into(), "gone0".into()];
        z.ports = vec![("8080".into(), "tcp".into()), ("1714-1764".into(), "udp".into())];
        z.services = vec!["ssh".into(), "nonexistent".into()];
        z.rules = vec![
            r#"rule family="ipv4" source address="10.0.0.0/8" port port="5432" protocol="tcp" accept"#.into(),
        ];
        let services = HashMap::from([("ssh".to_string(), vec![("22".into(), "tcp".into())])]);

        build(&[z], &services, &mut g);

        assert!(g.edges.iter().any(|e| e.from == "if:wlo1" && e.to == "zone:public" && e.kind == EdgeKind::InZone));
        assert!(!g.edges.iter().any(|e| e.from == "if:gone0"));

        assert_eq!(
            exposes(&g),
            [
                ("zone:public".into(), "port:tcp:8080".into(), "port".into()),
                ("zone:public".into(), "range:udp:1714-1764".into(), "port".into()),
                ("zone:public".into(), "port:tcp:22".into(), "service:ssh".into()),
                ("zone:public".into(), "port:tcp:5432".into(), "rule:10.0.0.0/8".into()),
            ]
        );

        let ssh = g.nodes.iter().find(|n| n.id == "port:tcp:22").unwrap();
        assert!(matches!(ssh.kind, NodeKind::Port { exposure: Some(Exposure::Any), .. }));
    }
}
