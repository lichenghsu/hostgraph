use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;

use bollard::models::{ContainerSummary, Network, PortSummaryTypeEnum};
use bollard::{Docker, API_DEFAULT_VERSION};

use crate::model::{iface_id, port_id, EdgeKind, Exposure, Graph, NodeKind, Proto};

/// A published (host -> container) port
#[derive(Debug, Clone, PartialEq, Eq)]
struct Published {
    proto: Proto,
    host_ip: Option<IpAddr>,
    host_port: u16,
    container_port: u16,
}

#[derive(Debug, Clone, Default)]
struct Container {
    id: String,
    name: String,
    image: String,
    ports: Vec<Published>,
    /// (node id, display name) of each network the container is attached to
    networks: Vec<(String, String)>,
}

/// Add running docker and podman containers, their published ports
/// (ForwardsTo) and their networks (AttachedTo).
///
/// Talks to each runtime's Docker-compatible API socket. Docker is queried
/// only if dockerd already runs: with socket activation, connecting would
/// start the daemon, and this tool must not change host state.
pub async fn collect(g: &mut Graph) {
    for (runtime, socket) in runtime_sockets() {
        if !socket.exists() {
            continue;
        }
        if runtime == "docker" && !process_running("dockerd") {
            g.warnings.push("docker: dockerd not running, skipped".into());
            continue;
        }
        if let Err(e) = collect_runtime(runtime, &socket, g).await {
            g.warnings.push(format!("{runtime} ({}): {e}", socket.display()));
        }
    }
}

fn runtime_sockets() -> Vec<(&'static str, PathBuf)> {
    let mut v = Vec::new();
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        v.push(("podman", PathBuf::from(dir).join("podman/podman.sock")));
    }
    v.push(("podman", PathBuf::from("/run/podman/podman.sock")));
    v.push(("docker", PathBuf::from("/var/run/docker.sock")));
    v
}

fn process_running(comm: &str) -> bool {
    procfs::process::all_processes()
        .map(|ps| ps.flatten().any(|p| p.stat().is_ok_and(|s| s.comm == comm)))
        .unwrap_or(false)
}

async fn collect_runtime(runtime: &str, socket: &std::path::Path, g: &mut Graph) -> Result<(), String> {
    let path = socket.to_str().ok_or("socket path is not UTF-8")?;
    let docker = Docker::connect_with_unix(path, 5, API_DEFAULT_VERSION).map_err(|e| e.to_string())?;

    let summaries = docker.list_containers(None).await.map_err(|e| e.to_string())?;
    let networks = docker.list_networks(None).await.unwrap_or_default();
    let bridges = bridge_names(&networks);

    let containers: Vec<Container> = summaries
        .iter()
        .map(|s| from_summary(runtime, s, &bridges))
        .collect();
    build(runtime, &containers, g);
    Ok(())
}

/// Network name -> host bridge interface, for bridge-driver networks.
/// Docker names them docker0 / br-<id12> or by the bridge.name option.
fn bridge_names(networks: &[Network]) -> HashMap<String, String> {
    networks
        .iter()
        .filter(|n| n.driver.as_deref() == Some("bridge"))
        .filter_map(|n| {
            let name = n.name.clone()?;
            let opt = n
                .options
                .as_ref()
                .and_then(|o| o.get("com.docker.network.bridge.name"))
                .cloned();
            let iface = opt.or_else(|| n.id.as_ref().map(|id| format!("br-{}", &id[..id.len().min(12)])))?;
            Some((name, iface))
        })
        .collect()
}

fn from_summary(runtime: &str, s: &ContainerSummary, bridges: &HashMap<String, String>) -> Container {
    let id = s.id.clone().unwrap_or_default();
    let name = s
        .names
        .as_ref()
        .and_then(|n| n.first())
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_else(|| id.chars().take(12).collect());

    let ports = s
        .ports
        .iter()
        .flatten()
        .filter_map(|p| {
            let proto = match p.typ {
                Some(PortSummaryTypeEnum::UDP) => Proto::Udp,
                Some(PortSummaryTypeEnum::TCP) | None => Proto::Tcp,
                _ => return None,
            };
            Some(Published {
                proto,
                host_ip: p.ip.as_deref().and_then(|ip| ip.parse().ok()),
                host_port: p.public_port?,
                container_port: p.private_port,
            })
        })
        .collect();

    let mut networks: Vec<(String, String)> = s
        .network_settings
        .as_ref()
        .and_then(|n| n.networks.as_ref())
        .map(|nets| {
            nets.keys()
                .filter(|n| !matches!(n.as_str(), "host" | "none"))
                .map(|n| match bridges.get(n) {
                    // A real host bridge: share the node with the interfaces collector
                    Some(iface) => (iface_id(iface), iface.clone()),
                    None => (format!("net:{runtime}:{n}"), n.clone()),
                })
                .collect()
        })
        .unwrap_or_default();
    networks.sort();

    Container {
        id,
        name,
        image: s.image.clone().unwrap_or_default(),
        ports,
        networks,
    }
}

fn build(runtime: &str, containers: &[Container], g: &mut Graph) {
    for c in containers {
        let short: String = c.id.chars().take(12).collect();
        let ctr_id = format!("ctr:{runtime}:{short}");
        g.add_node(
            ctr_id.clone(),
            NodeKind::Container {
                container_id: short,
                name: c.name.clone(),
                runtime: runtime.to_string(),
                image: c.image.clone(),
            },
        );

        for p in &c.ports {
            let id = port_id(p.proto, p.host_port);
            // Usually present already (docker-proxy or pasta listens on it);
            // otherwise pure DNAT, so derive exposure from the published IP
            let exposure = p.host_ip.map_or(Exposure::Any, Exposure::of);
            g.add_node(
                id.clone(),
                NodeKind::Port { proto: p.proto, port: p.host_port, exposure: Some(exposure) },
            );
            g.add_edge(&id, &ctr_id, EdgeKind::ForwardsTo { container_port: p.container_port });
        }

        for (net_id, name) in &c.networks {
            g.add_node(net_id.clone(), NodeKind::Bridge { name: name.clone() });
            g.add_edge(&ctr_id, net_id, EdgeKind::AttachedTo);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bollard::models::{ContainerSummaryNetworkSettings, EndpointSettings, PortSummary};

    #[test]
    fn maps_summary_ports_and_networks() {
        let s = ContainerSummary {
            id: Some("0123456789abcdef".into()),
            names: Some(vec!["/web".into()]),
            image: Some("nginx".into()),
            ports: Some(vec![
                PortSummary {
                    ip: Some("0.0.0.0".into()),
                    private_port: 80,
                    public_port: Some(8080),
                    typ: Some(PortSummaryTypeEnum::TCP),
                },
                // Exposed but not published: no host port
                PortSummary { ip: None, private_port: 443, public_port: None, typ: Some(PortSummaryTypeEnum::TCP) },
            ]),
            network_settings: Some(ContainerSummaryNetworkSettings {
                networks: Some(HashMap::from([
                    ("bridge".to_string(), EndpointSettings::default()),
                    ("appnet".to_string(), EndpointSettings::default()),
                ])),
            }),
            ..Default::default()
        };
        let bridges = HashMap::from([("bridge".to_string(), "docker0".to_string())]);

        let c = from_summary("docker", &s, &bridges);
        assert_eq!(c.name, "web");
        assert_eq!(
            c.ports,
            [Published { proto: Proto::Tcp, host_ip: Some("0.0.0.0".parse().unwrap()), host_port: 8080, container_port: 80 }]
        );
        assert_eq!(
            c.networks,
            [
                ("if:docker0".to_string(), "docker0".to_string()),
                ("net:docker:appnet".to_string(), "appnet".to_string()),
            ]
        );
    }

    #[test]
    fn build_adds_forward_and_keeps_listener_exposure() {
        let mut g = Graph::default();
        // pasta already listens on loopback for this published port
        g.add_node(
            port_id(Proto::Tcp, 3307),
            NodeKind::Port { proto: Proto::Tcp, port: 3307, exposure: Some(Exposure::Loopback) },
        );
        let c = Container {
            id: "abcdef0123456789".into(),
            name: "db".into(),
            image: "mysql".into(),
            ports: vec![
                Published { proto: Proto::Tcp, host_ip: Some("127.0.0.1".parse().unwrap()), host_port: 3307, container_port: 3306 },
                Published { proto: Proto::Udp, host_ip: None, host_port: 5353, container_port: 53 },
            ],
            networks: vec![],
        };

        build("podman", &[c], &mut g);

        assert!(g.has_node("ctr:podman:abcdef012345"));
        assert!(g.edges.iter().any(|e| e.from == "port:tcp:3307"
            && e.to == "ctr:podman:abcdef012345"
            && e.kind == EdgeKind::ForwardsTo { container_port: 3306 }));
        let udp = g.nodes.iter().find(|n| n.id == "port:udp:5353").unwrap();
        assert!(matches!(udp.kind, NodeKind::Port { exposure: Some(Exposure::Any), .. }));
    }
}
