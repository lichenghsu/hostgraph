use std::collections::HashMap;
use std::net::IpAddr;
use procfs::net::{TcpState, UdpState};
use procfs::process::{all_processes, FDTarget};

use crate::model::{port_id, EdgeKind, Exposure, Graph, NodeKind, Proto};

/// A socket bound to a local port and waiting for traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listener {
    proto: Proto,
    addr: IpAddr,
    port: u16,
    inode: u64,
}

/// Add every listening socket to the graph: a Port node per (proto, port),
/// a Process node per owning pid, and a ListensOn edge (with the bind
/// address) between them.
///
/// Reads the current network namespace only. Without root, sockets owned by
/// other users still appear as Port nodes, just without a Process.
pub fn collect(g: &mut Graph) {
    build(&read_listeners(), &socket_owners(), g);
}

/// Turn listeners and their owners into graph nodes and edges.
fn build(listeners: &[Listener], owners: &HashMap<u64, (i32, String)>, g: &mut Graph) {
    // A port can be bound on several addresses; the node shows the widest.
    let mut widest: HashMap<String, Exposure> = HashMap::new();
    for l in listeners {
        let e = widest.entry(port_id(l.proto, l.port)).or_insert(Exposure::Loopback);
        *e = (*e).max(Exposure::of(l.addr));
    }

    for l in listeners {
        let port_id = port_id(l.proto, l.port);
        let exposure = Some(widest[&port_id]);
        g.add_node(port_id.clone(), NodeKind::Port { proto: l.proto, port: l.port, exposure });

        if let Some((pid, name)) = owners.get(&l.inode) {
            let proc_id = format!("proc:{pid}");
            g.add_node(proc_id.clone(), NodeKind::Process { pid: *pid, name: name.clone() });
            g.add_edge(&proc_id, &port_id, EdgeKind::ListensOn { addr: l.addr });
        }
    }
}


/// Read listening sockets from /proc/net/{tcp,tcp6,udp,udp6}.
///
/// TCP: state LISTEN. UDP has no listen state, so an unconnected bound
/// socket (state CLOSE, remote port 0) counts as listening, same as `ss -ul`.
fn read_listeners() -> Vec<Listener> {
    let mut out = Vec::new();

    for table in [procfs::net::tcp(), procfs::net::tcp6()] {
        for e in table.into_iter().flatten() {
            if e.state == TcpState::Listen {
                out.push(Listener {
                    proto: Proto::Tcp,
                    addr: e.local_address.ip(),
                    port: e.local_address.port(),
                    inode: e.inode,
                });
            }
        }
    }

    for table in [procfs::net::udp(), procfs::net::udp6()] {
        for e in table.into_iter().flatten() {
            if e.state == UdpState::Close && e.remote_address.port() == 0 {
                out.push(Listener {
                    proto: Proto::Udp,
                    addr: e.local_address.ip(),
                    port: e.local_address.port(),
                    inode: e.inode,
                });
            }
        }
    }

    out
}

/// socket inode -> (pid, process name)
///
/// Processes that vanish mid-scan or whose fds we cannot read (other users'
/// processes without root) are skipped, so the map may be partial.
fn socket_owners() -> HashMap<u64, (i32, String)> {
    let mut map = HashMap::new();

    let Ok(procs) = all_processes() else {
        return map;
    };

    for proc in procs.flatten() {
        let Ok(stat) = proc.stat() else { continue };
        let Ok(fds) = proc.fd() else { continue };

        for fd in fds.flatten() {
            if let FDTarget::Socket(inode) = fd.target {
                map.entry(inode).or_insert((proc.pid, stat.comm.clone()));
            }
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};

    #[test]
    fn finds_own_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let inode = procfs::net::tcp()
            .unwrap()
            .into_iter()
            .find(|e| e.local_address.port() == port)
            .expect("listener in /proc/net/tcp")
            .inode;

        let owners = socket_owners();
        let (pid, _) = owners.get(&inode).expect("inode mapped to a process");
        assert_eq!(*pid, std::process::id() as i32);
    }

    fn l(proto: Proto, addr: &str, port: u16, inode: u64) -> Listener {
        Listener { proto, addr: addr.parse().unwrap(), port, inode }
    }

    fn port_exposure(g: &Graph, id: &str) -> Exposure {
        match g.nodes.iter().find(|n| n.id == id).map(|n| &n.kind) {
            Some(NodeKind::Port { exposure: Some(e), .. }) => *e,
            other => panic!("{id} is not a port node: {other:?}"),
        }
    }

    #[test]
    fn build_links_owner_and_skips_unknown() {
        let listeners = vec![
            l(Proto::Tcp, "0.0.0.0", 22, 100),
            // Same port on IPv6: one node, a second edge with its own addr
            l(Proto::Tcp, "::", 22, 101),
            // Owner unknown (no permission): port only
            l(Proto::Udp, "127.0.0.53", 53, 200),
        ];
        let owners = HashMap::from([
            (100, (1, "sshd".to_string())),
            (101, (1, "sshd".to_string())),
        ]);

        let mut g = Graph::default();
        build(&listeners, &owners, &mut g);

        let ids: Vec<_> = g.nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, ["port:tcp:22", "proc:1", "port:udp:53"]);

        let addrs: Vec<_> = g
            .edges
            .iter()
            .map(|e| match &e.kind {
                EdgeKind::ListensOn { addr } => (e.from.as_str(), e.to.as_str(), addr.to_string()),
                other => panic!("unexpected edge {other:?}"),
            })
            .collect();
        assert_eq!(
            addrs,
            [
                ("proc:1", "port:tcp:22", "0.0.0.0".to_string()),
                ("proc:1", "port:tcp:22", "::".to_string()),
            ]
        );

        assert_eq!(port_exposure(&g, "port:udp:53"), Exposure::Loopback);
    }

    #[test]
    fn port_takes_widest_exposure() {
        // Loopback bind first, wildcard second: node must still say Any
        let listeners = vec![
            l(Proto::Tcp, "127.0.0.1", 8080, 1),
            l(Proto::Tcp, "0.0.0.0", 8080, 2),
            l(Proto::Tcp, "192.168.1.10", 9000, 3),
            l(Proto::Tcp, "::1", 9000, 4),
        ];
        let mut g = Graph::default();
        build(&listeners, &HashMap::new(), &mut g);

        assert_eq!(port_exposure(&g, "port:tcp:8080"), Exposure::Any);
        assert_eq!(port_exposure(&g, "port:tcp:9000"), Exposure::Specific);
    }

    #[test]
    fn collect_sees_own_tcp_and_udp() {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp_port = format!("port:tcp:{}", tcp.local_addr().unwrap().port());
        let udp_port = format!("port:udp:{}", udp.local_addr().unwrap().port());
        let me = format!("proc:{}", std::process::id());

        let mut g = Graph::default();
        collect(&mut g);

        for port in [&tcp_port, &udp_port] {
            assert!(
                g.edges.iter().any(|e| e.from == me && &e.to == port),
                "missing edge {me} -> {port}"
            );
        }
    }
}
