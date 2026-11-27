use std::collections::HashMap;
use procfs::net::{TcpState, UdpState};
use procfs::process::{all_processes, FDTarget};

use crate::model::{EdgeKind, Graph, NodeKind, Proto};

/// A socket bound to a local port and waiting for traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listener {
    proto: Proto,
    port: u16,
    inode: u64,
}

/// Add every listening socket to the graph: a Port node per (proto, port),
/// a Process node per owning pid, and a ListensOn edge between them.
///
/// Reads the current network namespace only. Without root, sockets owned by
/// other users still appear as Port nodes, just without a Process.
pub fn collect(g: &mut Graph) {
    build(&read_listeners(), &socket_owners(), g);
}

/// Turn listeners and their owners into graph nodes and edges.
fn build(listeners: &[Listener], owners: &HashMap<u64, (i32, String)>, g: &mut Graph) {
    for l in listeners {
        let proto = match l.proto {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        };
        let port_id = format!("port:{proto}:{}", l.port);
        g.add_node(port_id.clone(), NodeKind::Port { proto: l.proto, port: l.port });

        if let Some((pid, name)) = owners.get(&l.inode) {
            let proc_id = format!("proc:{pid}");
            g.add_node(proc_id.clone(), NodeKind::Process { pid: *pid, name: name.clone() });
            g.add_edge(&proc_id, &port_id, EdgeKind::ListensOn);
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
                out.push(Listener { proto: Proto::Tcp, port: e.local_address.port(), inode: e.inode });
            }
        }
    }

    for table in [procfs::net::udp(), procfs::net::udp6()] {
        for e in table.into_iter().flatten() {
            if e.state == UdpState::Close && e.remote_address.port() == 0 {
                out.push(Listener { proto: Proto::Udp, port: e.local_address.port(), inode: e.inode });
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

    #[test]
    fn build_links_owner_and_skips_unknown() {
        let listeners = vec![
            Listener { proto: Proto::Tcp, port: 22, inode: 100 },
            // Same port on IPv6: must not duplicate the node or the edge
            Listener { proto: Proto::Tcp, port: 22, inode: 101 },
            // Owner unknown (no permission): port only
            Listener { proto: Proto::Udp, port: 53, inode: 200 },
        ];
        let owners = HashMap::from([
            (100, (1, "sshd".to_string())),
            (101, (1, "sshd".to_string())),
        ]);

        let mut g = Graph::default();
        build(&listeners, &owners, &mut g);

        let ids: Vec<_> = g.nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, ["port:tcp:22", "proc:1", "port:udp:53"]);
        assert_eq!(g.edges.len(), 1);
        assert_eq!(g.edges[0].from, "proc:1");
        assert_eq!(g.edges[0].to, "port:tcp:22");
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
