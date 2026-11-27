use std::fs;
use std::path::Path;

use crate::model::{iface_id, Graph, NodeKind};

/// Add host network interfaces from /sys/class/net.
///
/// Bridges (a `bridge/` subdirectory exists) become Bridge nodes, the rest
/// Interface nodes. Loopback and veth pairs are skipped: veths are the
/// container side of a bridge and only add noise.
pub fn collect(g: &mut Graph) {
    collect_from(Path::new("/sys/class/net"), g);
}

fn collect_from(root: &Path, g: &mut Graph) {
    let Ok(entries) = fs::read_dir(root) else { return };

    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n != "lo" && !n.starts_with("veth"))
        .collect();
    names.sort();

    for name in names {
        let kind = if root.join(&name).join("bridge").is_dir() {
            NodeKind::Bridge { name: name.clone() }
        } else {
            NodeKind::Interface { name: name.clone() }
        };
        g.add_node(iface_id(&name), kind);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_bridges_and_skips_noise() {
        let dir = std::env::temp_dir().join(format!("hostgraph-ifaces-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for p in ["lo", "eth0", "veth1234", "br0/bridge"] {
            fs::create_dir_all(dir.join(p)).unwrap();
        }

        let mut g = Graph::default();
        collect_from(&dir, &mut g);
        fs::remove_dir_all(&dir).unwrap();

        let got: Vec<_> = g
            .nodes
            .iter()
            .map(|n| match &n.kind {
                NodeKind::Bridge { name } => format!("bridge {name}"),
                NodeKind::Interface { name } => format!("iface {name}"),
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(got, ["bridge br0", "iface eth0"]);
    }
}
