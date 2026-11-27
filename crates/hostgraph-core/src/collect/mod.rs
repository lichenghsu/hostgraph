pub mod containers;
pub mod firewalld;
pub mod interfaces;
pub mod sockets;

use crate::analyze;
use crate::model::Graph;

/// Run every collector and the gap analysis.
///
/// A collector that fails adds a line to `Graph::warnings` instead of
/// failing the whole scan, so the graph shows whatever could be read.
pub async fn collect_all() -> Graph {
    // /proc and /sys scans are blocking file reads
    let mut g = tokio::task::spawn_blocking(|| {
        let mut g = Graph::default();
        interfaces::collect(&mut g);
        sockets::collect(&mut g);
        g
    })
    .await
    .unwrap_or_default();

    // After interfaces, so zones can link to them
    if let Err(e) = firewalld::collect(&mut g).await {
        g.warnings.push(format!("firewalld: {e}"));
    }
    containers::collect(&mut g).await;

    analyze::run(&mut g);
    g
}
