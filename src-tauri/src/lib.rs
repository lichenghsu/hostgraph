use std::process::Command;

use hostgraph_core::collect::collect_all_with;
use hostgraph_core::collect::sockets::{self, Owners};
use hostgraph_core::model::Graph;

/// Command-line flag that turns the app binary into the root helper.
pub const DUMP_OWNERS_FLAG: &str = "--dump-socket-owners";

/// Root helper entry point: print the socket inode -> process map as JSON.
///
/// This is the only code that runs as root. It reads /proc, takes no input
/// and changes nothing.
pub fn dump_socket_owners() {
    let owners = sockets::socket_owners();
    println!("{}", serde_json::to_string(&owners).expect("owners serialize"));
}

/// Collect the host's current network state as a graph: interfaces,
/// listening sockets, firewalld zones, containers, and the gaps between them.
///
/// With `privileged`, socket owners are read by this binary re-run as root
/// through pkexec, so ports owned by other users get their process. If that
/// fails or is cancelled, the scan continues unprivileged with a warning.
#[tauri::command]
async fn get_graph(privileged: bool) -> Graph {
    let (owners, warning) = if privileged {
        match tauri::async_runtime::spawn_blocking(read_owners_as_root).await {
            Ok(Ok(owners)) => (owners, None),
            Ok(Err(e)) => (Owners::new(), Some(e)),
            Err(e) => (Owners::new(), Some(e.to_string())),
        }
    } else {
        (Owners::new(), None)
    };

    let mut g = collect_all_with(owners).await;
    if let Some(w) = warning {
        g.warnings.insert(0, format!("root scan: {w}"));
    }
    g
}

fn read_owners_as_root() -> Result<Owners, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let out = Command::new("pkexec")
        .arg(&exe)
        .arg(DUMP_OWNERS_FLAG)
        .output()
        .map_err(|e| format!("cannot run pkexec: {e}"))?;

    // pkexec: 126 = dialog dismissed, 127 = not authorized or failed
    match out.status.code() {
        Some(0) => serde_json::from_slice(&out.stdout).map_err(|e| format!("bad helper output: {e}")),
        Some(126) => Err("authentication cancelled".into()),
        Some(127) => Err("not authorized".into()),
        _ => Err(String::from_utf8_lossy(&out.stderr).trim().to_string()),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![get_graph])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
