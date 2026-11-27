use hostgraph_core::collect::sockets;
use hostgraph_core::model::Graph;

/// Collect the host's current network state as a graph.
///
/// Scanning /proc walks every process's fds, so run it off the main thread
/// to keep the window responsive.
#[tauri::command]
async fn get_graph() -> Result<Graph, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let mut g = Graph::default();
        sockets::collect(&mut g);
        g
    })
    .await
    .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![get_graph])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
