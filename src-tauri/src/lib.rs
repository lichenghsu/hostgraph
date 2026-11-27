use hostgraph_core::collect::collect_all;
use hostgraph_core::model::Graph;

/// Collect the host's current network state as a graph: interfaces,
/// listening sockets, firewalld zones, containers, and the gaps between them.
#[tauri::command]
async fn get_graph() -> Graph {
    collect_all().await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![get_graph])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
