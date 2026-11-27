// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Re-run by pkexec as the root helper: print socket owners, no GUI
    if std::env::args().nth(1).as_deref() == Some(hostgraph_lib::DUMP_OWNERS_FLAG) {
        hostgraph_lib::dump_socket_owners();
        return;
    }
    hostgraph_lib::run()
}
