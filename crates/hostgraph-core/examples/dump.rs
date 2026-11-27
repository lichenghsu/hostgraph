//! Print the collected graph as JSON: `cargo run -p hostgraph-core --example dump`

#[tokio::main]
async fn main() {
    let g = hostgraph_core::collect::collect_all().await;
    println!("{}", serde_json::to_string_pretty(&g).expect("graph serializes"));
}
