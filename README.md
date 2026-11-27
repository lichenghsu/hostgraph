# hostgraph

> See what is open on your host, and where the traffic goes.

[<img src="https://img.shields.io/badge/license-MIT%20%7C%20Apache--2.0-blue?style=for-the-badge"/>][license]
[<img src="https://img.shields.io/badge/status-early%20development-orange?style=for-the-badge"/>][repo]
[<img src="https://img.shields.io/badge/platform-linux-FCC624?style=for-the-badge&logo=linux&logoColor=black"/>][repo]

### Built with

[<img src="https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white"/>][rust]
[<img src="https://img.shields.io/badge/tauri-%2324C8DB.svg?style=for-the-badge&logo=tauri&logoColor=white"/>][tauri]
[<img src="https://img.shields.io/badge/react-%2320232a.svg?style=for-the-badge&logo=react&logoColor=%2361DAFB"/>][react]
[<img src="https://img.shields.io/badge/typescript-%23007ACC.svg?style=for-the-badge&logo=typescript&logoColor=white"/>][typescript]
[<img src="https://img.shields.io/badge/vite-%23646CFF.svg?style=for-the-badge&logo=vite&logoColor=white"/>][vite]
[<img src="https://img.shields.io/badge/react%20flow-%23FF0072.svg?style=for-the-badge&logo=react&logoColor=white"/>][reactflow]
[<img src="https://img.shields.io/badge/pnpm-%234a4a4a.svg?style=for-the-badge&logo=pnpm&logoColor=%23F69220"/>][pnpm]

hostgraph is a desktop app that draws your Linux host's network exposure as an interactive, drag-and-drop graph. It shows both directions: what the outside world can reach on your machine, and how that traffic gets to processes and containers.

**Status:** working prototype. Listening sockets, firewalld, podman/docker and bridges are collected; nftables and Kubernetes are not yet.

## Why

You open a firewall port so another machine can reach a project. Then podman, docker, and a kind cluster each add their own port forwarding, bridges, and NAT rules on top. A few weeks later you no longer know which ports are open, which are still in use, and which container sits behind which one.

hostgraph collects all of that into one picture.

## Features

- **Listening sockets:** every listening TCP/UDP port, its bind address (loopback, one interface, or all), and the process that owns it
- **Firewall:** active firewalld zones plus the default zone, their interfaces, and the ports they open through ports, services, port ranges and rich rules
- **Container forwarding:** podman and docker published ports, linked to the container behind them
- **Bridges:** host bridges such as `virbr*` and `docker0`, and container networks
- **Gap detection:** flags ports the firewall opens with nothing listening, ports opened but bound to loopback only, and services listening on all interfaces that no zone allows
- **Canvas:** drag nodes, search, filter (loopback, unlinked, findings only), and click a node or finding for details

Planned:

- **nftables:** rules outside firewalld (`nft -j list ruleset`)
- **Kubernetes:** k8s and kind services, NodePorts, and pods

## Architecture

```
hostgraph/
├── crates/hostgraph-core/   # Rust library: collects host state into a graph model
├── src-tauri/               # Tauri 2 app: exposes hostgraph-core to the UI
└── src/                     # React + TypeScript UI, canvas built on React Flow
```

`hostgraph-core` has no UI dependencies, so a CLI or TUI can reuse it later.

Data sources:

| Source | How |
|--------|-----|
| Listening sockets | `/proc/net/{tcp,udp}{,6}` and `/proc/<pid>/fd` (`procfs`) |
| Interfaces and bridges | `/sys/class/net` |
| firewalld | system D-Bus (`zbus`) |
| docker / podman | Docker-compatible API socket (`bollard`) |
| nftables (planned) | `nft -j list ruleset` |
| Kubernetes (planned) | kube API (`kube`) |

## Development

Requirements:

- Rust (stable, edition 2024)
- Node.js and pnpm
- Tauri 2 system dependencies: see the [Tauri prerequisites](https://tauri.app/start/prerequisites/)

```bash
git clone https://github.com/lichenghsu/hostgraph.git
cd hostgraph
pnpm install
pnpm tauri dev
```

Test the Rust workspace, or print the collected graph as JSON without the UI:

```bash
cargo test --workspace
cargo run -p hostgraph-core --example dump
```

hostgraph only reads host state; it never changes firewall or container configuration. Without root, ports owned by other users appear without a process. Docker is queried only if `dockerd` is already running, because connecting to a socket-activated `docker.sock` would start the daemon.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

[repo]: https://github.com/lichenghsu/hostgraph
[license]: #license
[rust]: https://www.rust-lang.org/
[tauri]: https://tauri.app/
[react]: https://react.dev/
[typescript]: https://www.typescriptlang.org/
[vite]: https://vite.dev/
[reactflow]: https://reactflow.dev/
[pnpm]: https://pnpm.io/
