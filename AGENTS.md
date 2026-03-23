# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## Commands

```bash
make build          # Build the wireguard-cni binary via Nix
make test           # Run full test suite in Docker (requires wireguard kernel module)
make test-unit      # Run unit tests only (no e2e, no kernel module required)
make cover          # Generate and display test coverage
make fmt            # Format code via nix fmt (gofmt + nixfmt + actionlint)
make check          # Run nix flake check
make tidy           # Update go.sum and gomod2nix.toml
make docker         # Build container image
```

To run a single Ginkgo test or suite directly:
```bash
ginkgo run --label-filter="!e2e" ./pkg/config/...
ginkgo run -r --focus="<test description>" ./...
```

After changing Go dependencies, run `make tidy` to keep `gomod2nix.toml` in sync with `go.sum` — the CI `clean` job will fail if they diverge.

## Architecture

This is a [CNI (Container Network Interface)](https://github.com/containernetworking/cni) plugin that configures WireGuard interfaces inside container network namespaces.

**Entry point** (`main.go`) — Registers three CNI command handlers using the `skel` library:
- `cmdAdd`: Creates a WireGuard interface in the container's netns, assigns IP, configures peers and routes
- `cmdDel`: Removes the WireGuard interface (idempotent)
- `cmdCheck`: Verifies the interface exists with the correct address and public key

The plugin requires itself to be the **first plugin** in the CNI chain (it errors if `prevResult` is set).

**`pkg/config`** — Parses the CNI stdin JSON into typed structs and validates WireGuard parameters. Key types:
- `NetConf` (embeds `types.NetConf`) — top-level config with `address`, `privateKey`, `listenPort`, `peers`
- `WireGuardConfig.Result()` — builds the CNI `current.Result` (IPs + interface list) returned after `cmdAdd`

**`pkg/wireguard`** — Executes the actual network operations:
- `plugin.go`: Thin dispatch layer calling `name.go` functions within the container's netns
- `name.go`: Uses `netlink` (link/address management) and `wgctrl` (WireGuard device configuration) to create/delete/check the interface and install routes for each peer's `allowedIPs`

**Testing** — Uses Ginkgo v2/Gomega. Unit tests live alongside packages. E2e tests (`e2e_test.go` at the root) are tagged with the `e2e` Ginkgo label and require a real WireGuard kernel module — they use `testutils` from `containernetworking/plugins` to create real network namespaces and invoke the full CNI plugin.

**Nix** — The project uses Nix flakes for reproducible builds. `gomod2nix.toml` is generated from `go.sum` and must be kept in sync. The dev shell (`nix develop`) provides `ginkgo`, `gomod2nix`, `docker`, and formatting tools.
