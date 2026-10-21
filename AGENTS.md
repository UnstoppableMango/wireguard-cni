# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## Commands

```bash
make build          # Build the wireguard-cni binary via Nix
make test           # Run full test suite in Docker (excludes k8s tests; requires wireguard kernel module)
make test-unit      # Run unit tests only (no e2e, no kernel module required)
make test-k8s       # Run Kubernetes e2e tests (requires a running cluster)
make cover          # Generate and display test coverage
make fmt            # Format code via nix fmt (gofmt + nixfmt + actionlint)
make check          # Run nix flake check
make tidy           # Update go.sum and gomod2nix.toml
make docker         # Build container image
make kind           # Create KIND cluster and deploy CNI plugin
make kind-delete    # Delete KIND cluster
```

To run a single Ginkgo test or suite directly:
```bash
ginkgo run --label-filter="!e2e" ./pkg/config/...
ginkgo run -r --focus="<test description>" ./...
```

After changing Go dependencies, run `make tidy` to keep `gomod2nix.toml` in sync with `go.sum` — the CI `clean` job will fail if they diverge.

## CNI Specification

See `CNI_SPEC.md` in the project root for the condensed CNI v1.1.0 spec reference.
Do NOT fetch the upstream URL — use the local file instead.

## Architecture

This is a [CNI (Container Network Interface)](https://github.com/containernetworking/cni) plugin that configures WireGuard interfaces inside container network namespaces.

**Entry point** (`main.go`) — Linux-only (`//go:build linux`). Sets up structured logging (zap/JSON to stderr) and registers three CNI command handlers via `skel.PluginMainFuncs()`:
- `cmd.Add`: Creates a WireGuard interface in the container's netns, assigns IP, configures peers and routes
- `cmd.Del`: Removes the WireGuard interface (idempotent)
- `cmd.Check`: Verifies the interface exists with the correct address and public key

The plugin requires itself to be the **first plugin** in the CNI chain (it errors if `prevResult` is set).

**`pkg/cmd`** — CNI command handler implementations (Linux-specific):
- `cni_linux.go`: `Add()`, `Del()`, `Check()` functions — delegates to `pkg/wireguard` and `pkg/network`
- `cni.go`: Shared constants and logger utilities
- `unsupported.go`: Non-Linux panic fallback

**`pkg/config`** — Parses the CNI stdin JSON into typed structs and validates WireGuard parameters. Key types:
- `Config` (embeds `types.PluginConf`) — top-level config with `address`, `privateKey`, `listenPort`, `peers`
- `Config.Result()` — builds the CNI `current.Result` (IPs + interface list) returned after `cmdAdd`
- `Config.Wireguard()` — builds `*wgtypes.Config` for wgctrl

**`pkg/wireguard`** — High-level WireGuard plugin logic:
- `plugin.go`: `Add()`, `Check()`, `setup()` — orchestrates interface creation, address assignment, peer config, and route installation within the container's netns

**`pkg/network`** — Low-level network operations (Linux-specific):
- `link.go`: `Link` and `LinkManager` interfaces abstracting netlink operations
- `linux.go`: `netlinkManager` implementation using `vishvananda/netlink`
- `wg_linux.go`: `ConfigureWireGuard()` and `PublicKey()` using `wgctrl`
- `unsupported.go`: Non-Linux panic fallback

**Testing** — Uses Ginkgo v2/Gomega. Unit tests live alongside packages. E2e tests live in `test/e2e/`:
- `e2e_test.go`: Tagged with `"e2e"` label — requires a real WireGuard kernel module, uses `testutils` from `containernetworking/plugins` to create real network namespaces
- `k8s_test.go`: Tagged with `"k8s"` label — deploys to a real Kubernetes cluster via `test/utils/` helpers (`Client`, `Pod` types, `InvokeCNI()`)

**Nix** — The project uses Nix flakes for reproducible builds. `gomod2nix.toml` is generated from `go.sum` and must be kept in sync. The dev shell (`nix develop`) provides `ginkgo`, `gomod2nix`, `docker`, and formatting tools.
