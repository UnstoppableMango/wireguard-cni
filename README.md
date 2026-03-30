# wireguard-cni

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/UnstoppableMango/wireguard-cni/badge)](https://scorecard.dev/viewer/?uri=github.com/UnstoppableMango/wireguard-cni)

A [CNI (Container Network Interface)](https://github.com/containernetworking/cni) plugin that configures WireGuard interfaces inside container network namespaces.

## How it works

When invoked by the container runtime, the plugin:

1. Creates a WireGuard interface in the container's network namespace
2. Assigns the configured IP address
3. Configures peers and installs routes for each peer's `allowedIPs`

For the CNI `ADD` command, the plugin must be the **first** (and typically only) plugin in the CNI chain and must not receive a `prevResult`. For the CNI `CHECK` command, the plugin expects a valid `prevResult` from a prior `ADD` in the chain.

## Configuration

The plugin is configured via a standard CNI conflist. Example:

```json
{
  "cniVersion": "1.0.0",
  "name": "wireguard",
  "plugins": [
    {
      "type": "wireguard-cni",
      "runtimeConfig": {
        "ips": ["10.100.0.1/24"]
      },
      "privateKey": "REPLACE_WITH_WG_PRIVATE_KEY",
      "listenPort": 51820,
      "peers": [
        {
          "publicKey": "PEER_PUBLIC_KEY",
          "endpoint": "192.168.1.2:51820",
          "allowedIPs": ["10.100.0.2/32"],
          "persistentKeepalive": 25
        }
      ]
    }
  ]
}
```

### Fields

| Field | Required | Description |
|---|---|---|
| `runtimeConfig.ips` | yes | IP address(es) (CIDR) assigned to the WireGuard interface |
| `privateKey` | yes | Base64-encoded WireGuard private key |
| `listenPort` | no | UDP port to listen on |
| `peers` | no | List of WireGuard peers |

Each peer:

| Field | Required | Description |
|---|---|---|
| `publicKey` | yes | Base64-encoded peer public key |
| `allowedIPs` | no | CIDR ranges routed through this peer |
| `endpoint` | no | `host:port` of the peer |
| `persistentKeepalive` | no | Keepalive interval in seconds |

## Kubernetes deployment

The plugin ships as a container image that installs the binary and CNI config via a DaemonSet init container.

### Deploy with kustomize

```bash
kubectl apply -k kustomize/overlays/default
```

Before deploying, update the `10-wireguard.conflist` in `kustomize/base/configmap.yaml` with your WireGuard keys and peer configuration.

The DaemonSet copies the binary to `/opt/cni/bin/wireguard-cni` and the conflist to `/etc/cni/net.d/10-wireguard.conflist` on each node.

### Local development with KIND

```bash
make kind          # create cluster and deploy the plugin
make kind-delete   # tear down the cluster
```

## Building

Requires [Nix](https://nixos.org/):

```bash
make build    # build the binary (output: bin/wireguard-cni)
make docker   # build the container image (output: bin/image.tar)
```

## Testing

```bash
make test-unit   # unit tests (no kernel module required)
make test        # full e2e suite in Docker (requires WireGuard kernel module)
make test-k8s    # Kubernetes e2e tests (requires a running cluster)
```

## Requirements

- Linux (WireGuard kernel module)
- CNI spec version 1.0.0+

## Prior art

- <https://github.com/schu/wireguard-cni>
