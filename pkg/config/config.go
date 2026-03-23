package config

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
)

type PeerConfig struct {
	PublicKey           string   `json:"publicKey"`
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowedIPs"`
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"`
}

func (c *PeerConfig) ResolveUDPEndpoint() (*net.UDPAddr, error) {
	if c.Endpoint == "" {
		return nil, nil
	}
	return net.ResolveUDPAddr("udp", c.Endpoint)
}

type Config struct {
	types.PluginConf
	Address    string       `json:"address"`
	PrivateKey string       `json:"privateKey"`
	ListenPort int          `json:"listenPort,omitempty"`
	Peers      []PeerConfig `json:"peers"`
}

func Parse(stdin []byte) (*Config, error) {
	var conf Config
	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}
	if err := version.ParsePrevResult(&conf.PluginConf); err != nil {
		return nil, fmt.Errorf("failed to parse prevResult: %v", err)
	}

	return &conf, nil
}

// Result constructs the CNI result for a WireGuard interface.
// WireGuard uses AllowedIPs for routing so no gateway is set.
func (c *Config) Result(args *skel.CmdArgs) (*current.Result, error) {
	ip, ipnet, err := net.ParseCIDR(c.Address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %v", c.Address, err)
	}

	return &current.Result{
		CNIVersion: c.CNIVersion,
		Interfaces: []*current.Interface{{
			Name:    args.IfName,
			Sandbox: args.Netns,
		}},
		IPs: []*current.IPConfig{{
			Interface: new(0),
			Address: net.IPNet{
				IP:   ip,
				Mask: ipnet.Mask,
			},
		}},
		Routes: []*types.Route{},
	}, nil
}

func (c *Config) PrintResult(args *skel.CmdArgs) error {
	if result, err := c.Result(args); err != nil {
		return err
	} else {
		return types.PrintResult(result, c.CNIVersion)
	}
}
