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

func (c *PeerConfig) ResolveUDPAddr() (*net.UDPAddr, error) {
	if c.Endpoint == "" {
		return nil, nil
	}
	return net.ResolveUDPAddr("udp", c.Endpoint)
}

type Config struct {
	types.PluginConf
	RuntimeConfig struct {
		IPs []string `json:"ips,omitempty"`
	} `json:"runtimeConfig,omitempty"`
	PrivateKey string       `json:"privateKey"`
	ListenPort int          `json:"listenPort,omitempty"`
	Peers      []PeerConfig `json:"peers"`
}

func Parse(stdin []byte) (*Config, error) {
	var conf Config
	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %w", err)
	}
	if err := version.ParsePrevResult(&conf.PluginConf); err != nil {
		return nil, fmt.Errorf("failed to parse prevResult: %w", err)
	}

	if len(conf.RuntimeConfig.IPs) == 0 {
		return nil, fmt.Errorf("runtimeConfig.ips is required but was not provided")
	}

	return &conf, nil
}

// Result constructs the CNI result for a WireGuard interface.
// WireGuard uses AllowedIPs for routing so no gateway is set.
func (c *Config) Result(args *skel.CmdArgs) (*current.Result, error) {
	ip, ipnet, err := net.ParseCIDR(c.RuntimeConfig.IPs[0])
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", c.RuntimeConfig.IPs[0], err)
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

// MergedResult returns the CNI result for this Add invocation.
// In chained mode (PrevResult != nil), the WireGuard interface and IP are
// appended to prevResult. Otherwise a standalone WireGuard-only result is returned.
func (c *Config) MergedResult(args *skel.CmdArgs) (*current.Result, error) {
	if c.PrevResult == nil {
		return c.Result(args)
	}

	prev, err := current.GetResult(c.PrevResult)
	if err != nil {
		return nil, fmt.Errorf("failed to convert prevResult: %w", err)
	}
	ip, ipnet, err := net.ParseCIDR(c.RuntimeConfig.IPs[0])
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", c.RuntimeConfig.IPs[0], err)
	}

	idx := len(prev.Interfaces)
	prev.Interfaces = append(prev.Interfaces, &current.Interface{
		Name:    args.IfName,
		Sandbox: args.Netns,
	})
	prev.IPs = append(prev.IPs, &current.IPConfig{
		Interface: &idx,
		Address:   net.IPNet{IP: ip, Mask: ipnet.Mask},
	})
	return prev, nil
}

func (c *Config) PrintResult(args *skel.CmdArgs) error {
	return PrintResult(c, args)
}

func PrintResult(config *Config, args *skel.CmdArgs) error {
	result, err := config.MergedResult(args)
	if err != nil {
		return err
	}
	return types.PrintResult(result, config.CNIVersion)
}
