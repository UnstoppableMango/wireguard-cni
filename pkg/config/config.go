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

// BandwidthEntry holds rate-limit parameters from runtimeConfig.bandwidth.
// Rates are in bits per second; bursts are in bits.
type BandwidthEntry struct {
	IngressRate  uint64 `json:"ingressRate"`
	IngressBurst uint64 `json:"ingressBurst"`
	EgressRate   uint64 `json:"egressRate"`
	EgressBurst  uint64 `json:"egressBurst"`
}

type Config struct {
	types.PluginConf
	PrivateKey    string       `json:"privateKey"`
	ListenPort    int          `json:"listenPort,omitempty"`
	Peers         []PeerConfig `json:"peers"`
	RuntimeConfig struct {
		IPs       []string        `json:"ips,omitempty"`
		MAC       string          `json:"mac,omitempty"`
		Bandwidth *BandwidthEntry `json:"bandwidth,omitempty"`
	} `json:"runtimeConfig"`
}

// ParseMAC parses the MAC address from runtimeConfig.mac.
// Returns nil, nil when no MAC is configured.
func (c *Config) ParseMAC() (net.HardwareAddr, error) {
	if c.RuntimeConfig.MAC == "" {
		return nil, nil
	}
	mac, err := net.ParseMAC(c.RuntimeConfig.MAC)
	if err != nil {
		return nil, fmt.Errorf("invalid MAC address %q: %w", c.RuntimeConfig.MAC, err)
	}
	return mac, nil
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
func (c *Config) Result(args *skel.CmdArgs) (res *current.Result, err error) {
	if c.PrevResult != nil {
		if res, err = current.GetResult(c.PrevResult); err != nil {
			return nil, fmt.Errorf("get prevResult: %w", err)
		}
	} else {
		res = &current.Result{
			CNIVersion: c.CNIVersion,
			Routes:     []*types.Route{},
		}
	}

	idx := len(res.Interfaces)
	res.Interfaces = append(res.Interfaces, &current.Interface{
		Name:    args.IfName,
		Sandbox: args.Netns,
	})

	for _, ipstr := range c.RuntimeConfig.IPs {
		ip, ipnet, err := net.ParseCIDR(ipstr)
		if err != nil {
			return nil, err
		}
		res.IPs = append(res.IPs, &current.IPConfig{
			Interface: &idx,
			Address: net.IPNet{
				IP:   ip,
				Mask: ipnet.Mask,
			},
		})
	}

	return res, nil
}

func (c *Config) PrintResult(args *skel.CmdArgs) error {
	return PrintResult(c, args)
}

func PrintResult(config *Config, args *skel.CmdArgs) error {
	result, err := config.Result(args)
	if err != nil {
		return err
	}
	return types.PrintResult(result, config.CNIVersion)
}
