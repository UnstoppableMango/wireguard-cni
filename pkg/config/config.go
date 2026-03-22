package config

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
)

type PeerConfig struct {
	PublicKey           string   `json:"publicKey"`
	Endpoint            string   `json:"endpoint,omitempty"`
	AllowedIPs          []string `json:"allowedIPs"`
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"`
}

type Config struct {
	types.NetConf
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

	if err := version.ParsePrevResult(&conf.NetConf); err != nil {
		return nil, fmt.Errorf("could not parse prevResult: %v", err)
	}

	return &conf, nil
}

func Validate(conf *Config) error {
	if conf.Address == "" {
		return fmt.Errorf("address is required")
	}
	if _, _, err := net.ParseCIDR(conf.Address); err != nil {
		return fmt.Errorf("invalid address %q: %v", conf.Address, err)
	}

	if conf.PrivateKey == "" {
		return fmt.Errorf("privateKey is required")
	}

	for i, peer := range conf.Peers {
		if peer.PublicKey == "" {
			return fmt.Errorf("peer %d: publicKey is required", i)
		}
		if len(peer.AllowedIPs) == 0 {
			return fmt.Errorf("peer %d: allowedIPs is required", i)
		}
		for _, cidr := range peer.AllowedIPs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("peer %d: invalid allowedIP %q: %v", i, cidr, err)
			}
		}
	}

	return nil
}
