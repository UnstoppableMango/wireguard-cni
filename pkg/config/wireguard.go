package config

import (
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (c *Config) Wireguard() (*net.IPNet, *wgtypes.Config, error) {
	if c.Address == "" {
		return nil, nil, fmt.Errorf("address is required")
	}
	ip, addr, err := net.ParseCIDR(c.Address)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid address: %w", err)
	}
	addr.IP = ip

	if c.PrivateKey == "" {
		return nil, nil, fmt.Errorf("privateKey is required")
	}
	key, err := wgtypes.ParseKey(c.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid privateKey: %w", err)
	}

	wg := wgtypes.Config{
		PrivateKey:   &key,
		ReplacePeers: true,
	}
	if c.ListenPort != 0 {
		wg.ListenPort = &c.ListenPort
	}

	for i, p := range c.Peers {
		if pc, err := peerConfig(p); err != nil {
			return nil, nil, fmt.Errorf("peer %d: %w", i, err)
		} else {
			wg.Peers = append(wg.Peers, *pc)
		}
	}

	return addr, &wg, nil
}

func peerConfig(c PeerConfig) (*wgtypes.PeerConfig, error) {
	if c.PublicKey == "" {
		return nil, fmt.Errorf("publicKey is required")
	}
	key, err := wgtypes.ParseKey(c.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid publicKey: %w", err)
	}

	pc := wgtypes.PeerConfig{
		PublicKey:         key,
		ReplaceAllowedIPs: true,
	}

	for _, ip := range c.AllowedIPs {
		if _, ipnet, err := net.ParseCIDR(ip); err != nil {
			return nil, fmt.Errorf("invalid allowedIP %q: %w", ip, err)
		} else {
			pc.AllowedIPs = append(pc.AllowedIPs, *ipnet)
		}
	}

	if c.Endpoint != "" {
		if addr, err := c.ResolveUDPEndpoint(); err != nil {
			return nil, err
		} else {
			pc.Endpoint = addr
		}
	}

	if c.PersistentKeepalive > 0 {
		dur := time.Duration(c.PersistentKeepalive) * time.Second
		pc.PersistentKeepaliveInterval = &dur
	}

	return &pc, nil
}
