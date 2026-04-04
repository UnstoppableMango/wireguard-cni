package config

import (
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func parseKey(str string) (*wgtypes.Key, error) {
	key, err := wgtypes.ParseKey(str)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func WireguardConfig(conf *Config) (*wgtypes.Config, error) {
	if conf.Peers == nil {
		return nil, fmt.Errorf("wireguard config missing 'peers' key")
	}
	if conf.PrivateKey == "" {
		return nil, fmt.Errorf("wireguard config missing 'privateKey' key")
	}
	key, err := wgtypes.ParseKey(conf.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("privateKey: %w", err)
	}

	c := &wgtypes.Config{
		PrivateKey:   &key,
		ReplacePeers: true,
	}
	if conf.ListenPort != 0 {
		c.ListenPort = &conf.ListenPort
	}

	for i, p := range conf.Peers {
		pc, err := peerConfig(p)
		if err != nil {
			return nil, fmt.Errorf("peers[%d] %s: %w", i, p.Endpoint, err)
		}
		c.Peers = append(c.Peers, *pc)
	}
	return c, nil
}

func (c *Config) Wireguard() ([]*net.IPNet, *wgtypes.Config, error) {
	if len(c.RuntimeConfig.IPs) == 0 {
		return nil, nil, fmt.Errorf("runtimeConfig.ips is required")
	}

	var addrs []*net.IPNet
	for i, ipStr := range c.RuntimeConfig.IPs {
		ip, addr, err := net.ParseCIDR(ipStr)
		if err != nil {
			return nil, nil, fmt.Errorf("runtimeConfig.ips[%d]: %w", i, err)
		}
		addr.IP = ip
		addrs = append(addrs, addr)
	}

	wg, err := WireguardConfig(c)
	if err != nil {
		return nil, nil, err
	}
	return addrs, wg, nil
}

func peerConfig(conf Peer) (*wgtypes.PeerConfig, error) {
	if conf.PublicKey == "" {
		return nil, fmt.Errorf("peer config missing 'publicKey' key")
	}
	key, err := wgtypes.ParseKey(conf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("publicKey: %w", err)
	}

	pc := wgtypes.PeerConfig{
		PublicKey:         key,
		ReplaceAllowedIPs: true,
	}
	for _, ip := range conf.AllowedIPs {
		_, cidr, err := net.ParseCIDR(ip)
		if err != nil {
			return nil, fmt.Errorf("allowedIP %q: %w", ip, err)
		}
		pc.AllowedIPs = append(pc.AllowedIPs, *cidr)
	}

	if conf.Endpoint != "" {
		if pc.Endpoint, err = net.ResolveUDPAddr("udp", conf.Endpoint); err != nil {
			return nil, err
		}
	}
	if conf.PersistentKeepalive > 0 {
		dur := time.Duration(conf.PersistentKeepalive) * time.Second
		pc.PersistentKeepaliveInterval = &dur
	}

	return &pc, nil
}
