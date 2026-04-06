package wireguard

import (
	"fmt"
	"net"
	"time"

	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (cni *CNI) Create(ifName string, ip *current.IPConfig) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("new wgctrl: %w", err)
	}
	defer c.Close()

	conf, err := Config(cni.conf)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	return c.ConfigureDevice(ifName, *conf)
}

func (cni *CNI) Configure(ifName string) error {
	c, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("new wgctrl: %w", err)
	}
	defer c.Close()

	conf, err := Config(cni.conf)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	return c.ConfigureDevice(ifName, *conf)
}

func Config(conf *config.Config) (*wgtypes.Config, error) {
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

func peerConfig(cni config.Peer) (*wgtypes.PeerConfig, error) {
	if cni.PublicKey == "" {
		return nil, fmt.Errorf("peer config missing 'publicKey' key")
	}
	key, err := wgtypes.ParseKey(cni.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse publicKey: %w", err)
	}

	wg := wgtypes.PeerConfig{
		PublicKey:         key,
		ReplaceAllowedIPs: true,
	}
	for _, ip := range cni.AllowedIPs {
		_, cidr, err := net.ParseCIDR(ip)
		if err != nil {
			return nil, fmt.Errorf("parse allowedIP %q: %w", ip, err)
		}
		wg.AllowedIPs = append(wg.AllowedIPs, *cidr)
	}

	if cni.Endpoint != "" {
		if wg.Endpoint, err = net.ResolveUDPAddr("udp", cni.Endpoint); err != nil {
			return nil, fmt.Errorf("resolve addr %q: %w", cni.Endpoint, err)
		}
	}
	if cni.PersistentKeepalive > 0 {
		dur := time.Duration(cni.PersistentKeepalive) * time.Second
		wg.PersistentKeepaliveInterval = &dur
	}

	return &wg, nil
}
