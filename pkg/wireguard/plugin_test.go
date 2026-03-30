package wireguard_test

import (
	"errors"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newTestConfig() (*config.Config, wgtypes.Key) {
	privKey, err := wgtypes.GeneratePrivateKey()
	Expect(err).NotTo(HaveOccurred())
	peerKey, err := wgtypes.GeneratePrivateKey()
	Expect(err).NotTo(HaveOccurred())

	conf := &config.Config{
		PrivateKey: privKey.String(),
		Peers: []config.PeerConfig{{
			PublicKey:  peerKey.PublicKey().String(),
			AllowedIPs: []string{"10.1.0.0/24"},
		}},
	}
	conf.RuntimeConfig.IPs = []string{"10.0.0.1/24"}
	return conf, privKey
}

var _ = Describe("Add", func() {
	It("creates the link and runs setup when interface does not exist", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{}
		mgr := &fakeLinkManager{
			getErr:     notFoundError(),
			createLink: link,
		}

		err := wireguard.Add(mgr, conf)
		Expect(err).NotTo(HaveOccurred())
		Expect(mgr.created).To(BeTrue())
		Expect(link.assignedAddr).NotTo(BeNil())
		Expect(link.configuredConf).NotTo(BeNil())
		Expect(link.addedRoutes).To(HaveLen(1))
	})

	It("reconfigures existing interface without calling Create", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{}
		mgr := &fakeLinkManager{getLink: link}

		err := wireguard.Add(mgr, conf)
		Expect(err).NotTo(HaveOccurred())
		Expect(mgr.created).To(BeFalse())
		Expect(link.configuredConf).NotTo(BeNil())
		Expect(link.addedRoutes).To(HaveLen(1))
	})

	It("assigns address when reconfiguring and address not already present", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{addresses: []*net.IPNet{}}
		mgr := &fakeLinkManager{getLink: link}

		err := wireguard.Add(mgr, conf)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.assignCalled).To(BeTrue())
		Expect(link.assignedAddr).NotTo(BeNil())
	})

	It("skips AssignAddress when reconfiguring and address already present", func() {
		conf, _ := newTestConfig()
		ip, addr, err := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		Expect(err).NotTo(HaveOccurred())
		addr.IP = ip
		link := &fakeLink{addresses: []*net.IPNet{addr}}
		mgr := &fakeLinkManager{getLink: link}

		err = wireguard.Add(mgr, conf)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.assignCalled).To(BeFalse())
	})

	It("returns error when config is invalid", func() {
		conf := &config.Config{}
		mgr := &fakeLinkManager{}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid configuration"))
	})

	It("returns error when Get fails with non-not-found error", func() {
		conf, _ := newTestConfig()
		mgr := &fakeLinkManager{getErr: errors.New("unexpected error")}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError("get link: unexpected error"))
	})

	It("returns error when Create fails", func() {
		conf, _ := newTestConfig()
		mgr := &fakeLinkManager{
			getErr:    notFoundError(),
			createErr: errors.New("create failed"),
		}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError("create link: create failed"))
	})

	It("deletes the link when setup fails after create", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{assignAddressErr: errors.New("assign failed")}
		mgr := &fakeLinkManager{
			getErr:     notFoundError(),
			createLink: link,
		}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("assign address")))
		Expect(mgr.deleted).To(BeTrue())
	})

	It("returns error when AssignAddress fails during create path", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{assignAddressErr: errors.New("addr error")}
		mgr := &fakeLinkManager{
			getErr:     notFoundError(),
			createLink: link,
		}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("assign address"))
	})

	It("returns error when ConfigureWireGuard fails during create path", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{configureWireguardErr: errors.New("wg error")}
		mgr := &fakeLinkManager{
			getErr:     notFoundError(),
			createLink: link,
		}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when BringUp fails during create path", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{bringUpErr: errors.New("up error")}
		mgr := &fakeLinkManager{
			getErr:     notFoundError(),
			createLink: link,
		}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("set link up"))
	})

	It("returns error when AddRoute fails during create path", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{addRouteErr: errors.New("route error")}
		mgr := &fakeLinkManager{
			getErr:     notFoundError(),
			createLink: link,
		}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("add route"))
	})

	It("adds routes for all peers and CIDRs during create path", func() {
		privKey, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		peer1Key, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		peer2Key, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		conf := &config.Config{
			PrivateKey: privKey.String(),
			Peers: []config.PeerConfig{
				{
					PublicKey:  peer1Key.PublicKey().String(),
					AllowedIPs: []string{"10.1.0.0/24", "10.2.0.0/24"},
				},
				{
					PublicKey:  peer2Key.PublicKey().String(),
					AllowedIPs: []string{"10.3.0.0/24", "10.4.0.0/24"},
				},
			},
		}
		conf.RuntimeConfig.IPs = []string{"10.0.0.1/24"}
		link := &fakeLink{}
		mgr := &fakeLinkManager{
			getErr:     notFoundError(),
			createLink: link,
		}

		err = wireguard.Add(mgr, conf)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.addedRoutes).To(HaveLen(4))
	})

	It("returns error when Addresses fails during reconfigure path without calling Create or Delete", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{addressesErr: errors.New("addr error")}
		mgr := &fakeLinkManager{getLink: link}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("get addresses"))
		Expect(mgr.created).To(BeFalse())
		Expect(mgr.deleted).To(BeFalse())
	})

	It("returns error when AssignAddress fails during reconfigure path", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{
			addresses:        []*net.IPNet{},
			assignAddressErr: errors.New("assign failed"),
		}
		mgr := &fakeLinkManager{getLink: link}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("assign address"))
		Expect(mgr.created).To(BeFalse())
	})

	It("adds routes for all peers and CIDRs during reconfigure path", func() {
		privKey, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		peer1Key, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		peer2Key, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		conf := &config.Config{
			PrivateKey: privKey.String(),
			Peers: []config.PeerConfig{
				{
					PublicKey:  peer1Key.PublicKey().String(),
					AllowedIPs: []string{"10.1.0.0/24", "10.2.0.0/24"},
				},
				{
					PublicKey:  peer2Key.PublicKey().String(),
					AllowedIPs: []string{"10.3.0.0/24", "10.4.0.0/24"},
				},
			},
		}
		conf.RuntimeConfig.IPs = []string{"10.0.0.1/24"}
		link := &fakeLink{}
		mgr := &fakeLinkManager{getLink: link}

		err = wireguard.Add(mgr, conf)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.addedRoutes).To(HaveLen(4))
	})
})

// newTestPrevResult builds a minimal prevResult with the given interface name and address.
func newTestPrevResult(ifName, cidr string) *current.Result {
	ip, ipnet, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred())
	ifIdx := 0
	return &current.Result{
		CNIVersion: "1.0.0",
		Interfaces: []*current.Interface{
			{Name: ifName, Sandbox: "/var/run/netns/test"},
		},
		IPs: []*current.IPConfig{
			{
				Interface: &ifIdx,
				Address:   net.IPNet{IP: ip, Mask: ipnet.Mask},
			},
		},
	}
}

var _ = Describe("Check", func() {
	const ifName = "wg0"

	It("succeeds when address and public key match", func() {
		conf, privKey := newTestConfig()
		_, addr, _ := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		ip, _, _ := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		addr.IP = ip
		link := &fakeLink{
			addresses: []*net.IPNet{addr},
			publicKey: privKey.PublicKey(),
		}
		mgr := &fakeLinkManager{getLink: link}
		prevResult := newTestPrevResult(ifName, conf.RuntimeConfig.IPs[0])

		err := wireguard.Check(mgr, conf, ifName, prevResult)
		Expect(err).NotTo(HaveOccurred())
	})

	It("returns error when config is invalid", func() {
		conf := &config.Config{}
		mgr := &fakeLinkManager{}
		prevResult := &current.Result{}

		err := wireguard.Check(mgr, conf, ifName, prevResult)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid configuration"))
	})

	It("returns error when prevResult is nil", func() {
		conf, _ := newTestConfig()
		mgr := &fakeLinkManager{}

		err := wireguard.Check(mgr, conf, ifName, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("missing prevResult"))
	})

	It("returns error when interface is not found in prevResult", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{}
		mgr := &fakeLinkManager{getLink: link}
		prevResult := &current.Result{
			CNIVersion: "1.0.0",
			Interfaces: []*current.Interface{{Name: "other0"}},
		}

		err := wireguard.Check(mgr, conf, ifName, prevResult)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not found in prevResult"))
	})

	It("returns error when no IPs from prevResult match the interface", func() {
		conf, _ := newTestConfig()
		_, addr, _ := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		ip, _, _ := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		addr.IP = ip
		link := &fakeLink{addresses: []*net.IPNet{addr}}
		mgr := &fakeLinkManager{getLink: link}
		prevResult := &current.Result{
			CNIVersion: "1.0.0",
			Interfaces: []*current.Interface{{Name: ifName}},
			IPs:        []*current.IPConfig{},
		}

		err := wireguard.Check(mgr, conf, ifName, prevResult)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no IPs from prevResult matched"))
	})

	It("returns error when Get fails", func() {
		conf, _ := newTestConfig()
		mgr := &fakeLinkManager{getErr: errors.New("get failed")}
		prevResult := newTestPrevResult(ifName, conf.RuntimeConfig.IPs[0])

		err := wireguard.Check(mgr, conf, ifName, prevResult)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("check"))
	})

	It("returns error when Addresses fails", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{addressesErr: errors.New("addr error")}
		mgr := &fakeLinkManager{getLink: link}
		prevResult := newTestPrevResult(ifName, conf.RuntimeConfig.IPs[0])

		err := wireguard.Check(mgr, conf, ifName, prevResult)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("check"))
	})

	It("returns error when IP from prevResult is not assigned on the link", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{addresses: []*net.IPNet{}}
		mgr := &fakeLinkManager{getLink: link}
		prevResult := newTestPrevResult(ifName, conf.RuntimeConfig.IPs[0])

		err := wireguard.Check(mgr, conf, ifName, prevResult)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not found"))
	})

	It("returns error when Routes fails", func() {
		conf, privKey := newTestConfig()
		_, addr, _ := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		ip, _, _ := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		addr.IP = ip
		link := &fakeLink{
			addresses: []*net.IPNet{addr},
			routesErr: errors.New("routes error"),
			publicKey: privKey.PublicKey(),
		}
		mgr := &fakeLinkManager{getLink: link}
		_, routeDst, _ := net.ParseCIDR("10.1.0.0/24")
		ifIdx := 0
		prevResult := &current.Result{
			CNIVersion: "1.0.0",
			Interfaces: []*current.Interface{{Name: ifName}},
			IPs: []*current.IPConfig{{
				Interface: &ifIdx,
				Address:   net.IPNet{IP: addr.IP, Mask: addr.Mask},
			}},
			Routes: []*cnitypes.Route{{Dst: *routeDst}},
		}

		err := wireguard.Check(mgr, conf, ifName, prevResult)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("check"))
	})

	It("returns error when route from prevResult is not installed", func() {
		conf, privKey := newTestConfig()
		_, addr, _ := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		ip, _, _ := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		addr.IP = ip
		link := &fakeLink{
			addresses: []*net.IPNet{addr},
			routes:    []*net.IPNet{},
			publicKey: privKey.PublicKey(),
		}
		mgr := &fakeLinkManager{getLink: link}
		_, routeDst, _ := net.ParseCIDR("10.1.0.0/24")
		ifIdx := 0
		prevResult := &current.Result{
			CNIVersion: "1.0.0",
			Interfaces: []*current.Interface{{Name: ifName}},
			IPs: []*current.IPConfig{{
				Interface: &ifIdx,
				Address:   net.IPNet{IP: addr.IP, Mask: addr.Mask},
			}},
			Routes: []*cnitypes.Route{{Dst: *routeDst}},
		}

		err := wireguard.Check(mgr, conf, ifName, prevResult)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not found"))
	})

	It("succeeds when all IPs and routes from prevResult are present", func() {
		conf, privKey := newTestConfig()
		_, addr, _ := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		ip, _, _ := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		addr.IP = ip
		_, routeDst, _ := net.ParseCIDR("10.1.0.0/24")
		link := &fakeLink{
			addresses: []*net.IPNet{addr},
			routes:    []*net.IPNet{routeDst},
			publicKey: privKey.PublicKey(),
		}
		mgr := &fakeLinkManager{getLink: link}
		ifIdx := 0
		prevResult := &current.Result{
			CNIVersion: "1.0.0",
			Interfaces: []*current.Interface{{Name: ifName}},
			IPs: []*current.IPConfig{{
				Interface: &ifIdx,
				Address:   net.IPNet{IP: addr.IP, Mask: addr.Mask},
			}},
			Routes: []*cnitypes.Route{{Dst: *routeDst}},
		}

		err := wireguard.Check(mgr, conf, ifName, prevResult)
		Expect(err).NotTo(HaveOccurred())
	})

	It("returns error when PublicKey fails", func() {
		conf, _ := newTestConfig()
		_, addr, _ := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		ip, _, _ := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		addr.IP = ip
		link := &fakeLink{
			addresses:    []*net.IPNet{addr},
			publicKeyErr: errors.New("pubkey error"),
		}
		mgr := &fakeLinkManager{getLink: link}
		prevResult := newTestPrevResult(ifName, conf.RuntimeConfig.IPs[0])

		err := wireguard.Check(mgr, conf, ifName, prevResult)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("check"))
	})

	It("returns error when public key does not match", func() {
		conf, _ := newTestConfig()
		_, addr, _ := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		ip, _, _ := net.ParseCIDR(conf.RuntimeConfig.IPs[0])
		addr.IP = ip
		wrongKey, _ := wgtypes.GeneratePrivateKey()
		link := &fakeLink{
			addresses: []*net.IPNet{addr},
			publicKey: wrongKey.PublicKey(),
		}
		mgr := &fakeLinkManager{getLink: link}
		prevResult := newTestPrevResult(ifName, conf.RuntimeConfig.IPs[0])

		err := wireguard.Check(mgr, conf, ifName, prevResult)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("public key mismatch"))
	})
})
