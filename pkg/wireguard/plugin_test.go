package wireguard_test

import (
	"errors"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newTestConfig() (*config.Config, wgtypes.Key) {
	privKey, err := wgtypes.GeneratePrivateKey()
	Expect(err).NotTo(HaveOccurred())
	peerKey, err := wgtypes.GeneratePrivateKey()
	Expect(err).NotTo(HaveOccurred())

	return &config.Config{
		Address:    "10.0.0.1/24",
		PrivateKey: privKey.String(),
		Peers: []config.PeerConfig{{
			PublicKey:  peerKey.PublicKey().String(),
			AllowedIPs: []string{"10.1.0.0/24"},
		}},
	}, privKey
}

var _ = Describe("Add", func() {
	It("creates the link and runs setup", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{}
		mgr := &fakeLinkManager{createLink: link}

		err := wireguard.Add(mgr, conf)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.assignedAddr).NotTo(BeNil())
		Expect(link.configuredConf).NotTo(BeNil())
		Expect(link.addedRoutes).To(HaveLen(1))
	})

	It("returns error when config is invalid", func() {
		conf := &config.Config{}
		mgr := &fakeLinkManager{}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid configuration"))
	})

	It("returns error when Create fails", func() {
		conf, _ := newTestConfig()
		mgr := &fakeLinkManager{createErr: errors.New("create failed")}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to add link"))
	})

	It("deletes the link when setup fails", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{assignAddressErr: errors.New("assign failed")}
		mgr := &fakeLinkManager{createLink: link}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to setup link"))
		Expect(mgr.deleted).To(BeTrue())
	})

	It("returns error when AssignAddress fails", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{assignAddressErr: errors.New("addr error")}
		mgr := &fakeLinkManager{createLink: link}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when ConfigureWireGuard fails", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{configureWireguardErr: errors.New("wg error")}
		mgr := &fakeLinkManager{createLink: link}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when BringUp fails", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{bringUpErr: errors.New("up error")}
		mgr := &fakeLinkManager{createLink: link}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
	})

	It("returns error when AddRoute fails", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{addRouteErr: errors.New("route error")}
		mgr := &fakeLinkManager{createLink: link}

		err := wireguard.Add(mgr, conf)
		Expect(err).To(HaveOccurred())
	})

	It("adds routes for all peers and CIDRs", func() {
		privKey, _ := wgtypes.GeneratePrivateKey()
		peer1Key, _ := wgtypes.GeneratePrivateKey()
		peer2Key, _ := wgtypes.GeneratePrivateKey()
		conf := &config.Config{
			Address:    "10.0.0.1/24",
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
		link := &fakeLink{}
		mgr := &fakeLinkManager{createLink: link}

		err := wireguard.Add(mgr, conf)
		Expect(err).NotTo(HaveOccurred())
		Expect(link.addedRoutes).To(HaveLen(4))
	})
})

var _ = Describe("Check", func() {
	It("succeeds when address and public key match", func() {
		conf, privKey := newTestConfig()
		_, addr, _ := net.ParseCIDR(conf.Address)
		ip, _, _ := net.ParseCIDR(conf.Address)
		addr.IP = ip
		link := &fakeLink{
			addresses: []*net.IPNet{addr},
			publicKey: privKey.PublicKey(),
		}
		mgr := &fakeLinkManager{getLink: link}

		err := wireguard.Check(mgr, conf)
		Expect(err).NotTo(HaveOccurred())
	})

	It("returns error when config is invalid", func() {
		conf := &config.Config{}
		mgr := &fakeLinkManager{}

		err := wireguard.Check(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid configuration"))
	})

	It("returns error when Get fails", func() {
		conf, _ := newTestConfig()
		mgr := &fakeLinkManager{getErr: errors.New("get failed")}

		err := wireguard.Check(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("check"))
	})

	It("returns error when Addresses fails", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{addressesErr: errors.New("addr error")}
		mgr := &fakeLinkManager{getLink: link}

		err := wireguard.Check(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("check"))
	})

	It("returns error when address is not found on the link", func() {
		conf, _ := newTestConfig()
		link := &fakeLink{addresses: []*net.IPNet{}}
		mgr := &fakeLinkManager{getLink: link}

		err := wireguard.Check(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not found"))
	})

	It("returns error when PublicKey fails", func() {
		conf, _ := newTestConfig()
		_, addr, _ := net.ParseCIDR(conf.Address)
		ip, _, _ := net.ParseCIDR(conf.Address)
		addr.IP = ip
		link := &fakeLink{
			addresses:    []*net.IPNet{addr},
			publicKeyErr: errors.New("pubkey error"),
		}
		mgr := &fakeLinkManager{getLink: link}

		err := wireguard.Check(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("check"))
	})

	It("returns error when public key does not match", func() {
		conf, _ := newTestConfig()
		_, addr, _ := net.ParseCIDR(conf.Address)
		ip, _, _ := net.ParseCIDR(conf.Address)
		addr.IP = ip
		wrongKey, _ := wgtypes.GeneratePrivateKey()
		link := &fakeLink{
			addresses: []*net.IPNet{addr},
			publicKey: wrongKey.PublicKey(),
		}
		mgr := &fakeLinkManager{getLink: link}

		err := wireguard.Check(mgr, conf)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("public key mismatch"))
	})
})
