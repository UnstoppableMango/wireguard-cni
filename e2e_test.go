package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const IfName = "wg0"

func TestWireguardCNI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "WireGuard CNI Suite")
}

// assignAddrAndUp assigns a CIDR address to the named interface and brings it up.
// Must be called from within the target network namespace.
func assignAddrAndUp(ifName, cidr string) {
	GinkgoHelper()
	link, err := netlink.LinkByName(ifName)
	Expect(err).NotTo(HaveOccurred())
	addr, err := netlink.ParseAddr(cidr)
	Expect(err).NotTo(HaveOccurred())
	Expect(netlink.AddrAdd(link, addr)).To(Succeed())
	Expect(netlink.LinkSetUp(link)).To(Succeed())
}

// createVethPair creates a connected veth pair: hostName stays in the root
// namespace with hostCIDR assigned, peerName is placed in targetNS with peerCIDR.
func createVethPair(hostName, peerName, hostCIDR, peerCIDR string, targetNS ns.NetNS) {
	GinkgoHelper()
	_, _, err := ip.SetupVethWithName(hostName, peerName, 1500, "", targetNS)
	Expect(err).NotTo(HaveOccurred())
	assignAddrAndUp(hostName, hostCIDR)
	Expect(targetNS.Do(func(_ ns.NetNS) error {
		assignAddrAndUp(peerName, peerCIDR)
		return nil
	})).To(Succeed())
}

// addDefaultRouteInNS sets the default gateway inside targetNS, routing
// outbound traffic via viaIface to gateway.
func addDefaultRouteInNS(targetNS ns.NetNS, gateway, viaIface string) {
	GinkgoHelper()
	Expect(targetNS.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(viaIface)
		if err != nil {
			return err
		}
		return ip.AddDefaultRoute(net.ParseIP(gateway), link)
	})).To(Succeed())
}

// newNetConf builds a CNI ADD config for the wireguard-cni plugin. Pass a
// non-nil prevResult to produce a config suitable for CNI CHECK.
func newNetConf(privKey, peerPubKey wgtypes.Key, address string, prevResult []byte) []byte {
	conf := map[string]any{
		"cniVersion": "1.0.0",
		"name":       "wg-test",
		"type":       "wireguard-cni",
		"address":    address,
		"privateKey": privKey.String(),
		"peers": []map[string]any{
			{
				"publicKey":  peerPubKey.String(),
				"allowedIPs": []string{"10.0.0.0/8"},
			},
		},
	}
	if prevResult != nil {
		conf["prevResult"] = json.RawMessage(prevResult)
	}
	b, _ := json.Marshal(conf)
	return b
}

var _ = Describe("Integration", Ordered, Label("e2e"), func() {
	var (
		testNS    ns.NetNS
		privKey   wgtypes.Key
		peerKey   wgtypes.Key
		confJSON  []byte
		addResult []byte
	)

	BeforeAll(func() {
		var err error

		testNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			testNS.Close()
			testutils.UnmountNS(testNS)
		})

		privKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		peerKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())

		confJSON = newNetConf(
			privKey,
			peerKey.PublicKey(),
			"10.100.0.2/24",
			nil,
		)
	})

	It("ADD creates the WireGuard interface with the correct address", func() {
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      "wg0",
			Path:        "/opt/cni/bin",
			StdinData:   confJSON,
		}

		var err error
		_, addResult, err = testutils.CmdAddWithArgs(args, func() error {
			return cmdAdd(args)
		})
		Expect(err).NotTo(HaveOccurred())

		var addrs []netlink.Addr
		Expect(testNS.Do(func(_ ns.NetNS) error {
			link, err := netlink.LinkByName(IfName)
			if err != nil {
				return err
			}
			addrs, err = netlink.AddrList(link, netlink.FAMILY_ALL)
			return err
		})).To(Succeed())
		Expect(addrs).To(ContainElement(WithTransform(
			func(a netlink.Addr) string { return a.IP.String() },
			Equal("10.100.0.2"),
		)))

		var dev *wgtypes.Device
		Expect(testNS.Do(func(_ ns.NetNS) error {
			wgClient, err := wgctrl.New()
			if err != nil {
				return err
			}
			defer wgClient.Close()
			dev, err = wgClient.Device(IfName)
			return err
		})).To(Succeed())
		Expect(dev.PublicKey).To(Equal(privKey.PublicKey()))
	})

	It("CHECK succeeds after ADD", func() {
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      IfName,
			Path:        "/opt/cni/bin",
			StdinData: newNetConf(
				privKey,
				peerKey.PublicKey(),
				"10.100.0.2/24",
				addResult,
			),
		}

		Expect(testutils.CmdCheckWithArgs(args, func() error {
			return cmdCheck(args)
		})).To(Succeed())
	})

	It("CHECK fails without prevResult", func() {
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      IfName,
			Path:        "/opt/cni/bin",
			StdinData:   confJSON,
		}

		Expect(testutils.CmdCheckWithArgs(args, func() error {
			return cmdCheck(args)
		})).To(MatchError(ContainSubstring("requires a prevResult")))
	})

	It("DEL removes the interface", func() {
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      IfName,
			Path:        "/opt/cni/bin",
			StdinData:   confJSON,
		}

		Expect(testutils.CmdDelWithArgs(args, func() error {
			return cmdDel(args)
		})).To(Succeed())
	})

	It("DEL is idempotent (second call succeeds)", func() {
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      IfName,
			Path:        "/opt/cni/bin",
			StdinData:   confJSON,
		}

		Expect(testutils.CmdDelWithArgs(args, func() error {
			return cmdDel(args)
		})).To(Succeed())
	})
})

var _ = Describe("E2E", Ordered, Label("e2e"), func() {
	var (
		serverNS  ns.NetNS
		clientNS  ns.NetNS
		serverKey wgtypes.Key
		clientKey wgtypes.Key
		confJSON  []byte
	)

	BeforeAll(func() {
		var err error

		serverNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			serverNS.Close()
			testutils.UnmountNS(serverNS)
		})

		clientNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			clientNS.Close()
			testutils.UnmountNS(clientNS)
		})

		DeferCleanup(func() {
			ip.DelLinkByName("veth0-srv")
			ip.DelLinkByName("veth0-cli")
		})

		serverKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		clientKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())

		Expect(ip.EnableIP4Forward()).To(Succeed())

		By("creating veth links connecting root namespace to server and client namespaces")
		createVethPair("veth0-srv", "veth1-srv", "10.200.0.1/30", "10.200.0.2/30", serverNS)
		createVethPair("veth0-cli", "veth1-cli", "10.200.1.1/30", "10.200.1.2/30", clientNS)

		By("routing so namespaces can reach each other for the WireGuard handshake")
		// Client must reach 10.200.0.2 (server's veth) to initiate the handshake.
		addDefaultRouteInNS(clientNS, "10.200.1.1", "veth1-cli")
		// Server must reach 10.200.1.x (client's veth) to reply to handshake packets.
		addDefaultRouteInNS(serverNS, "10.200.0.1", "veth1-srv")

		By("configuring the WireGuard server")
		Expect(serverNS.Do(func(ns.NetNS) error {
			By("creating WireGuard server interface " + IfName)
			la := netlink.NewLinkAttrs()
			la.Name = IfName
			err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: la})
			Expect(err).NotTo(HaveOccurred())

			link, err := netlink.LinkByName(IfName)
			Expect(err).NotTo(HaveOccurred())
			addr, err := netlink.ParseAddr("10.99.0.1/24")
			Expect(err).NotTo(HaveOccurred())
			Expect(netlink.AddrAdd(link, addr)).To(Succeed())
			Expect(netlink.LinkSetUp(link)).To(Succeed())

			By("configuring server keys and peer allowlist")
			wgClient, err := wgctrl.New()
			Expect(err).NotTo(HaveOccurred())
			defer wgClient.Close()

			_, allowedNet, _ := net.ParseCIDR("10.99.0.0/24")
			Expect(wgClient.ConfigureDevice(IfName, wgtypes.Config{
				PrivateKey:   &serverKey,
				ListenPort:   new(51820),
				ReplacePeers: true,
				Peers: []wgtypes.PeerConfig{
					{
						PublicKey:         clientKey.PublicKey(),
						ReplaceAllowedIPs: true,
						AllowedIPs:        []net.IPNet{*allowedNet},
					},
				},
			})).To(Succeed())
			return nil
		})).To(Succeed())

		confJSON, err = json.Marshal(map[string]any{
			"cniVersion": "1.0.0",
			"name":       "wg-e2e",
			"type":       "wireguard-cni",
			"address":    "10.99.0.2/24",
			"privateKey": clientKey.String(),
			"peers": []map[string]any{
				{
					"publicKey":           serverKey.PublicKey().String(),
					"allowedIPs":          []string{"10.99.0.1/32"},
					"endpoint":            "10.200.0.2:51820",
					"persistentKeepalive": 5,
				},
			},
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("CNI ADD configures the client WireGuard interface", func() {
		args := &skel.CmdArgs{
			ContainerID: "e2e-client",
			Netns:       clientNS.Path(),
			IfName:      IfName,
			Path:        "/opt/cni/bin",
			StdinData:   confJSON,
		}

		_, _, err := testutils.CmdAddWithArgs(args, func() error {
			return cmdAdd(args)
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("client can reach server through WireGuard tunnel", func() {
		const addr = "10.99.0.1:19999"

		By("starting a TCP listener on the server's WireGuard address")
		var ln net.Listener
		Expect(serverNS.Do(func(ns.NetNS) error {
			var err error
			ln, err = net.Listen("tcp4", addr)
			return err
		})).To(Succeed())
		DeferCleanup(ln.Close)

		accepted := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			conn, err := ln.Accept()
			if err == nil {
				conn.Close()
			}
			accepted <- err
		}()

		By("dialing from the client namespace through the WireGuard tunnel")
		Expect(clientNS.Do(func(ns.NetNS) error {
			conn, err := net.DialTimeout("tcp4", addr, 10*time.Second)
			if err != nil {
				return err
			}
			conn.Close()
			return nil
		})).To(Succeed())

		Eventually(accepted, "15s").Should(Receive(BeNil()))
	})
})
