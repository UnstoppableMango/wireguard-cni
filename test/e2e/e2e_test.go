//go:build linux

package e2e_test

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/unstoppablemango/wireguard-cni/pkg/cmd"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const ifName = "wg0"

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
func newNetConf(privKey, peerPubKey wgtypes.Key, address, version string, prevResult []byte) []byte {
	conf := map[string]any{
		"cniVersion": version,
		"name":       "wg-test",
		"type":       "wireguard-cni",
		"runtimeConfig": map[string]any{
			"ips": []string{address},
		},
		"privateKey": privKey.String(),
		"peers": []map[string]any{{
			"publicKey":  peerPubKey.String(),
			"allowedIPs": []string{"10.0.0.0/8"},
		}},
	}
	if prevResult != nil {
		conf["prevResult"] = json.RawMessage(prevResult)
	}
	b, _ := json.Marshal(conf)
	return b
}

var _ = Describe("Host interface configuration", func() {
	for _, ver := range testutils.AllSpecVersions {
		Describe(fmt.Sprintf("cni %s", ver), Label(ver), Ordered, func() {
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

				confJSON = newNetConf(privKey, peerKey.PublicKey(), "10.100.0.2/24", ver, nil)
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
					return cmd.Add(args)
				})
				Expect(err).NotTo(HaveOccurred())

				var addrs []netlink.Addr
				Expect(testNS.Do(func(_ ns.NetNS) error {
					link, err := netlink.LinkByName(ifName)
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
					dev, err = wgClient.Device(ifName)
					return err
				})).To(Succeed())
				Expect(dev.PublicKey).To(Equal(privKey.PublicKey()))
			})

			if testutils.SpecVersionHasCHECK(ver) {
				It("CHECK succeeds after ADD", func() {
					args := &skel.CmdArgs{
						ContainerID: "test-container",
						Netns:       testNS.Path(),
						IfName:      ifName,
						Path:        "/opt/cni/bin",
						StdinData: newNetConf(
							privKey,
							peerKey.PublicKey(),
							"10.100.0.2/24",
							ver,
							addResult,
						),
					}

					Expect(testutils.CmdCheckWithArgs(args, func() error {
						return cmd.Check(args)
					})).To(Succeed())
				})

				It("CHECK fails without prevResult", func() {
					args := &skel.CmdArgs{
						ContainerID: "test-container",
						Netns:       testNS.Path(),
						IfName:      ifName,
						Path:        "/opt/cni/bin",
						StdinData:   confJSON,
					}

					Expect(testutils.CmdCheckWithArgs(args, func() error {
						return cmd.Check(args)
					})).To(MatchError(ContainSubstring("requires a prevResult")))
				})
			}

			It("DEL removes the interface", func() {
				args := &skel.CmdArgs{
					ContainerID: "test-container",
					Netns:       testNS.Path(),
					IfName:      ifName,
					Path:        "/opt/cni/bin",
					StdinData:   confJSON,
				}

				Expect(testutils.CmdDelWithArgs(args, func() error {
					return cmd.Del(args)
				})).To(Succeed())
			})

			It("DEL is idempotent (second call succeeds)", func() {
				args := &skel.CmdArgs{
					ContainerID: "test-container",
					Netns:       testNS.Path(),
					IfName:      ifName,
					Path:        "/opt/cni/bin",
					StdinData:   confJSON,
				}

				Expect(testutils.CmdDelWithArgs(args, func() error {
					return cmd.Del(args)
				})).To(Succeed())
			})
		})
	}
})

var _ = Describe("Chained mode", Label("e2e"), func() {
	for _, ver := range testutils.AllSpecVersions {
		// CNI 0.1.0 and 0.2.0 predate chained mode; their result type has no
		// Interfaces field, so prevResult-based tests don't apply.
		if ver == "0.1.0" || ver == "0.2.0" {
			continue
		}
		Describe(fmt.Sprintf("cni %s", ver), Label(ver), func() {
			It("ADD with a prevResult succeeds and returns merged result", func() {
				testNS, err := testutils.NewNS()
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() {
					_ = cmd.Del(&skel.CmdArgs{Netns: testNS.Path(), IfName: "wg0"})
					_ = cmd.Del(&skel.CmdArgs{Netns: testNS.Path(), IfName: "wg1"})
					testNS.Close()
					testutils.UnmountNS(testNS)
				})

				privKey, err := wgtypes.GeneratePrivateKey()
				Expect(err).NotTo(HaveOccurred())
				peerKey, err := wgtypes.GeneratePrivateKey()
				Expect(err).NotTo(HaveOccurred())

				// First do an ADD to get a valid prevResult.
				addArgs := &skel.CmdArgs{
					ContainerID: "test-chained",
					Netns:       testNS.Path(),
					IfName:      "wg0",
					Path:        "/opt/cni/bin",
					StdinData:   newNetConf(privKey, peerKey.PublicKey(), "10.102.0.2/24", ver, nil),
				}
				_, prevResult, err := testutils.CmdAddWithArgs(addArgs, func() error {
					return cmd.Add(addArgs)
				})
				Expect(err).NotTo(HaveOccurred())

				// Attempt ADD in chained mode with the prior result as prevResult.
				chainedArgs := &skel.CmdArgs{
					ContainerID: "test-chained",
					Netns:       testNS.Path(),
					IfName:      "wg1",
					Path:        "/opt/cni/bin",
					StdinData:   newNetConf(privKey, peerKey.PublicKey(), "10.102.1.2/24", ver, prevResult),
				}
				_, chainedResult, err := testutils.CmdAddWithArgs(chainedArgs, func() error {
					return cmd.Add(chainedArgs)
				})
				Expect(err).NotTo(HaveOccurred())

				// The merged result JSON should contain both interfaces.
				Expect(string(chainedResult)).To(ContainSubstring("wg0"))
				Expect(string(chainedResult)).To(ContainSubstring("wg1"))
			})
		})
	}
})

var _ = Describe("Wireguard tunnel traffic", func() {
	for _, ver := range testutils.AllSpecVersions {
		Describe(fmt.Sprintf("cni %s", ver), Label(ver), Ordered, func() {
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
					By("creating WireGuard server interface " + ifName)
					la := netlink.NewLinkAttrs()
					la.Name = ifName
					err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: la})
					Expect(err).NotTo(HaveOccurred())

					link, err := netlink.LinkByName(ifName)
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
					Expect(wgClient.ConfigureDevice(ifName, wgtypes.Config{
						PrivateKey:   &serverKey,
						ListenPort:   new(51820),
						ReplacePeers: true,
						Peers: []wgtypes.PeerConfig{{
							PublicKey:         clientKey.PublicKey(),
							ReplaceAllowedIPs: true,
							AllowedIPs:        []net.IPNet{*allowedNet},
						}},
					})).To(Succeed())
					return nil
				})).To(Succeed())

				confJSON, err = json.Marshal(map[string]any{
					"cniVersion": ver,
					"name":       "wg-e2e",
					"type":       "wireguard-cni",
					"runtimeConfig": map[string]any{
						"ips": []string{"10.99.0.2/24"},
					},
					"privateKey": clientKey.String(),
					"peers": []map[string]any{{
						"publicKey":           serverKey.PublicKey().String(),
						"allowedIPs":          []string{"10.99.0.1/32"},
						"endpoint":            "10.200.0.2:51820",
						"persistentKeepalive": 5,
					}},
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It("CNI ADD configures the client WireGuard interface", func() {
				args := &skel.CmdArgs{
					ContainerID: "e2e-client",
					Netns:       clientNS.Path(),
					IfName:      ifName,
					Path:        "/opt/cni/bin",
					StdinData:   confJSON,
				}

				_, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmd.Add(args)
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
	}
})
