//go:build linux

package main

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var _ = Describe("Integration", Ordered, Label("integration"), func() {
	var (
		testNS   ns.NetNS
		privKey  wgtypes.Key
		peerKey  wgtypes.Key
		confJSON []byte
	)

	BeforeAll(func() {
		var err error
		testNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		privKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		peerKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())

		confJSON = newNetConf(
			keyBase64(privKey),
			keyBase64(peerKey.PublicKey()),
			"10.100.0.2/24",
		)
	})

	AfterAll(func() {
		if testNS != nil {
			testNS.Close()
			testutils.UnmountNS(testNS)
		}
	})

	It("ADD creates the WireGuard interface with the correct address", func() {
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      "wg0",
			Args:        "",
			Path:        "/opt/cni/bin",
			StdinData:   confJSON,
		}

		_, _, err := testutils.CmdAddWithArgs(args, func() error {
			return cmdAdd(args)
		})
		Expect(err).NotTo(HaveOccurred())

		err = testNS.Do(func(_ ns.NetNS) error {
			link, lerr := netlink.LinkByName("wg0")
			if lerr != nil {
				return lerr
			}

			addrs, lerr := netlink.AddrList(link, netlink.FAMILY_ALL)
			if lerr != nil {
				return lerr
			}

			found := false
			for _, a := range addrs {
				if a.IP.String() == "10.100.0.2" {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("address 10.100.0.2 not found on wg0")
			}

			client, lerr := wgctrl.New()
			if lerr != nil {
				return lerr
			}
			defer client.Close()

			dev, lerr := client.Device("wg0")
			if lerr != nil {
				return lerr
			}

			expectedPub := privKey.PublicKey()
			if dev.PublicKey != expectedPub {
				return fmt.Errorf("public key mismatch")
			}

			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("DEL removes the interface", func() {
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      "wg0",
			Args:        "",
			Path:        "/opt/cni/bin",
			StdinData:   confJSON,
		}

		err := testutils.CmdDelWithArgs(args, func() error {
			return cmdDel(args)
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("DEL is idempotent (second call succeeds)", func() {
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      "wg0",
			Args:        "",
			Path:        "/opt/cni/bin",
			StdinData:   confJSON,
		}

		err := testutils.CmdDelWithArgs(args, func() error {
			return cmdDel(args)
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
