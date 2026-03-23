package e2e_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/unstoppablemango/wireguard-cni/pkg/funcs"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newNetConf(privKey, peerPubKey, address string) []byte {
	conf := map[string]any{
		"cniVersion": "1.0.0",
		"name":       "wg-test",
		"type":       "wireguard-cni",
		"address":    address,
		"privateKey": privKey,
		"peers": []map[string]any{
			{
				"publicKey":  peerPubKey,
				"allowedIPs": []string{"10.0.0.0/8"},
			},
		},
	}
	b, _ := json.Marshal(conf)
	return b
}

func newNetConfWithPrevResult(privKey, peerPubKey, address string, prevResult []byte) []byte {
	conf := map[string]any{
		"cniVersion": "1.0.0",
		"name":       "wg-test",
		"type":       "wireguard-cni",
		"address":    address,
		"privateKey": privKey,
		"peers": []map[string]any{
			{
				"publicKey":  peerPubKey,
				"allowedIPs": []string{"10.0.0.0/8"},
			},
		},
		"prevResult": json.RawMessage(prevResult),
	}
	b, _ := json.Marshal(conf)
	return b
}

func keyBase64(key wgtypes.Key) string {
	b := [32]byte(key)
	return base64.StdEncoding.EncodeToString(b[:])
}

var _ = Describe("Integration", Ordered, Label("e2e"), func() {
	var (
		testNS        ns.NetNS
		privKey       wgtypes.Key
		peerKey       wgtypes.Key
		confJSON      []byte
		addResultJSON []byte
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

		var (
			err         error
			resultBytes []byte
		)
		_, resultBytes, err = testutils.CmdAddWithArgs(args, func() error {
			return funcs.Add(args)
		})
		Expect(err).NotTo(HaveOccurred())
		addResultJSON = resultBytes

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

	It("CHECK succeeds after ADD", func() {
		checkConf := newNetConfWithPrevResult(
			keyBase64(privKey),
			keyBase64(peerKey.PublicKey()),
			"10.100.0.2/24",
			addResultJSON,
		)
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      "wg0",
			Args:        "",
			Path:        "/opt/cni/bin",
			StdinData:   checkConf,
		}

		err := testutils.CmdCheckWithArgs(args, func() error {
			return funcs.Check(args)
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("CHECK fails without prevResult", func() {
		args := &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       testNS.Path(),
			IfName:      "wg0",
			Args:        "",
			Path:        "/opt/cni/bin",
			StdinData:   confJSON,
		}

		err := funcs.Check(args)
		Expect(err).To(MatchError(ContainSubstring("requires a prevResult")))
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
			return funcs.Del(args)
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
			return funcs.Del(args)
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
