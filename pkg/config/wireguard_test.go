package config_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newNetConf(privKey, peerPubKey, address string) []byte {
	return newNetConfWithPrevResult(privKey, peerPubKey, address, nil)
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
	}
	if prevResult != nil {
		conf["prevResult"] = json.RawMessage(prevResult)
	}
	b, _ := json.Marshal(conf)
	return b
}

var _ = Describe("Wireguard", func() {
	It("validates required address", func() {
		key, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		conf := &config.Config{PrivateKey: key.String()}

		_, _, err = conf.Wireguard()
		Expect(err).To(MatchError(ContainSubstring("address is required")))
	})

	It("validates required privateKey", func() {
		conf := &config.Config{Address: "10.0.0.1/24"}
		_, _, err := conf.Wireguard()
		Expect(err).To(MatchError(ContainSubstring("privateKey is required")))
	})

	It("validates peer publicKey", func() {
		key, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		conf := &config.Config{
			Address:    "10.0.0.1/24",
			PrivateKey: key.String(),
			Peers: []config.PeerConfig{{
				AllowedIPs: []string{"0.0.0.0/0"},
			}},
		}

		_, _, err = conf.Wireguard()
		Expect(err).To(MatchError(ContainSubstring("publicKey is required")))
	})

	It("validates invalid address CIDR", func() {
		key, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		conf := &config.Config{
			Address:    "not-a-cidr",
			PrivateKey: key.String(),
		}

		_, _, err = conf.Wireguard()
		Expect(err).To(MatchError(ContainSubstring("invalid address")))
	})
})
