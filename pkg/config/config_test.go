package config_test

import (
	"encoding/base64"
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unstoppablemango/wireguard-cni/pkg/config"
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

func keyBase64(key wgtypes.Key) string {
	b := [32]byte(key)
	return base64.StdEncoding.EncodeToString(b[:])
}

var _ = Describe("Config", func() {
	It("parses a valid configuration", func() {
		privKey, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		peerKey, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())

		conf, err := config.Parse(newNetConf(keyBase64(privKey), keyBase64(peerKey.PublicKey()), "10.100.0.2/24"))
		Expect(err).NotTo(HaveOccurred())
		Expect(conf.Address).To(Equal("10.100.0.2/24"))
		Expect(conf.PrivateKey).To(Equal(keyBase64(privKey)))
		Expect(conf.Peers).To(HaveLen(1))
	})

	It("validates required address", func() {
		conf := &config.Config{PrivateKey: "somekey"}
		Expect(config.Validate(conf)).To(MatchError(ContainSubstring("address is required")))
	})

	It("validates required privateKey", func() {
		conf := &config.Config{Address: "10.0.0.1/24"}
		Expect(config.Validate(conf)).To(MatchError(ContainSubstring("privateKey is required")))
	})

	It("validates peer publicKey", func() {
		conf := &config.Config{
			Address:    "10.0.0.1/24",
			PrivateKey: "somekey",
			Peers:      []config.PeerConfig{{AllowedIPs: []string{"0.0.0.0/0"}}},
		}
		Expect(config.Validate(conf)).To(MatchError(ContainSubstring("publicKey is required")))
	})

	It("validates invalid address CIDR", func() {
		conf := &config.Config{Address: "not-a-cidr", PrivateKey: "somekey"}
		Expect(config.Validate(conf)).To(MatchError(ContainSubstring("invalid address")))
	})
})
