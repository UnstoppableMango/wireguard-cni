//go:build linux

package main

import (
	"encoding/base64"
	"encoding/json"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newNetConf(privKey, peerPubKey, address string) []byte {
	conf := map[string]interface{}{
		"cniVersion": "1.0.0",
		"name":       "wg-test",
		"type":       "wireguard-cni",
		"address":    address,
		"privateKey": privKey,
		"peers": []map[string]interface{}{
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

		conf, err := parseConfig(newNetConf(keyBase64(privKey), keyBase64(peerKey.PublicKey()), "10.100.0.2/24"))
		Expect(err).NotTo(HaveOccurred())
		Expect(conf.Address).To(Equal("10.100.0.2/24"))
		Expect(conf.PrivateKey).To(Equal(keyBase64(privKey)))
		Expect(conf.Peers).To(HaveLen(1))
	})

	It("validates required address", func() {
		conf := &Config{PrivateKey: "somekey"}
		Expect(validateConfig(conf)).To(MatchError(ContainSubstring("address is required")))
	})

	It("validates required privateKey", func() {
		conf := &Config{Address: "10.0.0.1/24"}
		Expect(validateConfig(conf)).To(MatchError(ContainSubstring("privateKey is required")))
	})

	It("validates peer publicKey", func() {
		conf := &Config{
			Address:    "10.0.0.1/24",
			PrivateKey: "somekey",
			Peers:      []PeerConfig{{AllowedIPs: []string{"0.0.0.0/0"}}},
		}
		Expect(validateConfig(conf)).To(MatchError(ContainSubstring("publicKey is required")))
	})

	It("validates invalid address CIDR", func() {
		conf := &Config{Address: "not-a-cidr", PrivateKey: "somekey"}
		Expect(validateConfig(conf)).To(MatchError(ContainSubstring("invalid address")))
	})
})

var _ = Describe("parseAddress", func() {
	It("preserves the host IP", func() {
		addr, err := parseAddress("10.100.0.2/24")
		Expect(err).NotTo(HaveOccurred())
		Expect(addr.IP.String()).To(Equal("10.100.0.2"))
		Expect(addr.Mask).To(Equal(net.CIDRMask(24, 32)))
	})

	It("rejects invalid CIDR", func() {
		_, err := parseAddress("not-valid")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("parseWGKey", func() {
	It("decodes a valid base64 key", func() {
		key, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		parsed, err := parseWGKey(keyBase64(key))
		Expect(err).NotTo(HaveOccurred())
		Expect(parsed).To(Equal(key))
	})

	It("rejects invalid base64", func() {
		_, err := parseWGKey("!!!not-base64!!!")
		Expect(err).To(HaveOccurred())
	})

	It("rejects a key of wrong length", func() {
		short := base64.StdEncoding.EncodeToString([]byte("short"))
		_, err := parseWGKey(short)
		Expect(err).To(HaveOccurred())
	})
})

