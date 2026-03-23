package config_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var _ = Describe("Config", func() {
	It("parses a valid configuration", func() {
		privKey, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		peerKey, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())

		conf, err := config.Parse(newNetConf(privKey.String(), peerKey.PublicKey().String(), "10.100.0.2/24"))

		Expect(err).NotTo(HaveOccurred())
		Expect(conf.Address).To(Equal("10.100.0.2/24"))
		Expect(conf.PrivateKey).To(Equal(privKey.String()))
		Expect(conf.Peers).To(HaveLen(1))
	})
})
