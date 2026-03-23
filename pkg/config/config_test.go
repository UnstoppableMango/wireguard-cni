package config_test

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/pkg/skel"
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

	It("returns error when stdin is not valid JSON", func() {
		_, err := config.Parse([]byte("not-json"))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to parse network configuration"))
	})

	It("returns error when prevResult cannot be parsed", func() {
		// cniVersion 0.0.1 is not a supported result version, so ParsePrevResult fails.
		stdin := []byte(`{"cniVersion":"0.0.1","name":"wg-test","type":"wireguard-cni","prevResult":{}}`)

		_, err := config.Parse(stdin)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("could not parse prevResult"))
	})
})

var _ = Describe("Result", func() {
	var args *skel.CmdArgs

	BeforeEach(func() {
		args = &skel.CmdArgs{
			IfName: "wg0",
			Netns:  "/var/run/netns/test",
		}
	})

	It("returns a result with the interface name and netns from args", func() {
		conf := &config.Config{Address: "10.0.0.1/24"}

		result, err := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		Expect(result.Interfaces).To(HaveLen(1))
		Expect(result.Interfaces[0].Name).To(Equal("wg0"))
		Expect(result.Interfaces[0].Sandbox).To(Equal("/var/run/netns/test"))
	})

	It("returns a result with the host IP from the address CIDR", func() {
		conf := &config.Config{Address: "10.0.0.5/24"}

		result, err := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		Expect(result.IPs).To(HaveLen(1))
		Expect(result.IPs[0].Address.IP).To(Equal(net.ParseIP("10.0.0.5").To16()))
		Expect(result.IPs[0].Address.Mask).To(Equal(net.CIDRMask(24, 32)))
	})

	It("returns a result with the CNI version from the config", func() {
		conf := &config.Config{Address: "10.0.0.1/24"}
		conf.CNIVersion = "1.0.0"

		result, err := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		Expect(result.CNIVersion).To(Equal("1.0.0"))
	})

	It("returns an empty routes list", func() {
		conf := &config.Config{Address: "10.0.0.1/24"}

		result, err := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		Expect(result.Routes).To(BeEmpty())
	})

	It("returns error when address is invalid", func() {
		conf := &config.Config{Address: "not-a-cidr"}

		_, err := conf.Result(args)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid address"))
	})
})
