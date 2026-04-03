package config_test

import (
	"encoding/json"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/pkg/skel"
	current "github.com/containernetworking/cni/pkg/types/100"
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
		Expect(conf.RuntimeConfig.IPs).To(ConsistOf("10.100.0.2/24"))
		Expect(conf.PrivateKey).To(Equal(privKey.String()))
		Expect(conf.Peers).To(HaveLen(1))
	})

	It("returns error when stdin is not valid JSON", func() {
		_, err := config.Parse([]byte("not-json"))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unmarshal config"))
	})

	It("returns error when prevResult cannot be parsed", func() {
		// cniVersion 0.0.1 is not a supported result version, so ParsePrevResult fails.
		stdin := []byte(`{"cniVersion":"0.0.1","name":"wg-test","type":"wireguard-cni","prevResult":{}}`)

		_, err := config.Parse(stdin)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("could not parse prevResult"))
	})
})

var _ = Describe("MergedResult", func() {
	var (
		args    *skel.CmdArgs
		privKey wgtypes.Key
		peerKey wgtypes.Key
	)

	BeforeEach(func() {
		var err error
		args = &skel.CmdArgs{
			IfName: "wg0",
			Netns:  "/var/run/netns/test",
		}
		privKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		peerKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
	})

	It("with nil PrevResult returns the same result as Result()", func() {
		conf := configWithIPs("10.100.0.2/24")

		merged, err := conf.Result(args)
		standalone, err2 := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		Expect(err2).NotTo(HaveOccurred())
		Expect(merged.Interfaces).To(Equal(standalone.Interfaces))
		Expect(merged.IPs).To(HaveLen(1))
	})

	It("with prevResult appends WireGuard interface after existing interfaces", func() {
		prevResult := buildPrevResult("eth0", "/var/run/netns/test", "192.168.1.2/24")
		stdin := newNetConfWithPrevResult(privKey.String(), peerKey.PublicKey().String(), "10.100.0.2/24", prevResult)
		conf, err := config.Parse(stdin)
		Expect(err).NotTo(HaveOccurred())

		result, err := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		Expect(result.Interfaces).To(HaveLen(2))
		Expect(result.Interfaces[0].Name).To(Equal("eth0"))
		Expect(result.Interfaces[1].Name).To(Equal("wg0"))
		Expect(result.Interfaces[1].Sandbox).To(Equal("/var/run/netns/test"))
	})

	It("with prevResult sets the WireGuard IP interface index to len(prevInterfaces)", func() {
		prevResult := buildPrevResult("eth0", "/var/run/netns/test", "192.168.1.2/24")
		stdin := newNetConfWithPrevResult(privKey.String(), peerKey.PublicKey().String(), "10.100.0.2/24", prevResult)
		conf, err := config.Parse(stdin)
		Expect(err).NotTo(HaveOccurred())

		result, err := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		wgIP := result.IPs[len(result.IPs)-1]
		Expect(wgIP.Interface).NotTo(BeNil())
		Expect(*wgIP.Interface).To(Equal(1)) // eth0 is index 0, wg0 is index 1
	})

	It("with prevResult preserves existing interfaces", func() {
		prevResult := buildPrevResult("eth0", "/var/run/netns/test", "192.168.1.2/24")
		stdin := newNetConfWithPrevResult(privKey.String(), peerKey.PublicKey().String(), "10.100.0.2/24", prevResult)
		conf, err := config.Parse(stdin)
		Expect(err).NotTo(HaveOccurred())

		result, err := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		Expect(result.Interfaces[0].Name).To(Equal("eth0"))
	})

	It("with prevResult preserves existing IPs", func() {
		prevResult := buildPrevResult("eth0", "/var/run/netns/test", "192.168.1.2/24")
		stdin := newNetConfWithPrevResult(privKey.String(), peerKey.PublicKey().String(), "10.100.0.2/24", prevResult)
		conf, err := config.Parse(stdin)
		Expect(err).NotTo(HaveOccurred())

		result, err := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		Expect(result.IPs).To(HaveLen(2))
		Expect(result.IPs[0].Address.IP.String()).To(Equal("192.168.1.2"))
	})

	It("with prevResult returns the WireGuard IP from runtimeConfig.ips[0]", func() {
		prevResult := buildPrevResult("eth0", "/var/run/netns/test", "192.168.1.2/24")
		stdin := newNetConfWithPrevResult(privKey.String(), peerKey.PublicKey().String(), "10.100.0.2/24", prevResult)
		conf, err := config.Parse(stdin)
		Expect(err).NotTo(HaveOccurred())

		result, err := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		wgIP := result.IPs[len(result.IPs)-1]
		Expect(wgIP.Address.IP.String()).To(Equal("10.100.0.2"))
		Expect(wgIP.Address.Mask).To(Equal(net.CIDRMask(24, 32)))
	})

	It("with prevResult returns error when address is invalid", func() {
		prevResult := buildPrevResult("eth0", "/var/run/netns/test", "192.168.1.2/24")
		stdin := newNetConfWithPrevResult(privKey.String(), peerKey.PublicKey().String(), "not-a-cidr", prevResult)
		conf, err := config.Parse(stdin)
		Expect(err).NotTo(HaveOccurred())

		_, err = conf.Result(args)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid CIDR address"))
	})
})

// buildPrevResult constructs a minimal CNI 1.0.0 result JSON for use as prevResult in tests.
func buildPrevResult(ifName, sandbox, cidr string) []byte {
	ifIdx := 0
	ip, ipnet, _ := net.ParseCIDR(cidr)
	result := &current.Result{
		CNIVersion: "1.0.0",
		Interfaces: []*current.Interface{
			{Name: ifName, Sandbox: sandbox},
		},
		IPs: []*current.IPConfig{
			{
				Interface: &ifIdx,
				Address:   net.IPNet{IP: ip, Mask: ipnet.Mask},
			},
		},
	}
	b, _ := json.Marshal(result)
	return b
}

var _ = Describe("Result", func() {
	var args *skel.CmdArgs

	BeforeEach(func() {
		args = &skel.CmdArgs{
			IfName: "wg0",
			Netns:  "/var/run/netns/test",
		}
	})

	It("returns a result with the interface name and netns from args", func() {
		conf := configWithIPs("10.0.0.1/24")

		result, err := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		Expect(result.Interfaces).To(HaveLen(1))
		Expect(result.Interfaces[0].Name).To(Equal("wg0"))
		Expect(result.Interfaces[0].Sandbox).To(Equal("/var/run/netns/test"))
	})

	It("returns a result with the host IP from runtimeConfig.ips[0]", func() {
		conf := configWithIPs("10.0.0.5/24")

		result, err := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		Expect(result.IPs).To(HaveLen(1))
		Expect(result.IPs[0].Address.IP).To(Equal(net.ParseIP("10.0.0.5").To16()))
		Expect(result.IPs[0].Address.Mask).To(Equal(net.CIDRMask(24, 32)))
	})

	It("returns a result with the CNI version from the config", func() {
		conf := configWithIPs("10.0.0.1/24")
		conf.CNIVersion = "1.0.0"

		result, err := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		Expect(result.CNIVersion).To(Equal("1.0.0"))
	})

	It("returns an empty routes list", func() {
		conf := configWithIPs("10.0.0.1/24")

		result, err := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		Expect(result.Routes).To(BeEmpty())
	})

	It("uses only the first IP when multiple are provided", func() {
		conf := configWithIPs("10.0.0.1/24", "10.0.0.2/24")

		result, err := conf.Result(args)

		Expect(err).NotTo(HaveOccurred())
		Expect(result.IPs).To(HaveLen(2))
		Expect(result.IPs[0].Address.IP.String()).To(Equal("10.0.0.1"))
		Expect(result.IPs[1].Address.IP.String()).To(Equal("10.0.0.2"))
	})

	It("returns error when address is invalid", func() {
		conf := configWithIPs("not-a-cidr")

		_, err := conf.Result(args)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid CIDR address"))
	})
})
