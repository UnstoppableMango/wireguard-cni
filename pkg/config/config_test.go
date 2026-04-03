package config_test

import (
	"encoding/json"
	"maps"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/cni/pkg/skel"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newNetConfWithRuntimeConfig(privKey, peerPubKey, address string, rc map[string]any) []byte {
	merged := map[string]any{"ips": []string{address}}
	maps.Copy(merged, rc)
	conf := map[string]any{
		"cniVersion": "1.0.0",
		"name":       "wg-test",
		"type":       "wireguard-cni",
		"privateKey": privKey,
		"peers": []map[string]any{
			{
				"publicKey":  peerPubKey,
				"allowedIPs": []string{"10.0.0.0/8"},
			},
		},
		"runtimeConfig": merged,
	}
	b, _ := json.Marshal(conf)
	return b
}

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
		Expect(err.Error()).To(ContainSubstring("failed to parse network configuration"))
	})

	It("returns error when prevResult cannot be parsed", func() {
		// cniVersion 0.0.1 is not a supported result version, so ParsePrevResult fails.
		stdin := []byte(`{"cniVersion":"0.0.1","name":"wg-test","type":"wireguard-cni","prevResult":{}}`)

		_, err := config.Parse(stdin)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("could not parse prevResult"))
	})

	It("returns error when runtimeConfig.ips is absent", func() {
		stdin := []byte(`{"cniVersion":"1.0.0","name":"wg-test","type":"wireguard-cni"}`)

		_, err := config.Parse(stdin)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("runtimeConfig.ips is required"))
	})

	It("returns error when runtimeConfig.ips is empty", func() {
		stdin := []byte(`{"cniVersion":"1.0.0","name":"wg-test","type":"wireguard-cni","runtimeConfig":{"ips":[]}}`)

		_, err := config.Parse(stdin)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("runtimeConfig.ips is required"))
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

	It("emits all IPs when multiple are provided", func() {
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

var _ = Describe("ParseMAC", func() {
	It("returns nil when no MAC is configured", func() {
		conf := &config.Config{}

		mac, err := conf.ParseMAC()

		Expect(err).NotTo(HaveOccurred())
		Expect(mac).To(BeNil())
	})

	It("parses a valid MAC address", func() {
		conf := &config.Config{}
		conf.RuntimeConfig.MAC = "02:11:22:33:44:55"

		mac, err := conf.ParseMAC()

		Expect(err).NotTo(HaveOccurred())
		Expect(mac).To(Equal(net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}))
	})

	It("returns error for an invalid MAC string", func() {
		conf := &config.Config{}
		conf.RuntimeConfig.MAC = "not-a-mac"

		_, err := conf.ParseMAC()

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("invalid MAC address"))
	})

	It("parses MAC from runtimeConfig JSON", func() {
		privKey, _ := wgtypes.GeneratePrivateKey()
		peerKey, _ := wgtypes.GeneratePrivateKey()
		stdin := newNetConfWithRuntimeConfig(privKey.String(), peerKey.PublicKey().String(), "10.0.0.1/24", map[string]any{
			"mac": "02:ab:cd:ef:00:01",
		})

		conf, err := config.Parse(stdin)
		Expect(err).NotTo(HaveOccurred())

		mac, err := conf.ParseMAC()
		Expect(err).NotTo(HaveOccurred())
		Expect(mac).To(Equal(net.HardwareAddr{0x02, 0xab, 0xcd, 0xef, 0x00, 0x01}))
	})
})

var _ = Describe("BandwidthEntry", func() {
	It("parses bandwidth config from runtimeConfig JSON", func() {
		privKey, _ := wgtypes.GeneratePrivateKey()
		peerKey, _ := wgtypes.GeneratePrivateKey()
		stdin := newNetConfWithRuntimeConfig(privKey.String(), peerKey.PublicKey().String(), "10.0.0.1/24", map[string]any{
			"bandwidth": map[string]any{
				"ingressRate":  1000000,
				"ingressBurst": 2000000,
				"egressRate":   500000,
				"egressBurst":  1000000,
			},
		})

		conf, err := config.Parse(stdin)
		Expect(err).NotTo(HaveOccurred())
		Expect(conf.RuntimeConfig.Bandwidth).NotTo(BeNil())
		Expect(conf.RuntimeConfig.Bandwidth.IngressRate).To(Equal(uint64(1000000)))
		Expect(conf.RuntimeConfig.Bandwidth.IngressBurst).To(Equal(uint64(2000000)))
		Expect(conf.RuntimeConfig.Bandwidth.EgressRate).To(Equal(uint64(500000)))
		Expect(conf.RuntimeConfig.Bandwidth.EgressBurst).To(Equal(uint64(1000000)))
	})

	It("bandwidth is nil when not set in runtimeConfig", func() {
		privKey, _ := wgtypes.GeneratePrivateKey()
		peerKey, _ := wgtypes.GeneratePrivateKey()
		stdin := newNetConf(privKey.String(), peerKey.PublicKey().String(), "10.0.0.1/24")

		conf, err := config.Parse(stdin)
		Expect(err).NotTo(HaveOccurred())
		Expect(conf.RuntimeConfig.Bandwidth).To(BeNil())
	})
})
