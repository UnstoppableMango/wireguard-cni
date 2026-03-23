package network_test

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unstoppablemango/wireguard-cni/pkg/network"
)

var _ = Describe("ParseAddress", func() {
	It("preserves the host IP", func() {
		addr, err := network.ParseAddress("10.100.0.2/24")
		Expect(err).NotTo(HaveOccurred())
		Expect(addr.IP.String()).To(Equal("10.100.0.2"))
		Expect(addr.Mask).To(Equal(net.CIDRMask(24, 32)))
	})

	It("rejects invalid CIDR", func() {
		_, err := network.ParseAddress("not-valid")
		Expect(err).To(HaveOccurred())
	})
})
