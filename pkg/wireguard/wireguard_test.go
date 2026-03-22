//go:build linux

package wireguard_test

import (
	"encoding/base64"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unstoppablemango/wireguard-cni/pkg/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func keyBase64(key wgtypes.Key) string {
	b := [32]byte(key)
	return base64.StdEncoding.EncodeToString(b[:])
}

var _ = Describe("ParseKey", func() {
	It("decodes a valid base64 key", func() {
		key, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		parsed, err := wireguard.ParseKey(keyBase64(key))
		Expect(err).NotTo(HaveOccurred())
		Expect(parsed).To(Equal(key))
	})

	It("rejects invalid base64", func() {
		_, err := wireguard.ParseKey("!!!not-base64!!!")
		Expect(err).To(HaveOccurred())
	})

	It("rejects a key of wrong length", func() {
		short := base64.StdEncoding.EncodeToString([]byte("short"))
		_, err := wireguard.ParseKey(short)
		Expect(err).To(HaveOccurred())
	})
})
