//go:build linux

package wireguard_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestWireguard(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Wireguard Suite")
}
