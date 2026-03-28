package e2e_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestWireguardCNI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Wireguard CNI Suite", Label("e2e"))
}
