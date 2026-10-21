//go:build linux

package e2e_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/unstoppablemango/wireguard-cni/test/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("Kubernetes secret ref", Ordered, Label("k8s"), func() {
	const (
		clientWgAddr = "10.99.1.2"
		serverWgAddr = "10.99.1.1"
		wgPort       = 51821
	)

	var (
		c      *utils.Client
		client *utils.Pod
		server *utils.Pod
	)

	BeforeAll(func(ctx context.Context) {
		var err error
		c, err = utils.NewClient()
		Expect(err).NotTo(HaveOccurred())

		By("creating isolated test namespace")
		created, err := c.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "wg-e2e-secret-"},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		ns := created.Name
		DeferCleanup(func(ctx context.Context) {
			_ = c.CoreV1().Namespaces().Delete(ctx, ns, metav1.DeleteOptions{})
		})

		By("granting the default service account access to read secrets")
		Expect(c.GrantSecretAccess(ctx, ns)).To(Succeed())

		By("creating server and client pods")
		client, err = c.CreatePod(ctx, "wg-client-", ns, clientWgAddr)
		Expect(err).NotTo(HaveOccurred())
		server, err = c.CreatePod(ctx, "wg-server-", ns, serverWgAddr)
		Expect(err).NotTo(HaveOccurred())

		By("creating private key secrets for server and client")
		Expect(server.CreatePrivateKeySecret(ctx, "server-wg-key")).To(Succeed())
		Expect(client.CreatePrivateKeySecret(ctx, "client-wg-key")).To(Succeed())

		By("waiting for pods to reach Running phase")
		waitForPodRunning(ctx, server)
		waitForPodRunning(ctx, client)
	})

	for _, ver := range testutils.AllSpecVersions {
		Describe(fmt.Sprintf("cni %s", ver), Label(ver), Ordered, func() {
			var serverConf, clientConf []byte

			BeforeAll(func(ctx context.Context) {
				By("getting server pod IP for use as WireGuard endpoint")
				serverPod, err := server.Get(ctx)
				Expect(err).NotTo(HaveOccurred())
				serverPodIP := serverPod.Status.PodIP
				Expect(serverPodIP).NotTo(BeEmpty())

				By("building CNI configs using privateKeyRef")
				serverConf, err = server.CniConfigWithSecretRef(ver, wgPort, []utils.CNIPeer{
					client.ClientPeer(),
				}, "server-wg-key")
				Expect(err).NotTo(HaveOccurred())

				clientConf, err = client.CniConfigWithSecretRef(ver, 0, []utils.CNIPeer{
					server.ServerPeer(serverPodIP, wgPort),
				}, "client-wg-key")
				Expect(err).NotTo(HaveOccurred())

				By("invoking CNI ADD on server pod")
				stdout, stderr, err := server.InvokeCNI(ctx, "ADD", serverConf)
				Expect(err).NotTo(HaveOccurred(), "server CNI ADD failed\nstderr: %s\nstdout: %s", stderr, stdout)

				By("invoking CNI ADD on client pod")
				stdout, stderr, err = client.InvokeCNI(ctx, "ADD", clientConf)
				Expect(err).NotTo(HaveOccurred(), "client CNI ADD failed\nstderr: %s\nstdout: %s", stderr, stdout)

				// Give the WireGuard handshake a moment
				time.Sleep(500 * time.Millisecond)

				DeferCleanup(func(ctx context.Context) {
					By("invoking CNI DEL on server pod")
					server.InvokeCNI(ctx, "DEL", serverConf) //nolint:errcheck
					By("invoking CNI DEL on client pod")
					client.InvokeCNI(ctx, "DEL", clientConf) //nolint:errcheck
				})
			})

			It("server pod has a WireGuard interface with the correct address", func(ctx context.Context) {
				stdout, stderr, err := server.Exec(ctx, []string{"ip", "addr", "show", "wg0"}, nil)
				Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
				Expect(stdout).To(ContainSubstring(serverWgAddr))
			})

			It("client pod has a WireGuard interface with the correct address", func(ctx context.Context) {
				stdout, stderr, err := client.Exec(ctx, []string{"ip", "addr", "show", "wg0"}, nil)
				Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
				Expect(stdout).To(ContainSubstring(clientWgAddr))
			})

			It("server has the correct peer public key configured", func(ctx context.Context) {
				stdout, stderr, err := server.Exec(ctx, []string{"wg", "show", "wg0"}, nil)
				Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
				Expect(stdout).To(ContainSubstring(client.PublicKey()))
			})
		})
	}
})
