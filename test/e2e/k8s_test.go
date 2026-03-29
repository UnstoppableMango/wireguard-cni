//go:build linux

package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/unstoppablemango/wireguard-cni/test/utils"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// waitForPodRunning polls until the named pod reaches PodRunning phase.
func waitForPodRunning(ctx context.Context, n *utils.Pod) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		pod, err := n.Get(ctx)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(pod.Status.Phase).To(Equal(corev1.PodRunning))
	}, 2*time.Minute, 3*time.Second).Should(Succeed())
}

var _ = Describe("Kubernetes", Ordered, Label("k8s"), func() {
	const (
		clientWgAddr = "10.99.0.2"
		serverWgAddr = "10.99.0.1"
		wgPort       = 51820
		tcpPort      = 19999
	)

	var (
		client, server                   *utils.Pod
		serverConf, clientConf           []byte
		serverAddResult, clientAddResult []byte
	)

	BeforeAll(func(ctx context.Context) {
		c, err := utils.NewClient()
		Expect(err).NotTo(HaveOccurred())

		By("creating isolated test namespace (GenerateName: wg-e2e-)")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "wg-e2e-",
			},
		}
		created, err := c.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func(ctx context.Context) {
			_ = c.CoreV1().Namespaces().Delete(ctx, created.Name, metav1.DeleteOptions{})
		})

		By("creating Node objects for server and client (generates WireGuard key pairs)")
		client, err = utils.CreatePod(ctx, c, "wg-client-", created.Name)
		Expect(err).NotTo(HaveOccurred())

		server, err = utils.CreatePod(ctx, c, "wg-server-", created.Name)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for server pod to reach Running phase")
		waitForPodRunning(ctx, server)

		By("waiting for client pod to reach Running phase")
		waitForPodRunning(ctx, client)
	})

	BeforeAll(func(ctx context.Context) {
		By("getting server pod IP for use as WireGuard endpoint")
		serverPod, err := server.Get(ctx)
		Expect(err).NotTo(HaveOccurred())
		serverPodIP := serverPod.Status.PodIP
		Expect(serverPodIP).NotTo(BeEmpty())

		By("building CNI configs for server and client")
		serverConf, err = server.CniConfig(serverWgAddr+"/24", wgPort, []utils.CNIPeer{
			{PublicKey: client.PublicKey(), AllowedIPs: []string{clientWgAddr + "/32"}},
		})
		Expect(err).NotTo(HaveOccurred())

		clientConf, err = client.CniConfig(clientWgAddr+"/24", 0, []utils.CNIPeer{{
			PublicKey:           server.PublicKey(),
			AllowedIPs:          []string{serverWgAddr + "/32"},
			Endpoint:            fmt.Sprintf("%s:%d", serverPodIP, wgPort),
			PersistentKeepalive: 5,
		}})
		Expect(err).NotTo(HaveOccurred())

		By("invoking CNI ADD on server pod via wireguard-cni binary")
		stdout, stderr, err := server.InvokeCNI(ctx, "ADD", serverConf)
		Expect(err).NotTo(HaveOccurred(), "server CNI ADD failed\nstderr: %s\n stdout: %s", stderr, stdout)
		serverAddResult = []byte(stdout)

		By("invoking CNI ADD on client pod via wireguard-cni binary")
		stdout, stderr, err = client.InvokeCNI(ctx, "ADD", clientConf)
		Expect(err).NotTo(HaveOccurred(), "client CNI ADD failed\nstderr: %s\n stdout: %s", stderr, stdout)
		clientAddResult = []byte(stdout)
	})

	It("server pod has a WireGuard interface with the correct address", func(ctx context.Context) {
		By("checking wg0 address via 'ip addr show wg0'")
		stdout, stderr, err := server.Exec(ctx, []string{"ip", "addr", "show", "wg0"}, nil)
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		Expect(stdout).To(ContainSubstring(serverWgAddr))

		By("verifying client public key appears in 'wg show wg0'")
		stdout, stderr, err = server.Exec(ctx, []string{"wg", "show", "wg0"}, nil)
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		Expect(stdout).To(ContainSubstring(client.PublicKey()))
	})

	It("client pod has a WireGuard interface with the correct address", func(ctx context.Context) {
		By("checking wg0 address via 'ip addr show wg0'")
		stdout, stderr, err := client.Exec(ctx, []string{"ip", "addr", "show", "wg0"}, nil)
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		Expect(stdout).To(ContainSubstring(clientWgAddr))

		By("verifying server public key appears in 'wg show wg0'")
		stdout, stderr, err = client.Exec(ctx, []string{"wg", "show", "wg0"}, nil)
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		Expect(stdout).To(ContainSubstring(server.PublicKey()))
	})

	It("WireGuard handshake completes between pods", func(ctx context.Context) {
		By("waiting for latest-handshake timestamp to become non-zero (Eventually 30s)")
		Eventually(func(g Gomega) {
			stdout, stderr, err := client.Exec(ctx, []string{"wg", "show", "wg0", "latest-handshakes"}, nil)
			g.Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
			// Output format: "<pubkey>\t<unix-timestamp>\n"
			g.Expect(stdout).NotTo(BeEmpty())
			parts := strings.Fields(stdout)
			g.Expect(parts).To(HaveLen(2))
			g.Expect(parts[1]).NotTo(Equal("0"), "handshake timestamp is still 0")
		}, 30*time.Second, 2*time.Second).Should(Succeed())
	})

	It("TCP traffic flows through the WireGuard tunnel, not direct pod networking", func(ctx context.Context) {
		By("starting netcat listener on server pod (reachable only via wg0 tunnel from client)")
		// -k keeps the listener alive across Eventually retries.
		go func() {
			defer GinkgoRecover()
			server.Exec(ctx, []string{"nc", "-l", "-k", fmt.Sprintf("%d", tcpPort)}, nil) //nolint:errcheck
		}()

		// Give nc a moment to bind
		time.Sleep(500 * time.Millisecond)

		By("dialing server's WireGuard address from client pod (Eventually 15s)")
		Eventually(func(g Gomega) {
			stdout, stderr, err := client.Exec(ctx, []string{"sh", "-c",
				fmt.Sprintf("echo ok | nc -w 3 %s %d", serverWgAddr, tcpPort),
			}, nil)
			g.Expect(err).NotTo(HaveOccurred(), "nc connect failed\nstdout: %s\nstderr: %s", stdout, stderr)
		}, 15*time.Second, 2*time.Second).Should(Succeed())

		By("confirming WireGuard transfer counters show non-zero TX bytes on client")
		stdout, stderr, err := client.Exec(ctx, []string{"wg", "show", "wg0", "transfer"}, nil)
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		// Output: "<pubkey>\t<rx-bytes>\t<tx-bytes>"
		parts := strings.Fields(stdout)
		Expect(parts).To(HaveLen(3))
		Expect(parts[2]).NotTo(Equal("0"), "expected non-zero TX bytes after tunnel traffic")
	})

	It("CNI CHECK succeeds on server pod", func(ctx context.Context) {
		checkConf, err := withPrevResult(serverConf, serverAddResult)
		Expect(err).NotTo(HaveOccurred())
		_, stderr, err := server.InvokeCNI(ctx, "CHECK", checkConf)
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
	})

	It("CNI CHECK succeeds on client pod", func(ctx context.Context) {
		checkConf, err := withPrevResult(clientConf, clientAddResult)
		Expect(err).NotTo(HaveOccurred())
		_, stderr, err := client.InvokeCNI(ctx, "CHECK", checkConf)
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
	})

	It("CNI DEL removes the WireGuard interface from server pod", func(ctx context.Context) {
		_, stderr, err := server.InvokeCNI(ctx, "DEL", serverConf)
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)

		By("verifying wg0 no longer exists on server pod")
		_, _, err = server.Exec(ctx, []string{"ip", "link", "show", "wg0"}, nil)
		Expect(err).To(HaveOccurred(), "expected wg0 to be absent after CNI DEL")
	})

	It("CNI DEL removes the WireGuard interface from client pod", func(ctx context.Context) {
		_, stderr, err := client.InvokeCNI(ctx, "DEL", clientConf)
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)

		By("verifying wg0 no longer exists on client pod")
		_, _, err = client.Exec(ctx, []string{"ip", "link", "show", "wg0"}, nil)
		Expect(err).To(HaveOccurred(), "expected wg0 to be absent after CNI DEL")
	})
})

// withPrevResult embeds a CNI ADD result as prevResult for use in CHECK calls.
func withPrevResult(conf, prevResult []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(conf, &m); err != nil {
		return nil, err
	}
	m["prevResult"] = json.RawMessage(prevResult)
	return json.Marshal(m)
}
