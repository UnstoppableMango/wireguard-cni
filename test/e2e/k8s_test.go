//go:build linux

package e2e_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/unstoppablemango/wireguard-cni/test/utils"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// waitForPodRunning polls until the named pod reaches PodRunning phase.
func waitForPodRunning(ctx context.Context, n *utils.Pod, podName string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		pod, err := n.Get(ctx, podName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(pod.Status.Phase).To(Equal(corev1.PodRunning))
	}, 2*time.Minute, 3*time.Second).Should(Succeed())
}

var _ = Describe("Kubernetes", Ordered, Label("k8s"), func() {
	const (
		serverWgIP     = "10.99.0.1/24"
		clientWgIP     = "10.99.0.2/24"
		serverWgAddr   = "10.99.0.1"
		wgPort         = 51820
		tcpPort        = 19999
		cniIfName      = "wg0"
		cniContainerID = "k8s-e2e-test"
		// /proc/1/ns/net is the network namespace of the container's init process,
		// i.e. the pod's own netns — accessible from within the container.
		cniNetns = "/proc/1/ns/net"
	)

	var (
		client kubernetes.Interface
		config *rest.Config

		clientPod, serverPod             *corev1.Pod
		clientNode, serverNode           *Node
		serverConf, clientConf           []byte
		serverAddResult, clientAddResult []byte
	)

	BeforeAll(func(ctx context.Context) {
		By("checking for kubeconfig at $KUBECONFIG")
		kubeconfig := os.Getenv("KUBECONFIG")
		if _, err := os.Stat(kubeconfig); err != nil {
			Skip(fmt.Sprintf("kubeconfig not found at %s: %v", kubeconfig, err))
		}

		By("building Kubernetes client")
		var err error
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())
		client, err = kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred())

		_, err = client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			Skip(fmt.Sprintf("cluster not reachable: %v", err))
		}
	})

	BeforeAll(func(ctx context.Context) {
		By("creating isolated test namespace (GenerateName: wg-e2e-)")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "wg-e2e-",
			},
		}
		created, err := client.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func(ctx context.Context) {
			_ = client.CoreV1().Namespaces().Delete(ctx, created.Name, metav1.DeleteOptions{})
		})

		By("creating Node objects for server and client (generates WireGuard key pairs)")
		clientNode, err = newNode("wg-client-", created.Name, client, config)
		Expect(err).NotTo(HaveOccurred())

		serverNode, err = newNode("wg-server-", created.Name, client, config)
		Expect(err).NotTo(HaveOccurred())
	})

	BeforeAll(func(ctx context.Context) {
		var err error

		By("creating privileged server pod with CNI binary mounted from host")
		serverPod, err = serverNode.createPod(ctx)
		Expect(err).NotTo(HaveOccurred())

		By("creating privileged client pod with CNI binary mounted from host")
		clientPod, err = clientNode.createPod(ctx)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for server pod to reach Running phase")
		waitForPodRunning(ctx, serverNode, serverPod.Name)

		By("waiting for client pod to reach Running phase")
		waitForPodRunning(ctx, clientNode, clientPod.Name)
	})

	BeforeAll(func(ctx context.Context) {
		var err error

		By("getting server pod IP for use as WireGuard endpoint")
		serverPod, err = serverNode.getPod(ctx, serverPod.Name)
		Expect(err).NotTo(HaveOccurred())
		serverPodIP := serverPod.Status.PodIP
		Expect(serverPodIP).NotTo(BeEmpty())

		By("building CNI configs for server and client")
		serverConf, err = buildCNIConf(serverNode.key, serverWgIP, wgPort, []cniPeer{
			{PublicKey: clientNode.publicKey(), AllowedIPs: []string{"10.99.0.2/32"}},
		})
		Expect(err).NotTo(HaveOccurred())

		clientConf, err = buildCNIConf(clientNode.key, clientWgIP, 0, []cniPeer{{
			PublicKey:           serverNode.publicKey(),
			AllowedIPs:          []string{"10.99.0.1/32"},
			Endpoint:            fmt.Sprintf("%s:%d", serverPodIP, wgPort),
			PersistentKeepalive: 5,
		}})
		Expect(err).NotTo(HaveOccurred())

		By("invoking CNI ADD on server pod via wireguard-cni binary")
		stdout, stderr, err := serverNode.invokeCNI(ctx, serverPod.Name, "ADD", cniContainerID, cniNetns, cniIfName, serverConf)
		Expect(err).NotTo(HaveOccurred(), "server CNI ADD failed\nstderr: %s\n stdout: %s", stderr, stdout)
		serverAddResult = []byte(stdout)

		By("invoking CNI ADD on client pod via wireguard-cni binary")
		stdout, stderr, err = clientNode.invokeCNI(ctx, clientPod.Name, "ADD", cniContainerID, cniNetns, cniIfName, clientConf)
		Expect(err).NotTo(HaveOccurred(), "client CNI ADD failed\nstderr: %s\n stdout: %s", stderr, stdout)
		clientAddResult = []byte(stdout)
	})

	It("server pod has a WireGuard interface with the correct address", func(ctx context.Context) {
		By("checking wg0 address via 'ip addr show wg0'")
		stdout, stderr, err := serverNode.exec(ctx, serverPod.Name,
			[]string{"ip", "addr", "show", "wg0"})
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		Expect(stdout).To(ContainSubstring(serverWgAddr))

		By("verifying client public key appears in 'wg show wg0'")
		stdout, stderr, err = serverNode.exec(ctx, serverPod.Name,
			[]string{"wg", "show", "wg0"})
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		Expect(stdout).To(ContainSubstring(clientNode.publicKey()))
	})

	It("client pod has a WireGuard interface with the correct address", func(ctx context.Context) {
		By("checking wg0 address via 'ip addr show wg0'")
		stdout, stderr, err := clientNode.exec(ctx, clientPod.Name,
			[]string{"ip", "addr", "show", "wg0"})
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		Expect(stdout).To(ContainSubstring("10.99.0.2"))

		By("verifying server public key appears in 'wg show wg0'")
		stdout, stderr, err = clientNode.exec(ctx, clientPod.Name,
			[]string{"wg", "show", "wg0"})
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		Expect(stdout).To(ContainSubstring(serverNode.publicKey()))
	})

	It("WireGuard handshake completes between pods", func(ctx context.Context) {
		By("waiting for latest-handshake timestamp to become non-zero (Eventually 30s)")
		Eventually(func(g Gomega) {
			stdout, stderr, err := clientNode.exec(ctx, clientPod.Name,
				[]string{"wg", "show", "wg0", "latest-handshakes"})
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
			serverNode.exec(ctx, serverPod.Name, []string{"nc", "-l", "-k", fmt.Sprintf("%d", tcpPort)}) //nolint:errcheck
		}()

		// Give nc a moment to bind
		time.Sleep(500 * time.Millisecond)

		By("dialing server's WireGuard address from client pod (Eventually 15s)")
		Eventually(func(g Gomega) {
			stdout, stderr, err := clientNode.exec(ctx, clientPod.Name,
				[]string{"sh", "-c",
					fmt.Sprintf("echo ok | nc -w 3 %s %d", serverWgAddr, tcpPort),
				})
			g.Expect(err).NotTo(HaveOccurred(),
				"nc connect failed\nstdout: %s\nstderr: %s", stdout, stderr)
		}, 15*time.Second, 2*time.Second).Should(Succeed())

		By("confirming WireGuard transfer counters show non-zero TX bytes on client")
		stdout, stderr, err := clientNode.exec(ctx, clientPod.Name,
			[]string{"wg", "show", "wg0", "transfer"})
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		// Output: "<pubkey>\t<rx-bytes>\t<tx-bytes>"
		parts := strings.Fields(stdout)
		Expect(parts).To(HaveLen(3))
		Expect(parts[2]).NotTo(Equal("0"), "expected non-zero TX bytes after tunnel traffic")
	})

	It("CNI CHECK succeeds on server pod", func(ctx context.Context) {
		checkConf, err := withPrevResult(serverConf, serverAddResult)
		Expect(err).NotTo(HaveOccurred())
		_, stderr, err := serverNode.invokeCNI(ctx, serverPod.Name, "CHECK", cniContainerID, cniNetns, cniIfName, checkConf)
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
	})

	It("CNI CHECK succeeds on client pod", func(ctx context.Context) {
		checkConf, err := withPrevResult(clientConf, clientAddResult)
		Expect(err).NotTo(HaveOccurred())
		_, stderr, err := clientNode.invokeCNI(ctx, clientPod.Name, "CHECK", cniContainerID, cniNetns, cniIfName, checkConf)
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
	})

	It("CNI DEL removes the WireGuard interface from server pod", func(ctx context.Context) {
		_, stderr, err := serverNode.invokeCNI(ctx, serverPod.Name, "DEL", cniContainerID, cniNetns, cniIfName, serverConf)
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)

		By("verifying wg0 no longer exists on server pod")
		_, _, err = serverNode.exec(ctx, serverPod.Name, []string{"ip", "link", "show", "wg0"})
		Expect(err).To(HaveOccurred(), "expected wg0 to be absent after CNI DEL")
	})

	It("CNI DEL removes the WireGuard interface from client pod", func(ctx context.Context) {
		_, stderr, err := clientNode.invokeCNI(ctx, clientPod.Name, "DEL", cniContainerID, cniNetns, cniIfName, clientConf)
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)

		By("verifying wg0 no longer exists on client pod")
		_, _, err = clientNode.exec(ctx, clientPod.Name, []string{"ip", "link", "show", "wg0"})
		Expect(err).To(HaveOccurred(), "expected wg0 to be absent after CNI DEL")
	})
})
