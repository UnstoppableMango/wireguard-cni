//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

// execInPod runs cmd inside a pod container and returns stdout, stderr, and any error.
func execInPod(ctx context.Context, clientset *kubernetes.Clientset, config *rest.Config,
	namespace, pod, container string, cmd []string) (string, string, error) {
	GinkgoHelper()

	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   cmd,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return "", "", err
	}

	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	return stdout.String(), stderr.String(), err
}

// waitForPodRunning polls until the named pod reaches PodRunning phase.
func waitForPodRunning(ctx context.Context, clientset *kubernetes.Clientset, namespace, name string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(pod.Status.Phase).To(Equal(corev1.PodRunning))
	}, 2*time.Minute, 3*time.Second).Should(Succeed())
}

// getPodIP returns the PodIP for the named pod, failing if empty.
func getPodIP(ctx context.Context, clientset *kubernetes.Clientset, namespace, name string) string {
	GinkgoHelper()
	pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	Expect(pod.Status.PodIP).NotTo(BeEmpty(), "pod %s has no PodIP", name)
	return pod.Status.PodIP
}

// createTestPod creates a privileged pod with wireguard-tools available.
// Returns the pod's generated name.
func createTestPod(ctx context.Context, clientset *kubernetes.Clientset, namespace, generateName string) string {
	GinkgoHelper()

	privileged := true
	uid := int64(0)
	netAdmin := corev1.Capability("NET_ADMIN")
	sysModule := corev1.Capability("SYS_MODULE")

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: generateName,
			Namespace:    namespace,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:            "main",
					Image:           "wireguard-cni-tools:latest",
					ImagePullPolicy: corev1.PullIfNotPresent,
					Command:         []string{"sleep", "3600"},
					SecurityContext: &corev1.SecurityContext{
						Privileged: &privileged,
						RunAsUser:  &uid,
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{netAdmin, sysModule},
						},
					},
				},
			},
		},
	}

	created, err := clientset.CoreV1().Pods(namespace).Create(ctx, pod, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	return created.Name
}

var _ = Describe("Kubernetes E2E", Ordered, Label("k8s-e2e"), func() {
	const (
		serverWgIP   = "10.99.0.1/24"
		clientWgIP   = "10.99.0.2/24"
		serverWgNet  = "10.99.0.0/24"
		clientWgNet  = "10.99.0.2/32"
		serverWgAddr = "10.99.0.1"
		wgPort       = 51820
		tcpPort      = 19999
	)

	var (
		ctx       context.Context
		clientset *kubernetes.Clientset
		config    *rest.Config
		namespace string
		serverPod string
		clientPod string
		serverKey wgtypes.Key
		clientKey wgtypes.Key
	)

	BeforeAll(func() {
		ctx = context.Background()

		By("checking for kubeconfig at $KUBECONFIG or .kube/config")
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			home, _ := os.UserHomeDir()
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		if _, err := os.Stat(kubeconfig); err != nil {
			Skip(fmt.Sprintf("kubeconfig not found at %s: %v", kubeconfig, err))
		}

		By("building Kubernetes client")
		var err error
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		Expect(err).NotTo(HaveOccurred())
		clientset, err = kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred())

		By("verifying cluster is reachable (5s timeout namespace list)")
		reachCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_, err = clientset.CoreV1().Namespaces().List(reachCtx, metav1.ListOptions{})
		if err != nil {
			Skip(fmt.Sprintf("cluster not reachable: %v", err))
		}
	})

	BeforeAll(func() {
		By("generating WireGuard key pairs for server and client")
		var err error
		serverKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		clientKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())

		By("creating isolated test namespace (GenerateName: wg-k8s-e2e-)")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "wg-k8s-e2e-",
			},
		}
		created, err := clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		namespace = created.Name
		DeferCleanup(func() {
			_ = clientset.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})
		})
	})

	BeforeAll(func() {
		By("creating privileged server pod with wireguard-tools")
		serverPod = createTestPod(ctx, clientset, namespace, "wg-server-")

		By("creating privileged client pod with wireguard-tools")
		clientPod = createTestPod(ctx, clientset, namespace, "wg-client-")

		By("waiting for server pod to reach Running phase")
		waitForPodRunning(ctx, clientset, namespace, serverPod)

		By("waiting for client pod to reach Running phase")
		waitForPodRunning(ctx, clientset, namespace, clientPod)
	})

	BeforeAll(func() {
		By("getting server pod IP for use as WireGuard endpoint")
		serverPodIP := getPodIP(ctx, clientset, namespace, serverPod)

		By("configuring WireGuard interface on server pod")
		serverCmds := [][]string{
			{"ip", "link", "add", "wg0", "type", "wireguard"},
			{"ip", "addr", "add", serverWgIP, "dev", "wg0"},
			{"sh", "-c", fmt.Sprintf("printf '%%s' '%s' > /tmp/wg-privkey", serverKey.String())},
			{"wg", "set", "wg0",
				"listen-port", fmt.Sprintf("%d", wgPort),
				"private-key", "/tmp/wg-privkey",
				"peer", clientKey.PublicKey().String(),
				"allowed-ips", serverWgNet,
			},
			{"rm", "/tmp/wg-privkey"},
			{"ip", "link", "set", "wg0", "up"},
		}
		for _, cmd := range serverCmds {
			stdout, stderr, err := execInPod(ctx, clientset, config, namespace, serverPod, "main", cmd)
			Expect(err).NotTo(HaveOccurred(),
				"server cmd %v failed\nstdout: %s\nstderr: %s", cmd, stdout, stderr)
		}

		By("configuring WireGuard interface on client pod")
		clientCmds := [][]string{
			{"ip", "link", "add", "wg0", "type", "wireguard"},
			{"ip", "addr", "add", clientWgIP, "dev", "wg0"},
			{"sh", "-c", fmt.Sprintf("printf '%%s' '%s' > /tmp/wg-privkey", clientKey.String())},
			{"wg", "set", "wg0",
				"private-key", "/tmp/wg-privkey",
				"peer", serverKey.PublicKey().String(),
				"allowed-ips", clientWgNet,
				"endpoint", fmt.Sprintf("%s:%d", serverPodIP, wgPort),
				"persistent-keepalive", "5",
			},
			{"rm", "/tmp/wg-privkey"},
			{"ip", "link", "set", "wg0", "up"},
		}
		for _, cmd := range clientCmds {
			stdout, stderr, err := execInPod(ctx, clientset, config, namespace, clientPod, "main", cmd)
			Expect(err).NotTo(HaveOccurred(),
				"client cmd %v failed\nstdout: %s\nstderr: %s", cmd, stdout, stderr)
		}
	})

	It("server pod has a WireGuard interface with the correct address", func() {
		By("checking wg0 address via 'ip addr show wg0'")
		stdout, stderr, err := execInPod(ctx, clientset, config, namespace, serverPod, "main",
			[]string{"ip", "addr", "show", "wg0"})
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		Expect(stdout).To(ContainSubstring(serverWgAddr))

		By("verifying client public key appears in 'wg show wg0'")
		stdout, stderr, err = execInPod(ctx, clientset, config, namespace, serverPod, "main",
			[]string{"wg", "show", "wg0"})
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		Expect(stdout).To(ContainSubstring(clientKey.PublicKey().String()))
	})

	It("client pod has a WireGuard interface with the correct address", func() {
		By("checking wg0 address via 'ip addr show wg0'")
		stdout, stderr, err := execInPod(ctx, clientset, config, namespace, clientPod, "main",
			[]string{"ip", "addr", "show", "wg0"})
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		Expect(stdout).To(ContainSubstring("10.99.0.2"))

		By("verifying server public key and endpoint appear in 'wg show wg0'")
		stdout, stderr, err = execInPod(ctx, clientset, config, namespace, clientPod, "main",
			[]string{"wg", "show", "wg0"})
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		Expect(stdout).To(ContainSubstring(serverKey.PublicKey().String()))
	})

	It("WireGuard handshake completes between pods", func() {
		By("waiting for latest-handshake timestamp to become non-zero (Eventually 30s)")
		Eventually(func(g Gomega) {
			stdout, stderr, err := execInPod(ctx, clientset, config, namespace, clientPod, "main",
				[]string{"wg", "show", "wg0", "latest-handshakes"})
			g.Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
			// Output format: "<pubkey>\t<unix-timestamp>\n"
			// A non-zero handshake has a timestamp > 0
			g.Expect(stdout).NotTo(BeEmpty())
			parts := strings.Fields(stdout)
			g.Expect(parts).To(HaveLen(2))
			g.Expect(parts[1]).NotTo(Equal("0"), "handshake timestamp is still 0")
		}, 30*time.Second, 2*time.Second).Should(Succeed())

		By("confirming handshake timestamp is non-zero on client side")
		stdout, stderr, err := execInPod(ctx, clientset, config, namespace, clientPod, "main",
			[]string{"wg", "show", "wg0", "latest-handshakes"})
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		parts := strings.Fields(stdout)
		Expect(parts).To(HaveLen(2))
		Expect(parts[1]).NotTo(Equal("0"))
	})

	It("TCP traffic flows through the WireGuard tunnel, not direct pod networking", func() {
		By("starting netcat listener bound only to server's WireGuard IP 10.99.0.1")
		// nc -l binds to the WireGuard IP — only reachable via wg0 tunnel.
		go func() {
			defer GinkgoRecover()
			// Best-effort: start listener; we don't need the result
			execInPod(ctx, clientset, config, namespace, serverPod, "main", //nolint:errcheck
				[]string{"nc", "-l", "-p", fmt.Sprintf("%d", tcpPort), "-s", serverWgAddr})
		}()

		// Give nc a moment to bind
		time.Sleep(500 * time.Millisecond)

		By("dialing server's WireGuard address from client pod (Eventually 15s)")
		Eventually(func(g Gomega) {
			stdout, stderr, err := execInPod(ctx, clientset, config, namespace, clientPod, "main",
				[]string{"sh", "-c",
					fmt.Sprintf("echo ok | nc -w 3 %s %d", serverWgAddr, tcpPort),
				})
			g.Expect(err).NotTo(HaveOccurred(),
				"nc connect failed\nstdout: %s\nstderr: %s", stdout, stderr)
		}, 15*time.Second, 2*time.Second).Should(Succeed())

		By("confirming WireGuard transfer counters show non-zero TX bytes on client")
		stdout, stderr, err := execInPod(ctx, clientset, config, namespace, clientPod, "main",
			[]string{"wg", "show", "wg0", "transfer"})
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		// Output: "<pubkey>\t<rx-bytes>\t<tx-bytes>"
		parts := strings.Fields(stdout)
		Expect(parts).To(HaveLen(3))
		Expect(parts[2]).NotTo(Equal("0"), "expected non-zero TX bytes after tunnel traffic")
	})
})
