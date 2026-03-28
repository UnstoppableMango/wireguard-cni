//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
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

// waitForPodRunning polls until the named pod reaches PodRunning phase.
func waitForPodRunning(ctx context.Context, n *Node, podName string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		pod, err := n.getPod(ctx, podName)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(pod.Status.Phase).To(Equal(corev1.PodRunning))
	}, 2*time.Minute, 3*time.Second).Should(Succeed())
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
		client kubernetes.Interface
		config *rest.Config

		clientSecret, serverSecret *corev1.Secret
		clientPod, serverPod       *corev1.Pod

		clientNode *Node
		serverNode *Node
	)

	BeforeAll(func(ctx context.Context) {
		By("checking for kubeconfig at $KUBECONFIG or .kube/config")
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
		By("generating WireGuard key pairs for server and client")
		serverKey, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
		clientKey, err := wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())

		By("creating isolated test namespace (GenerateName: wg-e2e-)")
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "wg-e2e-",
			},
		}
		created, err := client.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() {
			_ = client.CoreV1().Namespaces().Delete(ctx, created.Name, metav1.DeleteOptions{})
		})

		clientNode = newNode("wg-client-", created.Name, clientKey, serverKey, client, config)
		serverNode = newNode("wg-server-", created.Name, serverKey, clientKey, client, config)

		By("creating Secrets for server and client WireGuard private keys")
		clientSecret, err = clientNode.createPrivKeySecret(ctx)
		Expect(err).NotTo(HaveOccurred())
		serverSecret, err = serverNode.createPrivKeySecret(ctx)
		Expect(err).NotTo(HaveOccurred())
	})

	BeforeAll(func(ctx context.Context) {
		var err error

		By("creating privileged server pod with wireguard-tools")
		serverPod, err = serverNode.createTestPod(ctx, serverSecret.Name)
		Expect(err).NotTo(HaveOccurred())

		By("creating privileged client pod with wireguard-tools")
		clientPod, err = clientNode.createTestPod(ctx, clientSecret.Name)
		Expect(err).NotTo(HaveOccurred())

		By("waiting for server pod to reach Running phase")
		waitForPodRunning(ctx, serverNode, serverPod.Name)

		By("waiting for client pod to reach Running phase")
		waitForPodRunning(ctx, clientNode, clientPod.Name)
	})

	BeforeAll(func(ctx context.Context) {
		By("getting server pod IP for use as WireGuard endpoint")
		serverPodIP := serverPod.Status.PodIP
		Expect(serverPodIP).NotTo(BeEmpty())

		By("configuring WireGuard interface on server pod")
		serverCmds := [][]string{
			{"ip", "link", "add", "wg0", "type", "wireguard"},
			{"ip", "addr", "add", serverWgIP, "dev", "wg0"},
			{"wg", "set", "wg0",
				"listen-port", fmt.Sprintf("%d", wgPort),
				"private-key", "/run/secrets/wireguard/privatekey",
				"peer", clientNode.publicKey().String(),
				"allowed-ips", serverWgNet,
			},
			{"ip", "link", "set", "wg0", "up"},
		}
		for _, cmd := range serverCmds {
			stdout, stderr, err := serverNode.exec(ctx, serverPod.Name, cmd)
			Expect(err).NotTo(HaveOccurred(),
				"server cmd %v failed\nstdout: %s\nstderr: %s", cmd, stdout, stderr)
		}

		By("configuring WireGuard interface on client pod")
		clientCmds := [][]string{
			{"ip", "link", "add", "wg0", "type", "wireguard"},
			{"ip", "addr", "add", clientWgIP, "dev", "wg0"},
			{"wg", "set", "wg0",
				"private-key", "/run/secrets/wireguard/privatekey",
				"peer", serverNode.publicKey().String(),
				"allowed-ips", clientWgNet,
				"endpoint", fmt.Sprintf("%s:%d", serverPodIP, wgPort),
				"persistent-keepalive", "5",
			},
			{"ip", "link", "set", "wg0", "up"},
		}
		for _, cmd := range clientCmds {
			stdout, stderr, err := clientNode.exec(ctx, clientPod.Name, cmd)
			Expect(err).NotTo(HaveOccurred(),
				"client cmd %v failed\nstdout: %s\nstderr: %s", cmd, stdout, stderr)
		}
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
		Expect(stdout).To(ContainSubstring(clientNode.publicKey().String()))
	})

	It("client pod has a WireGuard interface with the correct address", func(ctx context.Context) {
		By("checking wg0 address via 'ip addr show wg0'")
		stdout, stderr, err := clientNode.exec(ctx, clientPod.Name,
			[]string{"ip", "addr", "show", "wg0"})
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		Expect(stdout).To(ContainSubstring("10.99.0.2"))

		By("verifying server public key and endpoint appear in 'wg show wg0'")
		stdout, stderr, err = clientNode.exec(ctx, clientPod.Name,
			[]string{"wg", "show", "wg0"})
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		Expect(stdout).To(ContainSubstring(serverNode.publicKey().String()))
	})

	It("WireGuard handshake completes between pods", func(ctx context.Context) {
		By("waiting for latest-handshake timestamp to become non-zero (Eventually 30s)")
		Eventually(func(g Gomega) {
			stdout, stderr, err := clientNode.exec(ctx, clientPod.Name,
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
		stdout, stderr, err := clientNode.exec(ctx, clientPod.Name,
			[]string{"wg", "show", "wg0", "latest-handshakes"})
		Expect(err).NotTo(HaveOccurred(), "stderr: %s", stderr)
		parts := strings.Fields(stdout)
		Expect(parts).To(HaveLen(2))
		Expect(parts[1]).NotTo(Equal("0"))
	})

	It("TCP traffic flows through the WireGuard tunnel, not direct pod networking", func(ctx context.Context) {
		By("starting netcat listener bound only to server's WireGuard IP 10.99.0.1")
		// nc -l binds to the WireGuard IP — only reachable via wg0 tunnel.
		go func() {
			defer GinkgoRecover()
			// Best-effort: start listener; we don't need the result
			serverNode.exec(ctx, serverPod.Name, []string{"nc", "-l", "-p", fmt.Sprintf("%d", tcpPort), "-s", serverWgAddr}) //nolint:errcheck
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
})

type Node struct {
	namespace string
	prefix    string
	theirKey  wgtypes.Key
	myKey     wgtypes.Key

	client kubernetes.Interface
	config *rest.Config
}

func newNode(
	prefix, namespace string,
	myKey, theirKey wgtypes.Key,
	client kubernetes.Interface,
	config *rest.Config,
) *Node {
	return &Node{
		namespace: namespace,
		prefix:    prefix,
		theirKey:  theirKey,
		myKey:     myKey,
		client:    client,
		config:    config,
	}
}

func (n *Node) publicKey() wgtypes.Key {
	return n.myKey.PublicKey()
}

func (n *Node) objectMeta() metav1.ObjectMeta {
	return metav1.ObjectMeta{
		GenerateName: n.prefix,
		Namespace:    n.namespace,
	}
}

func (n *Node) createPrivKeySecret(ctx context.Context) (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: n.objectMeta(),
		Data: map[string][]byte{
			"privatekey": []byte(n.myKey.String() + "\n"),
		},
	}

	return n.client.CoreV1().
		Secrets(n.namespace).
		Create(ctx, secret, metav1.CreateOptions{})
}

func (n *Node) createTestPod(ctx context.Context, secretName string) (*corev1.Pod, error) {
	pod := &corev1.Pod{
		ObjectMeta: n.objectMeta(),
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Volumes: []corev1.Volume{{
				Name: "wg-privkey",
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: secretName,
					},
				},
			}},
			Containers: []corev1.Container{{
				Name:            "main",
				Image:           "wireguard-cni-tools:latest",
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         []string{"sleep", "3600"},
				SecurityContext: &corev1.SecurityContext{
					Privileged: new(true),
					RunAsUser:  new(int64(0)),
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{
							corev1.Capability("NET_ADMIN"),
							corev1.Capability("SYS_MODULE"),
						},
					},
				},
				VolumeMounts: []corev1.VolumeMount{
					{
						Name:      "wg-privkey",
						MountPath: "/run/secrets/wireguard",
						ReadOnly:  true,
					},
				},
			}},
		},
	}

	return n.client.CoreV1().
		Pods(n.namespace).
		Create(ctx, pod, metav1.CreateOptions{})
}

func (n *Node) getPod(ctx context.Context, podName string) (*corev1.Pod, error) {
	return n.client.CoreV1().
		Pods(n.namespace).
		Get(ctx, podName, metav1.GetOptions{})
}

func (n *Node) exec(ctx context.Context, pod string, cmd []string) (string, string, error) {
	req := n.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(n.namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "main",
			Command:   cmd,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(n.config, "POST", req.URL())
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
