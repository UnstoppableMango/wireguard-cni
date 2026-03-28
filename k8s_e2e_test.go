//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

type cniPeer struct {
	PublicKey           string   `json:"publicKey"`
	AllowedIPs          []string `json:"allowedIPs"`
	Endpoint            string   `json:"endpoint,omitempty"`
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"`
}

func buildCNIConf(key wgtypes.Key, address string, listenPort int, peers []cniPeer) ([]byte, error) {
	conf := map[string]any{
		"cniVersion": "1.0.0",
		"name":       "wg-k8s-e2e",
		"type":       "wireguard-cni",
		"address":    address,
		"privateKey": key.String(),
		"peers":      peers,
	}
	if listenPort != 0 {
		conf["listenPort"] = listenPort
	}
	return json.Marshal(conf)
}

// withPrevResult embeds a CNI ADD result as prevResult for use in CHECK calls.
func withPrevResult(conf, prevResult []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(conf, &m); err != nil {
		return nil, err
	}
	m["prevResult"] = json.RawMessage(prevResult)
	return json.Marshal(m)
}

var _ = Describe("Kubernetes E2E", Ordered, Label("k8s-e2e"), func() {
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

		clientConf, err = buildCNIConf(clientNode.key, clientWgIP, 0, []cniPeer{
			{
				PublicKey:           serverNode.publicKey(),
				AllowedIPs:          []string{"10.99.0.1/32"},
				Endpoint:            fmt.Sprintf("%s:%d", serverPodIP, wgPort),
				PersistentKeepalive: 5,
			},
		})
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

type Node struct {
	namespace string
	prefix    string
	key       wgtypes.Key

	client kubernetes.Interface
	config *rest.Config
}

func newNode(
	prefix, namespace string,
	client kubernetes.Interface,
	config *rest.Config,
) (*Node, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	return &Node{
		namespace: namespace,
		prefix:    prefix,
		key:       key,
		client:    client,
		config:    config,
	}, nil
}

func (n *Node) publicKey() string {
	return n.key.PublicKey().String()
}

func (n *Node) objectMeta() metav1.ObjectMeta {
	return metav1.ObjectMeta{
		GenerateName: n.prefix,
		Namespace:    n.namespace,
	}
}

func (n *Node) createPod(ctx context.Context) (*corev1.Pod, error) {
	privileged := true
	runAsRoot := int64(0)
	hostPathDir := corev1.HostPathDirectory

	pod := &corev1.Pod{
		ObjectMeta: n.objectMeta(),
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Volumes: []corev1.Volume{{
				Name: "cni-bin",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/opt/cni/bin",
						Type: &hostPathDir,
					},
				},
			}},
			Containers: []corev1.Container{{
				Name:            "main",
				Image:           "wireguard-cni-tools:latest",
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         []string{"sleep", "3600"},
				SecurityContext: &corev1.SecurityContext{
					Privileged: &privileged,
					RunAsUser:  &runAsRoot,
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{
							corev1.Capability("NET_ADMIN"),
							corev1.Capability("SYS_MODULE"),
						},
					},
				},
				VolumeMounts: []corev1.VolumeMount{{
					Name:      "cni-bin",
					MountPath: "/opt/cni/bin",
					ReadOnly:  true,
				}},
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
	return n.execWithStdin(ctx, pod, cmd, nil)
}

func (n *Node) execWithStdin(ctx context.Context, pod string, cmd []string, stdin io.Reader) (string, string, error) {
	req := n.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(n.namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "main",
			Command:   cmd,
			Stdin:     stdin != nil,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(n.config, "POST", req.URL())
	if err != nil {
		return "", "", err
	}

	var stdout, stderr bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: &stdout,
		Stderr: &stderr,
	})
	return stdout.String(), stderr.String(), err
}

// invokeCNI runs the wireguard-cni binary inside the named pod with the CNI
// environment variables set and the given config JSON passed on stdin.
func (n *Node) invokeCNI(ctx context.Context, podName, command, containerID, netns, ifName string, config []byte) (string, string, error) {
	cmd := []string{
		"env",
		fmt.Sprintf("CNI_COMMAND=%s", command),
		fmt.Sprintf("CNI_CONTAINERID=%s", containerID),
		fmt.Sprintf("CNI_NETNS=%s", netns),
		fmt.Sprintf("CNI_IFNAME=%s", ifName),
		"CNI_PATH=/opt/cni/bin",
		"/opt/cni/bin/wireguard-cni",
	}
	return n.execWithStdin(ctx, podName, cmd, bytes.NewReader(config))
}
