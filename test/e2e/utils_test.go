package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

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
		// CNI skel rejects calls where the plugin's netns matches CNI_NETNS.
		// Since this binary runs inside the target pod they are always the same.
		"CNI_NETNS_OVERRIDE=1",
		"/opt/cni/bin/wireguard-cni",
	}
	return n.execWithStdin(ctx, podName, cmd, bytes.NewReader(config))
}
