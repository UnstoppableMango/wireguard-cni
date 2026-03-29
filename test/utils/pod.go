package utils

import (
	"bytes"
	"context"
	"io"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Pod struct {
	client    *Client
	namespace string
	name      string
	key       wgtypes.Key
}

func NewPod(client *Client, namespace, name string) (*Pod, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	return &Pod{
		name:      name,
		namespace: namespace,
		key:       key,
		client:    client,
	}, nil
}

func CreatePod(ctx context.Context, client *Client, prefix, namespace string) (*Pod, error) {
	res := resource(prefix, namespace)
	pod, err := client.CoreV1().
		Pods(namespace).
		Create(ctx, res, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return NewPod(client, namespace, pod.Name)
}

func (n *Pod) PublicKey() string {
	return n.key.PublicKey().String()
}

func (n *Pod) Get(ctx context.Context) (*corev1.Pod, error) {
	return n.client.CoreV1().
		Pods(n.namespace).
		Get(ctx, n.name, metav1.GetOptions{})
}

func (n *Pod) Exec(ctx context.Context, cmd []string, stdin io.Reader) (string, string, error) {
	return n.client.Exec(ctx, n.name, n.namespace, cmd, stdin)
}

func (p *Pod) InvokeCNI(ctx context.Context, command string, conf []byte) (string, string, error) {
	return p.Exec(ctx, InvokeCNI(command), bytes.NewReader(conf))
}

func (p *Pod) CniConfig(address string, listenPort int, peers []CNIPeer) ([]byte, error) {
	return cniConf(p.key, address, listenPort, peers)
}

func resource(prefix, namespace string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: prefix,
			Namespace:    namespace,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Volumes: []corev1.Volume{{
				Name: "cni-bin",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/opt/cni/bin",
						Type: new(corev1.HostPathDirectory),
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
				VolumeMounts: []corev1.VolumeMount{{
					Name:      "cni-bin",
					MountPath: "/opt/cni/bin",
					ReadOnly:  true,
				}},
			}},
		},
	}
}
