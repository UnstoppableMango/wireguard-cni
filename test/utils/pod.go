package utils

import (
	"context"
	"io"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Pod struct {
	client    *Client
	namespace string
	prefix    string
	key       wgtypes.Key
}

func NewPod(client *Client, prefix, namespace string) (*Pod, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	return &Pod{
		namespace: namespace,
		prefix:    prefix,
		key:       key,
		client:    client,
	}, nil
}

func (n *Pod) PublicKey() string {
	return n.key.PublicKey().String()
}

func (n *Pod) Create(ctx context.Context) (*corev1.Pod, error) {
	pod := n.resource(n.objectMeta())

	return n.client.CoreV1().
		Pods(n.namespace).
		Create(ctx, pod, metav1.CreateOptions{})
}

func (n *Pod) Get(ctx context.Context, name string) (*corev1.Pod, error) {
	return n.client.CoreV1().
		Pods(n.namespace).
		Get(ctx, name, metav1.GetOptions{})
}

func (n *Pod) Exec(ctx context.Context, pod string, cmd []string) (string, string, error) {
	return n.execWithStdin(ctx, pod, cmd, nil)
}

func (n *Pod) execWithStdin(ctx context.Context, pod string, cmd []string, stdin io.Reader) (string, string, error) {
	return n.client.Exec(ctx, pod, n.namespace, cmd, stdin)
}

func (n *Pod) objectMeta() metav1.ObjectMeta {
	return metav1.ObjectMeta{
		GenerateName: n.prefix,
		Namespace:    n.namespace,
	}
}

func (n *Pod) resource(meta metav1.ObjectMeta) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: meta,
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
