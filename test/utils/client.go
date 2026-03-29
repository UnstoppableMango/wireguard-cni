package utils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

type Client struct {
	kubernetes.Interface
	config *rest.Config
}

func NewClient() (*Client, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		return nil, fmt.Errorf("KUBECONFIG environment variable is not set or is empty")
	}
	if _, err := os.Stat(kubeconfig); err != nil {
		return nil, fmt.Errorf("kubeconfig not found at %s: %w", kubeconfig, err)
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build config from kubeconfig: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	return &Client{
		Interface: client,
		config:    config,
	}, nil
}

func (c *Client) Exec(ctx context.Context, pod, namespace string, cmd []string, stdin io.Reader) (string, string, error) {
	req := c.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "main",
			Command:   cmd,
			Stdin:     stdin != nil,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
	if err != nil {
		return "", "", err
	}

	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()

	var wg sync.WaitGroup
	var stdoutBuf, stderrBuf bytes.Buffer
	wg.Go(func() { io.Copy(&stdoutBuf, stdoutR) }) //nolint:errcheck
	wg.Go(func() { io.Copy(&stderrBuf, stderrR) }) //nolint:errcheck

	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  stdin,
		Stdout: stdoutW,
		Stderr: stderrW,
	})
	stdoutW.CloseWithError(err)
	stderrW.CloseWithError(err)
	wg.Wait()

	return stdoutBuf.String(), stderrBuf.String(), err
}

func (c *Client) CreatePod(ctx context.Context, prefix, namespace, addr string) (*Pod, error) {
	pod, err := c.CoreV1().Pods(namespace).Create(ctx,
		resource(prefix, namespace),
		metav1.CreateOptions{},
	)
	if err != nil {
		return nil, err
	}

	return NewPod(c, namespace, pod.Name, addr)
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
