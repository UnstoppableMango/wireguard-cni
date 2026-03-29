package utils

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Pod struct {
	client    *Client
	namespace string
	name      string
	addr      string
	key       wgtypes.Key
}

func NewPod(client *Client, namespace, name, addr string) (*Pod, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	return &Pod{
		name:      name,
		namespace: namespace,
		addr:      addr,
		key:       key,
		client:    client,
	}, nil
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

func (p *Pod) CniConfig(version string, listenPort int, peers []CNIPeer) ([]byte, error) {
	return cniConf(p.key, p.addr+"/24", version, listenPort, peers)
}

func (p *Pod) ClientPeer() CNIPeer {
	return CNIPeer{
		PublicKey:  p.PublicKey(),
		AllowedIPs: []string{p.addr + "/32"},
	}
}

func (p *Pod) ServerPeer(podIp string, port int) CNIPeer {
	return CNIPeer{
		PublicKey:           p.PublicKey(),
		AllowedIPs:          []string{p.addr + "/32"},
		Endpoint:            fmt.Sprintf("%s:%d", podIp, port),
		PersistentKeepalive: 5,
	}
}
