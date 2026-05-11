package cmd

import (
	"context"

	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func newK8sClient() (kubernetes.Interface, error) {
	conf, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(conf)
}

func resolveSecretRef(ctx context.Context, ref *config.SecretKeyRef) (string, error) {
	client, err := newK8sClient()
	if err != nil {
		return "", err
	}
	return config.GetSecret(ctx, client, ref)
}
