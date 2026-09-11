package config

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func GetSecret(ctx context.Context, client kubernetes.Interface, ref *SecretKeyRef) (string, error) {
	if ref.Namespace == "" {
		return "", fmt.Errorf("namespace is required")
	}
	if ref.Name == "" {
		return "", fmt.Errorf("name is required")
	}
	if ref.Key == "" {
		return "", fmt.Errorf("key is required")
	}

	secret, err := client.CoreV1().Secrets(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}

	val, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", ref.Key, ref.Namespace, ref.Name)
	}

	return string(val), nil
}
