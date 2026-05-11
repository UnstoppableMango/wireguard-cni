package config_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("ResolvePrivateKey", func() {
	var (
		ctx     context.Context
		client  *fake.Clientset
		privKey wgtypes.Key
	)

	BeforeEach(func() {
		ctx = context.Background()
		client = fake.NewClientset()
		var err error
		privKey, err = wgtypes.GeneratePrivateKey()
		Expect(err).NotTo(HaveOccurred())
	})

	It("resolves the private key from a secret", func() {
		_, err := client.CoreV1().Secrets("test-ns").Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "wg-secret",
				Namespace: "test-ns",
			},
			Data: map[string][]byte{
				"privateKey": []byte(privKey.String()),
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		val, err := config.GetSecret(ctx, client, &config.SecretKeyRef{
			Namespace: "test-ns",
			SecretKeySelector: corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "wg-secret"},
				Key:                  "privateKey",
			},
		})

		Expect(err).NotTo(HaveOccurred())
		Expect(val).To(Equal(privKey.String()))
	})

	It("returns error when namespace is missing", func() {
		_, err := config.GetSecret(ctx, client, &config.SecretKeyRef{
			SecretKeySelector: corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "wg-secret"},
				Key:                  "privateKey",
			},
		})

		Expect(err).To(MatchError(ContainSubstring("namespace is required")))
	})

	It("returns error when name is missing", func() {
		_, err := config.GetSecret(ctx, client, &config.SecretKeyRef{
			Namespace: "test-ns",
			SecretKeySelector: corev1.SecretKeySelector{
				Key: "privateKey",
			},
		})

		Expect(err).To(MatchError(ContainSubstring("name is required")))
	})

	It("returns error when key is missing", func() {
		_, err := config.GetSecret(ctx, client, &config.SecretKeyRef{
			Namespace: "test-ns",
			SecretKeySelector: corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "wg-secret"},
			},
		})

		Expect(err).To(MatchError(ContainSubstring("key is required")))
	})

	It("returns error when secret does not exist", func() {
		_, err := config.GetSecret(ctx, client, &config.SecretKeyRef{
			Namespace: "test-ns",
			SecretKeySelector: corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "nonexistent"},
				Key:                  "privateKey",
			},
		})

		Expect(err).To(MatchError(ContainSubstring("get secret")))
	})

	It("returns error when key is not found in secret", func() {
		_, err := client.CoreV1().Secrets("test-ns").Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "wg-secret",
				Namespace: "test-ns",
			},
			Data: map[string][]byte{
				"otherKey": []byte("somevalue"),
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, err = config.GetSecret(ctx, client, &config.SecretKeyRef{
			Namespace: "test-ns",
			SecretKeySelector: corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "wg-secret"},
				Key:                  "privateKey",
			},
		})

		Expect(err).To(MatchError(ContainSubstring("key \"privateKey\" not found in secret")))
	})
})
