//go:build linux

package network

import (
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (l *netlinkLink) logger() *zap.Logger {
	return zap.L().With(
		zap.String("interface", l.Name()),
	)
}

func (l *netlinkLink) ConfigureWireGuard(conf wgtypes.Config) error {
	log := l.logger()

	log.Debug("creating wgctrl client")
	client, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer client.Close()

	log.Debug("configuring device")
	return client.ConfigureDevice(l.Name(), conf)
}

func (l *netlinkLink) PublicKey() (wgtypes.Key, error) {
	log := l.logger()

	log.Debug("creating wgctrl client")
	client, err := wgctrl.New()
	if err != nil {
		return wgtypes.Key{}, err
	}
	defer client.Close()

	log.Debug("retrieving device")
	dev, err := client.Device(l.Name())
	if err != nil {
		return wgtypes.Key{}, err
	}
	return dev.PublicKey, nil
}
