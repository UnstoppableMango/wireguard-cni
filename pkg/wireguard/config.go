package wireguard

import (
	"fmt"

	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func LoadConfig(stdin []byte) (*wgtypes.Config, error) {
	conf, err := config.Parse(stdin)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return config.WireguardConfig(conf)
}
