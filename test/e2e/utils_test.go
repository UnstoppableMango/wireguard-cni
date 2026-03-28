package e2e_test

import (
	"encoding/json"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
