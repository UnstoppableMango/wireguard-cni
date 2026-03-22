//go:build linux

package main

import (
	"encoding/base64"
	"encoding/json"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newNetConf(privKey, peerPubKey, address string) []byte {
	conf := map[string]any{
		"cniVersion": "1.0.0",
		"name":       "wg-test",
		"type":       "wireguard-cni",
		"address":    address,
		"privateKey": privKey,
		"peers": []map[string]any{
			{
				"publicKey":  peerPubKey,
				"allowedIPs": []string{"10.0.0.0/8"},
			},
		},
	}
	b, _ := json.Marshal(conf)
	return b
}

func keyBase64(key wgtypes.Key) string {
	b := [32]byte(key)
	return base64.StdEncoding.EncodeToString(b[:])
}
