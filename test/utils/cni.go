package utils

import (
	"encoding/json"
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	cniIfName      = "wg0"
	cniContainerID = "k8s-e2e-test"
	// /proc/1/ns/net is the network namespace of the container's init process,
	// i.e. the pod's own netns — accessible from within the container.
	cniNetns = "/proc/1/ns/net"
)

func InvokeCNI(command string) []string {
	return invokeCNI(command, cniContainerID, cniNetns, cniIfName)
}

func invokeCNI(command, containerID, netns, ifName string) []string {
	return []string{
		"env",
		fmt.Sprintf("CNI_COMMAND=%s", command),
		fmt.Sprintf("CNI_CONTAINERID=%s", containerID),
		fmt.Sprintf("CNI_NETNS=%s", netns),
		fmt.Sprintf("CNI_IFNAME=%s", ifName),
		"CNI_PATH=/opt/cni/bin",
		// CNI skel rejects calls where the plugin's netns matches CNI_NETNS.
		// Since this binary runs inside the target pod they are always the same.
		"CNI_NETNS_OVERRIDE=1",
		"/opt/cni/bin/wireguard-cni",
	}
}

type CNIPeer struct {
	PublicKey           string   `json:"publicKey"`
	AllowedIPs          []string `json:"allowedIPs"`
	Endpoint            string   `json:"endpoint,omitempty"`
	PersistentKeepalive int      `json:"persistentKeepalive,omitempty"`
}

func cniConf(key wgtypes.Key, address, version string, listenPort int, peers []CNIPeer) ([]byte, error) {
	conf := map[string]any{
		"cniVersion": version,
		"name":       "wg-k8s-e2e",
		"type":       "wireguard-cni",
		"runtimeConfig": map[string]any{
			"ips": []string{address},
		},
		"privateKey": key.String(),
		"peers":      peers,
	}
	if listenPort != 0 {
		conf["listenPort"] = listenPort
	}
	return json.Marshal(conf)
}
