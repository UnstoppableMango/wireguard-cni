package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/unstoppablemango/wireguard-cni/test/utils"
)

// withPrevResult embeds a CNI ADD result as prevResult for use in CHECK calls.
func withPrevResult(conf, prevResult []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(conf, &m); err != nil {
		return nil, err
	}
	m["prevResult"] = json.RawMessage(prevResult)
	return json.Marshal(m)
}

// invokeCNI runs the wireguard-cni binary inside the named pod with the CNI
// environment variables set and the given config JSON passed on stdin.
func invokeCNI(ctx context.Context, p *utils.Pod, command, containerID, netns, ifName string, config []byte) (string, string, error) {
	cmd := []string{
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

	return p.Exec(ctx, cmd, bytes.NewReader(config))
}
