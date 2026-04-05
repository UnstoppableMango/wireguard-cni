package wireguard

import (
	"fmt"

	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/unstoppablemango/wireguard-cni/pkg/config"
)

func IPAMAdd(c *config.Config, bytes []byte) (*current.Result, error) {
	if c.IPAM.Type == "" {
		// TODO
		return &current.Result{}, nil
	}
	result, err := ipam.ExecAdd(c.IPAM.Type, bytes)
	if err != nil {
		return nil, fmt.Errorf("ipam exec add: %w", err)
	}
	return current.NewResultFromResult(result)
}

func IPAMDel(c *config.Config, bytes []byte) error {
	if c.IPAM.Type == "" {
		return nil
	}
	if err := ipam.ExecDel(c.IPAM.Type, bytes); err != nil {
		return fmt.Errorf("ipam exec del: %w", err)
	}
	return nil
}

func IPAMCheck(c *config.Config, bytes []byte) error {
	if c.IPAM.Type == "" {
		return nil
	}
	if err := ipam.ExecCheck(c.IPAM.Type, bytes); err != nil {
		return fmt.Errorf("ipam exec check: %w", err)
	}
	return nil
}
