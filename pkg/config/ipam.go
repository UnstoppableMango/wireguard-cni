package config

import (
	"fmt"

	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ipam"
)

func (c *Config) IPAMAdd(bytes []byte) (*current.Result, error) {
	if c.IPAM.Type == "" {
		return &current.Result{}, nil
	}
	result, err := ipam.ExecAdd(c.IPAM.Type, bytes)
	if err != nil {
		return nil, fmt.Errorf("ipam exec add: %w", err)
	}
	return current.NewResultFromResult(result)
}

func (c *Config) IPAMDel(bytes []byte) error {
	if c.IPAM.Type == "" {
		return nil
	}
	if err := ipam.ExecDel(c.IPAM.Type, bytes); err != nil {
		return fmt.Errorf("ipam exec del: %w", err)
	}
	return nil
}
