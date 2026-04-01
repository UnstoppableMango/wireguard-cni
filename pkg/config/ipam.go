package config

import (
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ipam"
)

func (c *Config) IPAMAdd(bytes []byte) (*current.Result, error) {
	result, err := ipam.ExecAdd(c.IPAM.Type, bytes)
	if err != nil {
		return nil, err
	}
	return current.NewResultFromResult(result)
}

func (c *Config) IPAMDel(bytes []byte) error {
	return ipam.ExecDel(c.IPAM.Type, bytes)
}
