package wireguard

import (
	"fmt"

	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"go.uber.org/zap"
)

type CNI struct {
	log  *zap.Logger
	conf *config.Config
}

func New(conf *config.Config) *CNI {
	return &CNI{
		log:  zap.L(),
		conf: conf,
	}
}

func FromBytes(bytes []byte) (*CNI, error) {
	conf, err := config.Parse(bytes)
	if err != nil {
		return nil, err
	}
	if conf.PrevResult == nil {
		return nil, fmt.Errorf("must be called as a chained plugin")
	}
	return New(conf), nil
}

func (cni *CNI) Add(ifName string, stdin []byte) error {
	ipam, err := IPAMAdd(cni.conf, stdin)
	if err != nil {
		return fmt.Errorf("ipam add: %w", err)
	}
	if err = cni.ConfigureAll(ipam.IPs, ipam.Interfaces); err != nil {
		_ = IPAMDel(cni.conf, stdin)
		return fmt.Errorf("configure all: %w", err)
	}
	return nil
}

func (cni *CNI) Check(ifName string, prev *current.Result) error {
	if err := IPAMCheck(cni.conf, nil); err != nil {
		return fmt.Errorf("ipam check: %w", err)
	}
	return nil
}

func (cni *CNI) Delete(ifName string, stdin []byte) error {
	if err := IPAMDel(cni.conf, stdin); err != nil {
		return fmt.Errorf("ipam del: %w", err)
	}
	return nil
}
