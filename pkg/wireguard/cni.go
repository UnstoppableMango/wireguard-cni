package wireguard

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/iface"
	"go.uber.org/zap"
)

type CNI struct {
	log  *zap.Logger
	conf *config.Config
	prev *current.Result
}

func New(conf *config.Config, prev *current.Result) *CNI {
	return &CNI{
		log:  zap.L(),
		conf: conf,
		prev: prev,
	}
}

func FromConfig(conf *config.Config) (*CNI, error) {
	if conf.PrevResult == nil {
		return nil, fmt.Errorf("must be called as a chained plugin")
	}
	prev, err := current.GetResult(conf.PrevResult)
	if err != nil {
		return nil, fmt.Errorf("get result: %w", err)
	}
	return New(conf, prev), nil
}

func FromBytes(bytes []byte) (*CNI, error) {
	conf, err := config.Parse(bytes)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return FromConfig(conf)
}

func (cni *CNI) Add(netNs, ifName string) error {
	log := cni.log.With(zap.String("if", ifName))
	if len(cni.prev.IPs) == 0 {
		return fmt.Errorf("got no container IPs")
	}

	result, err := current.NewResultFromResult(cni.prev)
	if err != nil {
		return fmt.Errorf("new result: %w", err)
	}

	i, err := cni.create(netNs, ifName, log)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	result.Interfaces = append(result.Interfaces, &current.Interface{
		Name:    ifName,
		Sandbox: netNs,
		Mac:     i.Mac().String(),
	})

	for _, ip := range result.IPs {
		log.Info("assigning address", zap.Stringer("addr", &ip.Address))
		if err := i.AssignAddr(ip.Address); err != nil {
			return fmt.Errorf("assign addr: %w", err)
		}
		ip.Interface = new(i.Index())
	}

	log.Info("bringing link up")
	if err := i.SetUp(); err != nil {
		return fmt.Errorf("set up: %w", err)
	}

	for _, peer := range cni.conf.Peers {
		log := log.With(zap.String("peer", peer.Endpoint))
		for _, ip := range peer.AllowedIPs {
			log.Debug("adding route", zap.String("ip", ip))
			r, err := i.AddRoute(ip)
			if err != nil {
				return fmt.Errorf("add route: %w", err)
			}
			result.Routes = append(result.Routes, &types.Route{
				Dst:   r.Dst(),
				Scope: new(r.Scope()),
			})
		}
	}
	return types.PrintResult(result, cni.conf.CNIVersion)
}

func (cni *CNI) create(netNs, ifName string, log *zap.Logger) (iface.Link, error) {
	log.Info("creating interface")
	i, err := iface.Create(ifName)
	if err != nil {
		return nil, fmt.Errorf("create interface: %w", err)
	}

	log.Debug("configuring interface")
	if err := cni.Configure(ifName); err != nil {
		return nil, fmt.Errorf("configure interface: %w", err)
	}

	log.Debug("moving interface into container namespace")
	return i.MoveTo(netNs)
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
