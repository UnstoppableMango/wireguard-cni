package wireguard

import (
	"fmt"

	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/unstoppablemango/wireguard-cni/pkg/config"
	"github.com/unstoppablemango/wireguard-cni/pkg/iface"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl"
)

type Option func(*CNI)

type CNI struct {
	log  *zap.Logger
	net  iface.Client
	conf *config.Config
	prev *current.Result
}

func New(conf *config.Config, prev *current.Result, options ...Option) *CNI {
	cni := &CNI{
		log:  zap.L(),
		net:  iface.NewClient(),
		conf: conf,
		prev: prev,
	}
	for _, option := range options {
		option(cni)
	}
	return cni
}

func WithLogger(log *zap.Logger) Option {
	return func(cni *CNI) {
		cni.log = log
	}
}

func WithClient(net iface.Client) Option {
	return func(cni *CNI) {
		cni.net = net
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
	log := cni.log.With(zap.String("if", ifName), zap.String("netns", netNs))
	if len(cni.prev.IPs) == 0 {
		return fmt.Errorf("got no container IPs")
	}

	result, err := current.NewResultFromResult(cni.prev)
	if err != nil {
		return fmt.Errorf("new result: %w", err)
	}

	log.Info("creating interface")
	link, err := Create(cni.net, netNs, ifName, cni.conf)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	result.Interfaces = append(result.Interfaces, &current.Interface{
		Name:    ifName,
		Sandbox: netNs,
		Mac:     link.Mac().String(),
	})

	log.Info("applying configuration")
	if err := Apply(link, cni.conf, result); err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	return types.PrintResult(result, cni.conf.CNIVersion)
}

func (cni *CNI) Check(ifName string, prev *current.Result) error {
	panic("not implemented")
}

func (cni *CNI) Delete(ifName string, stdin []byte) error {
	panic("not implemented")
}

func AddRoute(link iface.Link, dst string) (*types.Route, error) {
	route, err := link.AddRoute(dst)
	if err != nil {
		return nil, fmt.Errorf("add route: %w", err)
	}
	return &types.Route{
		Dst:   route.Dst(),
		Scope: new(route.Scope()),
	}, nil
}

func Apply(link iface.Link, conf *config.Config, result *current.Result) error {
	for _, ip := range result.IPs {
		if err := AssignAddr(link, ip); err != nil {
			return fmt.Errorf("assign addr: %w", err)
		}
	}

	if err := link.SetUp(); err != nil {
		return fmt.Errorf("set up: %w", err)
	}

	for _, peer := range conf.Peers {
		for _, ip := range peer.AllowedIPs {
			route, err := AddRoute(link, ip)
			if err != nil {
				return fmt.Errorf("add route: %w", err)
			}
			result.Routes = append(result.Routes, route)
		}
	}
	return nil
}

func AssignAddr(link iface.Link, ip *current.IPConfig) error {
	if err := link.AssignAddr(ip.Address); err != nil {
		return fmt.Errorf("assign addr: %w", err)
	}
	ip.Interface = new(link.Index())
	return nil
}

func Create(c iface.Client, netNs, ifName string, conf *config.Config) (iface.Link, error) {
	log := zap.L().With(zap.String("if", ifName))

	log.Info("creating interface")
	link, err := c.Create(ifName)
	if err != nil {
		return nil, fmt.Errorf("create interface: %w", err)
	}

	wg, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("new wgctrl: %w", err)
	}
	defer wg.Close()

	log.Debug("configuring interface")
	if err := Configure(wg, ifName, conf); err != nil {
		return nil, fmt.Errorf("configure: %w", err)
	}

	log.Debug("moving interface into container namespace")
	return link.MoveTo(netNs)
}

func Configure(c *wgctrl.Client, ifName string, conf *config.Config) error {
	cfg, err := ConfigFor(conf)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	return c.ConfigureDevice(ifName, *cfg)
}
