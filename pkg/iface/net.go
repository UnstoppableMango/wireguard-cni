package iface

import "net"

type Link interface {
	AddRoute(route string) (Route, error)
	AssignAddr(addr net.IPNet) error
	Index() int
	Mac() net.HardwareAddr
	MoveTo(netNs string) (Link, error)
	Routes() ([]Route, error)
	SetUp() error
}

type NS interface {
	Create(ifName string) (Link, error)
}

type Route interface {
	Dst() net.IPNet
	Scope() int
}

type Client interface {
	Create(ifName string) (Link, error)
	NsByPath(path string) (NS, error)
}
