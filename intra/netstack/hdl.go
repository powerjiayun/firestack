// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"net"
	"net/netip"
	"strings"

	"github.com/celzero/firestack/intra/settings"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type gconns interface {
	*GUDPConn | *GTCPConn | *GICMPConn
}

type GBaseConnHandler interface {
	// OpenConns returns the number of active connections.
	OpenConns() string
	// CloseConns closes conns by ids, or all if ids is empty.
	CloseConns([]string) []string
	// end closes the handler and all its connections.
	End()
}

type GSpecConnHandler[T gconns] interface {
	GBaseConnHandler
	// Proxy copies data between conn and dst (egress).
	// must not block forever as it may block netstack
	// see: netstack/dispatcher.go:newReadvDispatcher
	Proxy(in T, src, dst netip.AddrPort) bool
	// ReverseProxy copies data between conn and dst (ingress).
	ReverseProxy(out T, in net.Conn, src, dst netip.AddrPort) bool
	// Error notes the error in connecting src to dst; retrying if necessary.
	Error(in T, src, dst netip.AddrPort, err error)
}

type GMuxConnHandler[T gconns] interface {
	// ProxyMux proxies data between conn and multiple destinations
	// (endpoint-independent mapping).
	ProxyMux(in T, src, dst netip.AddrPort, dmx DemuxerFn) bool
}

type GEchoConnHandler interface {
	// Ping informs if ICMP Echo from src to dst is replied to
	Ping(msg []byte, src, dst netip.AddrPort) bool
}

type GConnHandler interface {
	TCP() GTCPConnHandler         // TCP returns the TCP handler.
	UDP() GUDPConnHandler         // UDP returns the UDP handler.
	ICMP() GICMPHandler           // ICMP returns the ICMP handler.
	CloseConns(csv string) string // CloseConns closes the connections with the given IDs, or all if empty.
}

type gconnhandler struct {
	tcp  GTCPConnHandler
	udp  GUDPConnHandler
	icmp GICMPHandler
}

var _ GConnHandler = (*gconnhandler)(nil)

func NewGConnHandler(tcp GTCPConnHandler, udp GUDPConnHandler, icmp GICMPHandler) GConnHandler {
	return &gconnhandler{
		tcp:  tcp,
		udp:  udp,
		icmp: icmp,
	}
}

func (g *gconnhandler) TCP() GTCPConnHandler {
	return g.tcp
}

func (g *gconnhandler) UDP() GUDPConnHandler {
	return g.udp
}

func (g *gconnhandler) ICMP() GICMPHandler {
	return g.icmp
}

func (g *gconnhandler) CloseConns(csv string) string {
	var cids []string = nil // nil closes all conns
	if len(csv) > 0 {
		// split returns [""] (slice of length 1) if csv is empty
		// and so, avoid splitting on empty csv, and let cids be nil
		cids = strings.Split(csv, ",")
	}

	var t []string
	var u []string
	var i []string
	if tcp := g.tcp; tcp != nil {
		t = tcp.CloseConns(cids)
	}
	if udp := g.udp; udp != nil {
		u = udp.CloseConns(cids)
	}
	if icmp := g.icmp; icmp != nil {
		i = icmp.CloseConns(cids)
	}
	s := make([]string, 0, len(t)+len(u)+len(i))
	s = append(s, t...)
	s = append(s, u...)
	s = append(s, i...)
	return strings.Join(s, ",")
}

// src/dst addrs are flipped
// fdbased.Attach -> ... -> nic.DeliverNetworkPacket -> ... -> nic.DeliverTransportPacket:
// github.com/google/gvisor/blob/be6ffa7/pkg/tcpip/stack/nic.go#L831-L837

func localAddrPort(id stack.TransportEndpointID) netip.AddrPort {
	// todo: unmap?
	return localUDPAddr(id).AddrPort()
}

func remoteAddrPort(id stack.TransportEndpointID) netip.AddrPort {
	// todo: unmap?
	return remoteUDPAddr(id).AddrPort()
}

func remoteUDPAddr(id stack.TransportEndpointID) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   nsaddr2ip(id.RemoteAddress),
		Port: int(id.RemotePort),
	}
}

func localUDPAddr(id stack.TransportEndpointID) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   nsaddr2ip(id.LocalAddress),
		Port: int(id.LocalPort),
	}
}

func nsaddr2ip(addr tcpip.Address) net.IP {
	b := addr.AsSlice()
	return net.IP(b)
}

func addrport2nsaddr(ipp netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var proto tcpip.NetworkProtocolNumber
	var addr tcpip.Address
	if ipp.Addr().Is4() {
		proto = ipv4.ProtocolNumber
		addr = tcpip.AddrFrom4(ipp.Addr().As4())
	} else {
		proto = ipv6.ProtocolNumber
		addr = tcpip.AddrFrom16(ipp.Addr().As16())
	}
	return tcpip.FullAddress{
		NIC:  settings.NICID,
		Addr: addr,
		Port: ipp.Port(),
	}, proto
}
