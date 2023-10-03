// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package split

import (
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/protect/ipmap"
)

type establishConnFunc func(*protect.RDial, string, netip.Addr, int) (net.Conn, error)

var ipm ipmap.IPMap = ipmap.NewIPMap()

func addr(ip netip.Addr, port int) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(port))
}
func tcpaddr(ip netip.Addr, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: ip.AsSlice(), Port: port}
}

func udpaddr(ip netip.Addr, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: ip.AsSlice(), Port: port}
}

func Renew(hostname string, addrs []string) bool {
	ips := ipm.Of(hostname, addrs)
	return ips != nil && !ips.Empty()
}

func For(hostname string) []netip.Addr {
	ipset := ipm.Get(hostname)
	if ipset != nil {
		return ipset.GetAll()
	}
	return nil
}

func Confirm(hostname string, addr net.Addr) bool {
	ips := ipm.GetAny(hostname)
	if ips != nil {
		if ip, err := netip.ParseAddr(addr.String()); err == nil {
			ips.Confirm(ip)
			return true
		} // not ok
	} // not ok
	return false
}

func Disconfirm(hostname string, ip net.Addr) bool {
	ips := ipm.GetAny(hostname)
	if ips != nil {
		if ip, err := netip.ParseAddr(ip.String()); err == nil {
			ips.Disconfirm(ip)
			return true
		} // not ok
	} // not ok
	return false
}

func dial(d *protect.RDial, proto string, ip netip.Addr, port int) (net.Conn, error) {
	switch proto {
	case "tcp", "tcp4", "tcp6":
		return d.DialTCP(proto, nil, tcpaddr(ip, port))
	case "udp", "udp4", "udp6":
		return d.DialUDP(proto, nil, udpaddr(ip, port))
	default:
		return d.Dial(proto, addr(ip, port))
	}
}

func splitdial(d *protect.RDial, proto string, ip netip.Addr, port int) (net.Conn, error) {
	switch proto {
	case "tcp", "tcp4", "tcp6":
		if conn, err := DialWithSplitRetry(d, tcpaddr(ip, port)); err == nil {
			log.D("redial: tcp: confirmed IP %s worked for %s", ip)
			return conn, nil
		}
	case "udp", "udp4", "udp6":
		if conn, err := d.DialUDP(proto, nil, udpaddr(ip, port)); err == nil {
			log.D("redial: udp: confirmed IP %s worked for %s", ip)
			return conn, nil
		}
	default:
		log.I("redial: unknown network %s", proto)
		return d.Dial(proto, addr(ip, port))
	}
	return nil, net.UnknownNetworkError(proto)
}

func Dial(d *protect.RDial, network, addr string) (net.Conn, error) {
	return commondial(d, network, addr, dial)
}

func commondial(d *protect.RDial, network, addr string, connect establishConnFunc) (net.Conn, error) {
	start := time.Now()

	log.D("commondial: dialing %s", addr)
	domain, portstr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		return nil, err
	}
	// TODO: Improve IP fallback strategy with parallelism and Happy Eyeballs.
	var conn net.Conn
	ips := ipm.Get(domain)
	confirmed := ips.Confirmed()
	if confirmed.IsValid() {
		if conn, err := connect(d, network, confirmed, port); err == nil {
			return conn, nil
		}
		ips.Disconfirm(confirmed)
		log.D("commondial: confirmed IP %s for %s failed with err %v", confirmed, addr, err)
	}

	allips := ips.GetAll()
	log.D("redial: trying all IPs %d for %s", len(allips), addr)
	for _, ip := range allips {
		// confirmed already tried above
		if ip.Compare(confirmed) == 0 || !ip.IsValid() {
			continue
		}
		if conn, err = connect(d, network, ip, port); err == nil {
			ips.Confirm(ip)
			log.I("commondial: found working IP %s for %s", ip, addr)
			return conn, nil
		}
	}

	dur := time.Since(start).Seconds()
	log.W("commondial: duration: %ss; renew %s", dur, addr)

	go Renew(domain, ips.Seed())

	return d.Dial(network, addr)
}

func ReDial(d *protect.RDial, network, addr string) (net.Conn, error) {
	return commondial(d, network, addr, splitdial)
}
