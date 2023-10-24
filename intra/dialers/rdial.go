// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

type connectFunc func(*protect.RDial, string, netip.Addr, int) (net.Conn, error)

func filter(ips []netip.Addr, exclude netip.Addr) []netip.Addr {
	filtered := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Compare(exclude) == 0 || !ip.IsValid() {
			continue
		}
		filtered = append(filtered, ip)
	}
	return filtered
}

func ipConnect(d *protect.RDial, proto string, ip netip.Addr, port int) (net.Conn, error) {
	switch proto {
	case "tcp", "tcp4", "tcp6":
		return d.DialTCP(proto, nil, tcpaddr(ip, port))
	case "udp", "udp4", "udp6":
		return d.DialUDP(proto, nil, udpaddr(ip, port))
	default:
		return d.Dial(proto, addr(ip, port))
	}
}

func splitIpConnect(d *protect.RDial, proto string, ip netip.Addr, port int) (net.Conn, error) {
	switch proto {
	case "tcp", "tcp4", "tcp6":
		return DialWithSplitRetry(d, tcpaddr(ip, port))
	case "udp", "udp4", "udp6":
		return d.DialUDP(proto, nil, udpaddr(ip, port))
	default:
		return d.Dial(proto, addr(ip, port))
	}
}

func commondial(d *protect.RDial, network, addr string, connect connectFunc) (net.Conn, error) {
	start := time.Now()

	log.D("rdial: commondial: dialing %s", addr)
	domain, portstr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// cannot dial into a wildcard address
	// while, listen is unsupported
	if len(domain) == 0 {
		return nil, net.InvalidAddrError(addr)
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
		if conn, err = connect(d, network, confirmed, port); err == nil {
			log.V("rdial: commondial: found working ip %s for %s", confirmed, addr)
			return conn, nil
		}
		ips.Disconfirm(confirmed)
		log.D("rdial: commondial: confirmed ip %s for %s failed with err %v", confirmed, addr, err)
	}

	allips := filter(ips.GetAll(), confirmed)
	if len(allips) <= 0 {
		log.D("rdial: commondial: renew ips for %s", addr)
		Renew(domain, ips.Seed())
		allips = filter(ips.GetAll(), confirmed)
	}
	log.D("rdial: commondial: trying all ips %d for %s", len(allips), addr)
	for _, ip := range allips {
		if conn, err = connect(d, network, ip, port); err == nil {
			ips.Confirm(ip)
			log.I("redial: commondial: found working ip %s for %s", ip, addr)
			return conn, nil
		}
		log.W("rdial: commondial: ip %s for %s failed with err %v", ip, addr, err)
	}

	dur := time.Since(start).Seconds()
	log.D("rdial: commondial: duration: %ds; failed %s", dur*1000, addr)
	// xxx: return nil, errNoIps
	return d.Dial(network, addr)
}

func SplitDial(d *protect.RDial, network, addr string) (net.Conn, error) {
	return commondial(d, network, addr, splitIpConnect)
}

func Dial(d *protect.RDial, network, addr string) (net.Conn, error) {
	return commondial(d, network, addr, ipConnect)
}