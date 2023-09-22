// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package split

import (
	"net"
	"strconv"

	"github.com/celzero/firestack/intra/core/ipmap"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

var osdialer = &net.Dialer{}
var ipm ipmap.IPMap = ipmap.NewIPMap(osdialer.Resolver)

func tcpaddr(ip net.IP, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: ip, Port: port}
}

func Renew(hostname string, addrs []string) bool {
	ips := ipm.Of(hostname, addrs)
	return ips != nil && !ips.Empty()
}

func Confirm(hostname string, ip net.IP) bool {
	ips := ipm.Get(hostname)
	if ips != nil {
		ips.Confirm(ip)
		return true
	}
	return false
}

func Disconfirm(hostname string, ip net.IP) bool {
	ips := ipm.Get(hostname)
	if ips != nil {
		ips.Disconfirm(ip)
		return true
	}
	return false
}

func ReDial(dialer *protect.RDial, network, addr string) (net.Conn, error) {
	log.D("redial: dialing %s", addr)
	domain, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	// TODO: Improve IP fallback strategy with parallelism and Happy Eyeballs.
	var conn net.Conn
	ips := ipm.Get(domain)
	confirmed := ips.Confirmed()
	if confirmed != nil {
		log.D("redial: trying IP %s for addr %s", confirmed, addr)
		if conn, err = DialWithSplitRetry(dialer, tcpaddr(confirmed, port)); err == nil {
			log.I("redial: confirmed IP %s worked for %s", confirmed, addr)
			return conn, nil
		}
		log.D("redial: IP %s for %s failed with err %v", confirmed, addr, err)
		ips.Disconfirm(confirmed)
	}

	allips := ips.GetAll()
	log.D("redial: trying all IPs %d for %s", len(allips), addr)
	for _, ip := range allips {
		if ip.Equal(confirmed) {
			continue // don't try this IP again
		}
		if conn, err = DialWithSplitRetry(dialer, tcpaddr(ip, port)); err == nil {
			go ips.Confirm(ip)
			log.I("redial: found working IP %s for %s", ip, addr)
			return conn, nil
		}
	}
	log.W("redial: all IPs %d failed for %s", len(allips), addr)
	Renew(domain, nil)
	return nil, err
}
