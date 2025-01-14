// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect/ipmap"
)

const dialRetryTimeout = 35 * time.Second

var errRetryTimeout = errors.New("dialers: retry timeout")

func maybeFilter(ips []netip.Addr, alwaysExclude netip.Addr) ([]netip.Addr, bool) {
	failingopen := true
	use4 := Use4()
	use6 := Use6()

	filtered := make([]netip.Addr, 0, len(ips))
	unfiltered := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Compare(alwaysExclude) == 0 || !ip.IsValid() {
			continue
		} else if use4 && ip.Is4() {
			filtered = append(filtered, ip)
		} else if use6 && ip.Is6() {
			filtered = append(filtered, ip)
		} else {
			unfiltered = append(unfiltered, ip)
		}
	}
	if len(filtered) <= 0 {
		// if all ips are filtered out, fail open and return unfiltered
		return unfiltered, failingopen
	}
	if len(unfiltered) > 0 {
		// sample one unfiltered ip in an ironic case that it works
		// but the filtered out ones don't. this can happen in scenarios
		// where tunnel's ipProto is IP4 but the underlying network is IP6:
		// that is, IP6 is filtered out even though it might have worked.
		filtered = append(filtered, unfiltered[0])
	}
	return filtered, !failingopen
}

func commondial[D rdials, C rconns](d D, network, addr string, connect dialFn[D, C]) (C, error) {
	return commondial2(d, network, "", addr, connect)
}

func commondial2[D rdials, C rconns](d D, network, laddr, raddr string, connect dialFn[D, C]) (C, error) {
	start := time.Now()

	local, lerr := netip.ParseAddrPort(laddr) // okay if local is invalid
	domain, portstr, err := net.SplitHostPort(raddr)

	log.D("commondial: dialing (host:port) %s=>%s; errs? %v %v",
		laddr, raddr, lerr, err)

	if err != nil {
		return nil, err
	}

	// cannot dial into a wildcard address
	// while, listen is unsupported
	if len(domain) == 0 {
		return nil, net.InvalidAddrError(raddr)
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		return nil, err
	}

	var conn C
	var errs error
	ips := ipm.Get(domain)
	dontretry := ips.OneIPOnly() // just one IP, no retries possible
	confirmed := ips.Confirmed() // may be zeroaddr
	confirmedIPOK := ipok(confirmed)

	defer func() {
		dur := time.Since(start)
		log.D("commondial: duration: %s; addr %s; confirmed? %s, sz: %d", dur, raddr, confirmed, ips.Size())
	}()

	if confirmedIPOK {
		remote := netip.AddrPortFrom(confirmed, uint16(port))
		log.V("commondial: dialing confirmed ip %s for %s", confirmed, remote)
		conn, err = connect(d, network, local, remote)
		// nilaway: tx.socks5 returns nil conn even if err == nil
		if conn == nil {
			err = core.OneErr(err, errNoConn)
		}
		if err == nil {
			log.V("commondial: ip %s works for %s", confirmed, remote)
			return conn, nil
		}
		errs = errors.Join(errs, err)
		ips.Disconfirm(confirmed)
		logwd(err)("rdial: commondial: confirmed %s for %s failed; err %v",
			confirmed, remote, err)
	}

	if dontretry {
		if !confirmedIPOK {
			log.E("commondial: ip %s not ok for %s", confirmed, raddr)
			errs = errors.Join(errs, errNoIps)
		}
		return nil, errs
	}

	ipset := ips.Addrs()
	allips, failingopen := maybeFilter(ipset, confirmed)
	if len(allips) <= 0 || failingopen {
		var ok bool
		if ips, ok = renew(domain, ips); ok {
			ipset = ips.Addrs()
			allips, failingopen = maybeFilter(ipset, confirmed)
		}
		log.D("commondial: renew ips for %s; ok? %t, failingopen? %t", raddr, ok, failingopen)
	}
	log.D("commondial: trying all ips %d %v for %s, failingopen? %t",
		len(allips), allips, raddr, failingopen)
	for _, ip := range allips {
		end := time.Since(start)
		if end > dialRetryTimeout {
			errs = errors.Join(errs, errRetryTimeout)
			log.D("commondial: timeout %s for %s", end, raddr)
			break
		}
		if ipok(ip) {
			remote := netip.AddrPortFrom(ip, uint16(port))
			conn, err = connect(d, network, local, remote)
			// nilaway: tx.socks5 returns nil conn even if err == nil
			if conn == nil {
				err = core.OneErr(err, errNoConn)
			}
			if err == nil {
				confirm(ips, ip)
				log.I("commondial: ip %s works for %s", ip, remote)
				return conn, nil
			}
			errs = errors.Join(errs, err)
			logwd(err)("rdial: commondial: ip %s for %s failed; err %v", ip, remote, err)
		} else {
			log.W("commondial: ip %s not ok for %s", ip, raddr)
		}
	}

	if len(ipset) <= 0 {
		errs = errNoIps
	}

	return nil, errs
}

func clos(c ...core.MinConn) {
	core.CloseConn(c...)
}

func confirm(ips *ipmap.IPSet, ip netip.Addr) {
	if ips != nil && ipok(ip) {
		ips.Confirm(ip)
	}
}

func ipok(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified()
}

func logwd(err error) log.LogFn {
	if err != nil {
		return log.W
	}
	return log.D
}
