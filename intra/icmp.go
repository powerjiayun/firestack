// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"context"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/settings"
)

type icmpHandler struct {
	*baseHandler
}

var _ netstack.GICMPHandler = (*icmpHandler)(nil)

func NewICMPHandler(pctx context.Context, resolver dnsx.Resolver, prox ipn.Proxies, tunMode *settings.TunMode, listener Listener) netstack.GICMPHandler {
	h := &icmpHandler{
		baseHandler: newBaseHandler(pctx, "icmp", resolver, prox, tunMode, listener),
	}

	go h.processSummaries()

	log.I("icmp: new handler created")
	return h
}

// Ping implements netstack.GICMPHandler. Takes ownership of msg.
// Nb: to send icmp pings, root access is required; and so,
// send "unprivileged" icmp pings via udp reqs; which do
// work on Vanilla Android, because ping_group_range is
// set to 0 2147483647
// ref: cs.android.com/android/platform/superproject/+/master:system/core/rootdir/init.rc;drc=eef0f563fd2d16343aa1ac01eebe98126f26e352;l=297
// ref: androidxref.com/9.0.0_r3/xref/libcore/luni/src/test/java/libcore/java/net/InetAddressTest.java#265
// see: sturmflut.github.io/linux/ubuntu/2015/01/17/unprivileged-icmp-sockets-on-linux/
// ex: github.com/prometheus-community/pro-bing/blob/0bacb2d5e/ping.go#L703
func (h *icmpHandler) Ping(msg []byte, source, target netip.AddrPort) (echoed bool) {
	var px ipn.Proxy = nil
	var err error
	var tx, rx int

	// flow is alg/nat-aware, do not change target or any addrs
	res, undidAlg, realips, doms := h.onFlow(source, target)
	dst := oneRealIPPort(realips, target)
	// on Android, uid is always "unknown" for icmp
	cid, uid, _, pids := h.judge(res)
	smm := icmpSummary(cid, uid)

	defer func() {
		smm.Tx = int64(tx)
		smm.Rx = int64(rx)
		smm.Target = dst.Addr().String()
		h.queueSummary(smm.done(err)) // err may be nil
	}()

	if h.status.Load() == HDLEND {
		err = errIcmpEnd
		log.D("t.icmp: handler ended (%s => %s)", source, target)
		return false // not handled
	}

	if isAnyBlockPid(pids) {
		smm.PID = ipn.Block
		if undidAlg && len(realips) <= 0 && len(doms) > 0 {
			err = errNoIPsForDomain
		} else {
			err = errIcmpFirewalled
		}
		log.I("t.icmp: egress: firewalled %s => %s", source, target)
		// sleep for a while to avoid busy conns? will also block netstack
		// see: netstack/dispatcher.go:newReadvDispatcher
		// time.Sleep(blocktime)
		return false // denied
	}

	if px, err = h.prox.ProxyTo(dst, uid, pids); err != nil || px == nil {
		log.E("t.icmp: egress: no proxy(%s); err %v", pids, err)
		return false // denied
	}

	proto, anyaddr := anyaddrFor(dst)

	uc, err := px.Dialer().Probe(proto, anyaddr)
	defer core.Close(uc)
	ucnil := uc == nil || core.IsNil(uc)

	smm.PID = px.ID()

	// nilaway: tx.socks5 returns nil conn even if err == nil
	if err != nil || ucnil {
		err = core.OneErr(err, unix.ENETUNREACH)
		log.E("t.icmp: egress: dial(%s); hasConn? %s(%t); err %v",
			dst, pids, !ucnil, err)
		return false // unhandled
	}

	h.conntracker.Track(cid, uc)
	defer h.conntracker.Untrack(cid)

	// todo: construct ICMP header? github.com/prometheus-community/pro-bing/blob/0bacb2d5e7/ping.go#L717
	reply, from := core.Echo(uc, msg, net.UDPAddrFromAddrPort(dst), target.Addr().Is4())
	// todo: ignore non-ICMP replies in b: github.com/prometheus-community/pro-bing/blob/0bacb2d5e7/ping.go#L630
	log.D("t.icmp: ingress: read(%v <= %v / %v) ping done %d; err? %v",
		source, from, dst, len(reply), err)

	return true // echoed; even if err != nil
}

func extend(c core.MinConn, t time.Duration) {
	if c != nil && core.IsNotNil(c) {
		_ = c.SetDeadline(time.Now().Add(t))
	}
}

func anyaddrFor(ipp netip.AddrPort) (proto, anyaddr string) {
	return ipn.AnyAddrForUDP(ipp)
}

func logev(err error) log.LogFn {
	f := log.E
	if err == nil {
		f = log.VV
	}
	return f
}
