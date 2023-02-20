// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2019 The Outline Authors
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

// Derived from go-tun2socks's "direct" handler under the Apache 2.0 license.

package intra

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"github.com/txthinking/socks5"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

const (
	// arbitrary threshold of temporary errs before connection is closed
	maxconnerr = 7
)

// UDPSocketSummary describes a non-DNS UDP association, reported when it is discarded.
type UDPSocketSummary struct {
	UploadBytes   int64 // Amount uploaded (bytes)
	DownloadBytes int64 // Amount downloaded (bytes)
	Duration      int32 // How long the socket was open (seconds)
}

// UDPListener is notified when a non-DNS UDP association is discarded.
type UDPListener interface {
	OnUDPSocketClosed(*UDPSocketSummary)
}

type tracker struct {
	conn     interface{} // net.Conn and net.PacketConn
	start    time.Time
	upload   int64        // Non-DNS upload bytes
	download int64        // Non-DNS download bytes
	errcount int          // conn splice err count
	ip       *net.UDPAddr // masked addr
}

func makeTracker(conn interface{}) *tracker {
	return &tracker{conn, time.Now(), 0, 0, 0, nil}
}

// UDPHandler adds DOH support to the base UDPConnHandler interface.
type UDPHandler interface {
	core.UDPConnHandler
	netstack.GUDPConnHandler
	blockConn(localudp core.UDPConn, target *net.UDPAddr) bool
	SetProxyOptions(*settings.ProxyOptions) error
}

type udpHandler struct {
	UDPHandler
	sync.RWMutex

	resolver dnsx.Resolver
	timeout  time.Duration
	udpConns map[core.UDPConn]*tracker
	config   *net.ListenConfig
	blocker  protect.Blocker
	tunMode  *settings.TunMode
	listener UDPListener
	proxy    proxy.Dialer
	pt       ipn.NAT64
}

// NewUDPHandler makes a UDP handler with Intra-style DNS redirection:
// All packets are routed directly to their destination.
// `timeout` controls the effective NAT mapping lifetime.
// `config` is used to bind new external UDP ports.
// `listener` receives a summary about each UDP binding when it expires.
func NewUDPHandler(resolver dnsx.Resolver, pt ipn.NAT64, blocker protect.Blocker,
	tunMode *settings.TunMode, listener UDPListener) UDPHandler {
	// RFC 4787 REQ-5 requires a timeout no shorter than 5 minutes.
	udptimeout, _ := time.ParseDuration("5m")
	c := protect.MakeListenConfig2(blocker)
	h := &udpHandler{
		timeout:  udptimeout,
		udpConns: make(map[core.UDPConn]*tracker, 8),
		resolver: resolver,
		blocker:  blocker,
		tunMode:  tunMode,
		config:   c,
		listener: listener,
		pt:       pt,
	}

	return h
}

func nc2str(conn core.UDPConn, c net.Conn, nat *tracker) string {
	laddr := c.LocalAddr()
	raddr := c.RemoteAddr()
	nsladdr := conn.LocalAddr()
	nsraddr := conn.RemoteAddr()
	return fmt.Sprintf("(l:%v [%v] <- r:%v [%v / n:%v])", laddr, nsladdr, nsraddr, raddr, nat.ip)
}

func pc2str(conn core.UDPConn, c net.PacketConn, nat *tracker) string {
	laddr := c.LocalAddr()
	nsladdr := conn.LocalAddr()
	nsraddr := conn.RemoteAddr()
	return fmt.Sprintf("(l:%v [%v] <- r:%v [ / n:%v])", laddr, nsladdr, nsraddr, nat.ip)
}

// fetchUDPInput reads from nat.conn to masqurade-write it to core.UDPConn
func (h *udpHandler) fetchUDPInput(conn core.UDPConn, nat *tracker) {
	buf := core.NewBytes(core.BufSize)

	defer func() {
		h.Close(conn)
		core.FreeBytes(buf)
	}()

	for {
		if nat.errcount > maxconnerr {
			log.Debugf("t.udp.fetchudp: too many errors (%v), closing", nat.errcount)
			return
		}

		var n int
		var logaddr string
		var addr net.Addr
		var err error
		// FIXME: ReadFrom seems to block for 50mins+ at times:
		// Cancel the goroutine in such cases and close the conns
		switch c := nat.conn.(type) {
		case net.PacketConn:
			logaddr = pc2str(conn, c, nat)
			log.Debugf("t.udp.fetchudp: read (pc) remote for %s", logaddr)
			c.SetDeadline(time.Now().Add(h.timeout)) // extend deadline
			// reads a packet from t.conn copying it to buf
			n, addr, err = c.ReadFrom(buf)
		case net.Conn:
			logaddr = nc2str(conn, c, nat)
			log.Debugf("t.udp.fetchudp: read (c) remote for %s", logaddr)
			c.SetDeadline(time.Now().Add(h.timeout)) // extend deadline
			// c is already dialed-in to some addr in udpHandler.Connect
			n, err = c.Read(buf)
		default:
			err = errors.New("failed to read from proxy udp conn")
		}

		// is err recoverable?
		// ref: github.com/miekg/dns/blob/f8a185d39/server.go#L521
		if neterr, ok := err.(net.Error); ok && neterr.Temporary() {
			nat.errcount += 1
			log.Infof("t.udp.fetchudpinput: %s temp err#%d(%v)", logaddr, err, nat.errcount)
			continue
		} else if err != nil {
			log.Infof("t.udp.fetchudpinput: %s err(%v)", logaddr, err)
			return
		} else {
			nat.errcount = 0
		}

		var udpaddr *net.UDPAddr
		if addr != nil {
			udpaddr = addr.(*net.UDPAddr)
		} else if nat.ip != nil {
			// overwrite source-addr as set in t.ip
			udpaddr = nat.ip
		}

		log.Debugf("t.udp.fetchudpinput: data(%d) from remote(actual:%v/masq:%v) | addrs: %s", n, addr, udpaddr, logaddr)

		nat.download += int64(n)
		// writes data to conn (tun) with udpaddr as source
		if _, err = conn.WriteFrom(buf[:n], udpaddr); err != nil {
			log.Warnf("failed to write udp data to tun (%s) from %s", logaddr, udpaddr)
		}
	}
}

func (h *udpHandler) dnsOverride(nat *tracker, conn core.UDPConn, addr *net.UDPAddr, query []byte) bool {
	if !h.isDns(addr) {
		return false
	}

	resp, err := h.resolver.Forward(query)
	if resp != nil {
		_, err = conn.WriteFrom(resp, addr)
	}
	if err != nil {
		log.Warnf("dns udp query failed: %v", err)
	}

	// conn was only used for this DNS query, so it's unlikely to be used again.
	if nat.upload == 0 && nat.download == 0 {
		h.Close(conn)
	}
	return true
}

func (h *udpHandler) isDns(addr *net.UDPAddr) bool {
	// addr with zone information removed; see: netip.ParseAddrPort which h.resolver relies on
	addr2 := &net.UDPAddr{IP: addr.IP, Port: addr.Port}
	return h.resolver.IsDnsAddr(dnsx.NetTypeUDP, addr2.String())
}

func (h *udpHandler) onFlow(localudp core.UDPConn, target *net.UDPAddr, realips, domains, blocklists string) (block bool) {
	// BlockModeNone returns false, BlockModeSink returns true
	if h.tunMode.BlockMode == settings.BlockModeSink {
		return true
	}
	if h.tunMode.BlockMode == settings.BlockModeNone {
		return false
	}
	// Implict: BlockModeFilter or BlockModeFilterProc
	localaddr := localudp.LocalAddr()
	return h.blockConnAddr(localaddr, target, realips, domains, blocklists)
}

func (h *udpHandler) blockConnAddr(source *net.UDPAddr, target *net.UDPAddr, realips, domains, blocklists string) (block bool) {
	uid := -1
	if h.tunMode.BlockMode == settings.BlockModeFilterProc {
		procEntry := settings.FindProcNetEntry("udp", source.IP, source.Port, target.IP, target.Port)
		if procEntry != nil {
			uid = procEntry.UserID
		}
	}

	var proto int32 = 17 // udp
	src := source.String()
	dst := target.String()
	if len(realips) > 0 && len(domains) > 0 {
		block = h.blocker.BlockAlg(proto, uid, src, dst, realips, domains, blocklists)
	} else {
		block = h.blocker.Block(proto, uid, src, dst)
	}

	if block {
		log.Infof("firewalled udp connection from %s:%s to %s:%s",
			source.Network(), source.String(), target.Network(), target.String())
	}
	return block
}

func (h *udpHandler) OnNewConn(conn *netstack.GUDPConn, _, dst *net.UDPAddr) bool {
	if err := h.Connect(conn, dst); err != nil {
		return false
	}
	return true
}

// Connect connects the proxy server.
// Note, target may be nil in lwip (deprecated) while it may be unspecified in netstack
func (h *udpHandler) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	ipx4 := maybeUndoNat64(h.pt, target.IP)

	realips, domains, blocklists := undoAlg(h.resolver, ipx4)

	// flow is alg/nat-aware, do not change target or any addrs
	if h.onFlow(conn, target, realips, domains, blocklists) {
		// an error here results in a core.udpConn.Close
		return fmt.Errorf("udp connect: connection firewalled")
	}

	dnsredir := h.isDns(target)

	// TODO: fake-dns-ips shouldn't be un-nated / un-alg'd
	// alg happens before nat64, and so, alg has no knowledge of nat-ed ips
	// ipx4 is un-nated (and same as target.IP when no nat64 is involved)
	// but ipx4 might itself be an alg ip; so check if there's a real-ip to connect to
	// ie, must send to un-nated ips; overwrite target.IP with ipx4
	target.IP = oneRealIp(realips, ipx4)

	var c any
	var err error
	if h.proxymode() && !dnsredir {
		// TODO: target can be nil: What happens then?
		// TODO: target can unspecified on netstack... handle approp in receiveTo?
		// deprecated: github.com/golang/go/issues/25104
		c, err = h.proxy.Dial(target.Network(), target.String())
	} else {
		bindaddr := &net.UDPAddr{IP: nil, Port: 0}
		c, err = h.config.ListenPacket(context.TODO(), bindaddr.Network(), bindaddr.String())
	}

	if err != nil {
		log.Errorf("failed to bind udp addr for(%s); err(%v)", target, err)
		return err
	}

	nat := makeTracker(c)

	if h.proxymode() && !dnsredir {
		nat.ip = &net.UDPAddr{
			IP:   target.IP,
			Port: target.Port,
			Zone: target.Zone,
		}
	}

	h.Lock()
	h.udpConns[conn] = nat
	h.Unlock()

	// TODO: fetch-udp-input not required for dns? dns-override takes over;
	// and funcs doDoh and doDnscrypt close the conns once tx is complete.
	go h.fetchUDPInput(conn, nat)

	log.Infof("new udp proxy (proxy? %t) conn to target: %s", h.proxymode(), target)
	return nil
}

func (h *udpHandler) HandleData(conn *netstack.GUDPConn, data []byte, addr *net.UDPAddr) error {
	return h.ReceiveTo(conn, data, addr)
}

// ReceiveTo is called when data arrives from conn (tun).
func (h *udpHandler) ReceiveTo(conn core.UDPConn, data []byte, addr *net.UDPAddr) (err error) {
	h.RLock()
	nat, ok1 := h.udpConns[conn]
	h.RUnlock()

	if !ok1 {
		log.Warnf("t.udp.rcv: no nat(%v -> %v)", conn.LocalAddr(), addr)
		return fmt.Errorf("conn %v->%v does not exist", conn.LocalAddr(), addr)
	}

	if h.dnsOverride(nat, conn, addr, data) {
		log.Debugf("t.udp.rcv: dns-override for dstaddr(%v)", addr)
		return nil
	}

	ipx4 := maybeUndoNat64(h.pt, addr.IP)

	// unused in netstack as it only supports connected udp
	// that is, udpconn.writeFrom(data, addr) isn't supported
	nat.ip = &net.UDPAddr{
		IP:   addr.IP,
		Port: addr.Port,
		Zone: addr.Zone,
	}

	// send data to un-nated ips; overwrite target.IP with ipx4
	// alg happens before nat64, and so, alg has no knowledge of nat-ed ips
	// ipx4 is un-nated (and equal to target.IP when no nat64 is involved)
	realips, _, _ := undoAlg(h.resolver, ipx4)

	// TODO: should onFlow be called from ReceiveTo?

	// but ipx4 might itself be an alg ip; so check if there's a real-ip to connect to
	addr.IP = oneRealIp(realips, ipx4)

	nat.upload += int64(len(data))

	switch c := nat.conn.(type) {
	case net.PacketConn:
		// Update deadline.
		c.SetDeadline(time.Now().Add(h.timeout))
		// writes packet payload, data, to addr
		_, err = c.WriteTo(data, addr)
	case net.Conn:
		// Update deadline.
		c.SetDeadline(time.Now().Add(h.timeout))
		// c is already dialed-in to some addr in udpHandler.Connect
		_, err = c.Write(data)
	default:
		err = errors.New("failed write to udp proxy")
	}

	// is err recoverable?
	// ref: github.com/miekg/dns/blob/f8a185d39/server.go#L521
	if neterr, ok := err.(net.Error); ok && neterr.Temporary() {
		nat.errcount += 1
		if nat.errcount > maxconnerr {
			log.Warnf("t.udp.rcv: too many errors(%d) for conn(%v)", nat.errcount, conn.LocalAddr())
			return err
		} else {
			log.Warnf("t.udp.rcv: temporary error(%v) for conn(%v)", err, conn.LocalAddr())
			return nil
		}
	} else if err != nil {
		log.Infof("t.udp.rcv: end splice, forward udp err(%v)", err)
		return err
	} else {
		nat.errcount = 0
	}

	log.Infof("t.udp.rcv: src(%v) -> dst(%v) / data(%d)", conn.LocalAddr(), addr, len(data))
	return nil
}

func (h *udpHandler) Close(conn core.UDPConn) {
	conn.Close()

	h.Lock()
	defer h.Unlock()

	if t, ok := h.udpConns[conn]; ok {
		switch c := t.conn.(type) {
		case net.PacketConn:
			c.Close()
		case net.Conn:
			c.Close()
		default:
		}
		// TODO: Cancel any outstanding DoH queries.
		duration := int32(time.Since(t.start).Seconds())
		h.listener.OnUDPSocketClosed(&UDPSocketSummary{t.upload, t.download, duration})
		delete(h.udpConns, conn)
	}
}

// TODO: move these to settings pkg
func (h *udpHandler) socks5Proxy() bool {
	return h.tunMode.ProxyMode == settings.ProxyModeSOCKS5
}

func (h *udpHandler) httpsProxy() bool {
	return h.tunMode.ProxyMode == settings.ProxyModeHTTPS
}

func (h *udpHandler) hasProxy() bool {
	return h.proxy != nil
}

func (h *udpHandler) SetProxyOptions(po *settings.ProxyOptions) error {
	var fproxy proxy.Dialer
	var err error
	if po == nil {
		h.proxy = nil
		err = fmt.Errorf("udp: proxyopts nil")
		log.Warnf("udp: err proxying to(%v): %v", po, err)
		return err
	}

	// TODO: merge this code which is similar between tcp.go/udp.go
	if h.socks5Proxy() {
		// x.net.proxy doesn't yet support udp
		// https://github.com/golang/net/blob/62affa334/internal/socks/socks.go#L233
		// fproxy, err = proxy.SOCKS5("udp", po.IPPort, po.Auth, proxy.Direct)
		udptimeoutsec := 5 * 60                    // 5m
		tcptimeoutsec := (2 * 60 * 60) + (40 * 60) // 2h40m
		fproxy, err = socks5.NewClient(po.IPPort, po.Auth.User, po.Auth.Password, tcptimeoutsec, udptimeoutsec)
	} else if h.httpsProxy() {
		err = fmt.Errorf("udp: http-proxy not supported")
	} else {
		err = errors.New("udp: proxy mode not set")
	}
	if err != nil {
		h.proxy = nil
		log.Warnf("udp: err proxying to(%v): %v", po, err)
		return err
	}
	h.proxy = fproxy
	return nil
}

func (h *udpHandler) proxymode() bool {
	return h.hasProxy() && (h.socks5Proxy() || h.httpsProxy())
}
