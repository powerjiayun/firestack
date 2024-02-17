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
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/log"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/netstack"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

// TCPHandler is a core TCP handler that also supports DOH and splitting control.
type TCPHandler interface {
	netstack.GTCPConnHandler
}

type tcpHandler struct {
	TCPHandler
	resolver    dnsx.Resolver
	dialer      *net.Dialer
	tunMode     *settings.TunMode
	listener    SocketListener
	prox        ipn.Proxies
	fwtracker   *core.ExpMap
	status      int
	conntracker core.ConnMapper // connid -> [local,remote]
}

type ioinfo struct {
	bytes int64
	err   error
}

const (
	TCPOK = iota
	TCPEND
)

var (
	errTcpFirewalled = errors.New("tcp: firewalled")
	errTcpSetupConn  = errors.New("tcp: could not create conn")
)

// NewTCPHandler returns a TCP forwarder with Intra-style behavior.
// Connections to `fakedns` are redirected to DOH.
// All other traffic is forwarded using `dialer`.
// `listener` is provided with a summary of each socket when it is closed.
func NewTCPHandler(resolver dnsx.Resolver, prox ipn.Proxies, tunMode *settings.TunMode, ctl protect.Controller, listener SocketListener) TCPHandler {
	d := protect.MakeNsDialer("tcph", ctl)
	h := &tcpHandler{
		resolver:    resolver,
		dialer:      d,
		tunMode:     tunMode,
		listener:    listener,
		prox:        prox,
		fwtracker:   core.NewExpiringMap(),
		conntracker: core.NewConnMap(),
		status:      TCPOK,
	}

	log.I("tcp: new handler created")
	return h
}

func conn2str(a net.Conn, b net.Conn) string {
	ar := a.RemoteAddr()
	br := b.RemoteAddr()
	al := a.LocalAddr()
	bl := b.LocalAddr()
	return fmt.Sprintf("a(%v->%v) => b(%v<-%v)", al, ar, bl, br)
}

func pclose(c io.Closer, a string) {
	if c == nil {
		return
	}
	if a == "rw" {
		c.Close()
		return
	}
	switch x := c.(type) {
	case core.TCPConn: // net.TCPConn confirms to core.TCPConn
		if a == "r" {
			x.CloseRead()
		} else if a == "w" {
			x.CloseWrite()
		} else { // == "rw"
			x.Close()
		}
	case core.UDPConn:
		x.Close()
	case io.Closer:
		x.Close()
	}
}

// TODO: Propagate TCP RST using local.Abort(), on appropriate errors.
func upload(cid string, local net.Conn, remote net.Conn, ioch chan<- ioinfo) {
	ci := conn2str(local, remote)

	// io.copy does remote.ReadFrom(local)
	n, err := io.Copy(remote, local)
	log.D("intra: %s upload(%d) done(%v) b/w %s", cid, n, err, ci)

	pclose(local, "r")
	pclose(remote, "w")
	ioch <- ioinfo{n, err}
}

func download(cid string, local net.Conn, remote net.Conn) (n int64, err error) {
	ci := conn2str(local, remote)

	n, err = io.Copy(local, remote)
	log.D("intra: %s download(%d) done(%v) b/w %s", cid, n, err, ci)

	pclose(local, "w")
	pclose(remote, "r")
	return
}

// forward copies data between local and remote, and tracks the connection.
// It also sends a summary to the listener when done. Always called in a goroutine.
func forward(local net.Conn, remote net.Conn, t core.ConnMapper, l SocketListener, smm *SocketSummary) {
	cid := smm.ID

	t.Track(cid, local, remote)
	defer t.Untrack(cid)

	uploadch := make(chan ioinfo)

	var dbytes int64
	var derr error
	go upload(cid, local, remote, uploadch)
	dbytes, derr = download(cid, local, remote)

	upload := <-uploadch

	smm.Rx = dbytes
	smm.Tx = upload.bytes
	smm.Target = remote.RemoteAddr().String()

	smm.done(derr, upload.err)
	go sendNotif(l, smm)
}

// must always be called from a goroutine
func sendNotif(l SocketListener, s *SocketSummary) {
	if s == nil { // unlikely
		return
	}
	// sleep a bit to avoid scenario where kotlin-land
	// hasn't yet had the chance to persist info about
	// this conn (cid) to meaninfully process its summary
	time.Sleep(1 * time.Second)

	ok1 := l != nil      // likely due to bugs
	ok2 := len(s.ID) > 0 // likely due to bugs
	log.V("intra: end? sendNotif(%t,%t): %s", ok1, ok2, s.str())
	if ok1 && ok2 {
		l.OnSocketClosed(s) // s.Duration may be uninitialized (zero)
	}
}

func dnsOverride(r dnsx.Resolver, proto string, conn net.Conn, addr net.Addr) bool {
	// addr with zone information removed; see: netip.ParseAddrPort which h.resolver relies on
	// addr2 := &net.TCPAddr{IP: addr.IP, Port: addr.Port}
	if r.IsDnsAddr(addr.String()) {
		// conn closed by the resolver
		r.Serve(proto, conn)
		return true
	}
	return false
}

func (h *tcpHandler) onFlow(localaddr *net.TCPAddr, target *net.TCPAddr, realips, domains, probableDomains, blocklists string) *Mark {
	// BlockModeNone returns false, BlockModeSink returns true
	if h.tunMode.BlockMode == settings.BlockModeSink {
		return optionsBlock
	} else if h.tunMode.BlockMode == settings.BlockModeNone {
		// todo: block-mode none should call into listener.Flow to determine upstream proxy
		return optionsBase
	}

	if len(realips) <= 0 || len(domains) <= 0 {
		log.D("onFlow: no realips(%s) or domains(%s + %s), for src=%s dst=%s", realips, domains, probableDomains, localaddr, target)
	}

	// Implict: BlockModeFilter or BlockModeFilterProc
	uid := -1
	if h.tunMode.BlockMode == settings.BlockModeFilterProc {
		procEntry := settings.FindProcNetEntry("tcp", localaddr.IP, localaddr.Port, target.IP, target.Port)
		if procEntry != nil {
			uid = procEntry.UserID
		}
	}

	var proto int32 = 6 // tcp
	src := localaddr.String()
	dst := target.String()
	res := h.listener.Flow(proto, uid, src, dst, realips, domains, probableDomains, blocklists)

	if res == nil {
		log.W("tcp: onFlow: empty res from kt; using base")
		return optionsBase
	} else if len(res.PID) <= 0 {
		log.W("tcp: onFlow: no pid from kt; using base")
		res.PID = ipn.Base
	}

	return res
}

func (h *tcpHandler) End() error {
	h.status = TCPEND
	h.CloseConns(nil)
	return nil
}

func closeconns(cm core.ConnMapper, cids []string) (closed []string) {
	if len(cids) <= 0 {
		closed = cm.Clear()
	} else {
		closed = cm.UntrackBatch(cids)
	}

	log.I("intra: closed %d/%d", len(closed), len(cids))
	return closed
}

// CloseConns implements netstack.GTCPConnHandler
func (h *tcpHandler) CloseConns(cids []string) (closed []string) {
	return closeconns(h.conntracker, cids)
}

// Proxy implements netstack.GTCPConnHandler
func (h *tcpHandler) Proxy(gconn *netstack.GTCPConn, src, target *net.TCPAddr) (open bool) {
	const allow bool = true
	const deny bool = !allow
	if h.status == TCPEND {
		log.D("tcp: proxy: end")
		return deny
	}

	const rst bool = true // tear down conn
	const ack bool = !rst // send synack
	var err error

	if src == nil || target == nil {
		log.E("tcp: nil addr %v -> %v", src, target)
		gconn.Connect(rst) // fin
		return deny
	}

	// alg happens after nat64, and so, alg knows nat-ed ips
	// that is, realips are un-nated
	realips, domains, probableDomains, blocklists := undoAlg(h.resolver, target.IP)

	// flow/dns-override are nat-aware, as in, they can deal with
	// nat-ed ips just fine, and so, use target as-is instead of ipx4
	res := h.onFlow(src, target, realips, domains, probableDomains, blocklists)

	cid, pid, uid := splitCidPidUid(res)
	s := tcpSummary(cid, pid, uid)

	defer func() {
		if !open {
			gconn.Close()
			s.done(err)
			go sendNotif(h.listener, s)
		} // else: conn proxied; sendNotif called by h.forward()
	}()

	if pid == ipn.Block {
		var secs uint32
		k := uid
		if len(domains) > 0 { // probableDomains are not reliable to use for firewalling
			k += domains
		} else {
			k += target.String()
		}
		if secs = stall(h.fwtracker, k); secs > 0 {
			waittime := time.Duration(secs) * time.Second
			time.Sleep(waittime)
		}
		log.I("tcp: gconn %s firewalled from %s -> %s (dom: %s + %s/ real: %s) for %s; stall? %ds", cid, src, target, domains, probableDomains, realips, uid, secs)
		err = errTcpFirewalled
		gconn.Connect(rst) // fin
		return deny
	}

	// handshake
	if open, err = gconn.Connect(ack); !open {
		err = fmt.Errorf("tcp: %s connect err %v; %s -> %s for %s", cid, err, src, target, uid)
		log.E("%v", err)
		return deny // == !open
	}

	var px ipn.Proxy
	if px, err = h.prox.GetProxy(pid); err != nil {
		return deny
	}

	if pid != ipn.Exit { // see udp.go Connect
		if dnsOverride(h.resolver, dnsx.NetTypeTCP, gconn, target) {
			// SocketSummary not sent; dnsx.Summary supercedes it
			return allow
		} // else not a dns request
	} // if ipn.Exit then let it connect as-is (aka exit)

	// pick all realips to connect to
	for _, dstip := range makeIPs(realips, target.IP) {
		target.IP = dstip
		if err = h.handle(px, gconn, target, s); err == nil {
			return allow
		} // else try the next realip
	}
	return deny
}

func (h *tcpHandler) handle(px ipn.Proxy, src net.Conn, target *net.TCPAddr, smm *SocketSummary) (err error) {
	var pc protect.Conn

	start := time.Now()
	var dst net.Conn

	// ref: stackoverflow.com/questions/63656117
	// ref: stackoverflow.com/questions/40328025
	if pc, err = px.Dial(target.Network(), target.String()); err == nil {
		smm.Rtt = int32(time.Now().Sub(start).Seconds() * 1000)

		switch uc := pc.(type) {
		case *net.TCPConn: // usual
			dst = uc
		case *gonet.TCPConn: // from wgproxy
			dst = uc
		case core.TCPConn: // from confirming proxy dialers
			dst = uc
		case net.Conn: // from non-confirming proxy dialers
			dst = uc
		default:
			err = errTcpSetupConn
		}
	}

	if err != nil {
		log.W("tcp: err dialing %s proxy(%s) to dst(%v) for %s: %v", smm.ID, px.ID(), target, smm.UID, err)
		return err
	}

	go func() {
		cm := h.conntracker
		l := h.listener
		defer func() {
			if r := recover(); r != nil {
				log.W("tcp: forward: panic %v", r)
			}
		}()
		forward(src, dst, cm, l, smm) // src always *gonet.TCPConn
	}()

	log.I("tcp: new conn %s via proxy(%s); src(%s) -> dst(%s) for %s", smm.ID, px.ID(), src.LocalAddr(), target, smm.UID)
	return nil // handled; takes ownership of src
}

// TODO: move this to ipn.Ground
func stall(m *core.ExpMap, k string) (secs uint32) {
	if n := m.Get(k); n <= 0 {
		secs = 0 // no stall
	} else if n > 30 {
		secs = 30 // max up to 30s
	} else if n < 5 {
		secs = (rand.Uint32() % 5) + 1 // up to 5s
	} else {
		secs = n
	}
	// track uid->target for n secs, or 30s if n is 0
	life30s := ((29 + secs) % 30) + 1
	newlife := time.Duration(life30s) * time.Second
	m.Set(k, newlife)
	return
}

func netipFrom(ip net.IP) *netip.Addr {
	if addr, ok := netip.AddrFromSlice(ip); ok {
		addr = addr.Unmap()
		return &addr
	}
	return nil
}

func oneRealIp(realips string, dstip net.IP) net.IP {
	if len(realips) <= 0 {
		return dstip
	}
	// override alg-ip with the first real-ip
	if ips := strings.Split(realips, ","); len(ips) > 0 {
		for _, v := range ips {
			// len may be zero when realips is "," or ""
			if len(v) > 0 {
				ip := net.ParseIP(v)
				if len(ip) > 0 && !ip.IsUnspecified() {
					return ip
				}
			}
		}
	}
	return dstip
}

func makeIPs(realips string, dstip net.IP) []net.IP {
	ips := strings.Split(realips, ",")
	r := make([]net.IP, 0, len(ips))
	// override alg-ip with the first real-ip
	for _, v := range ips { // may contain unspecifed ips
		// len may be zero when realips is "," or ""
		if len(v) > 0 {
			ip := net.ParseIP(v)
			if len(ip) > 0 && !ip.IsUnspecified() {
				r = append(r, ip)
			}
		}
	}

	if len(r) > 0 {
		rand.Shuffle(len(r), func(i, j int) {
			r[i], r[j] = r[j], r[i]
		})
		return r
	}

	return []net.IP{dstip}
}

func undoAlg(r dnsx.Resolver, algip net.IP) (realips, domains, probableDomains, blocklists string) {
	force := true             // force PTR resolution
	dstip := netipFrom(algip) // may be nil
	if gw := r.Gateway(); dstip != nil && dstip.IsValid() && gw != nil {
		dst := dstip.AsSlice()
		domains = gw.PTR(dst, !force)
		if len(domains) <= 0 {
			probableDomains = gw.PTR(dst, force)
		}
		realips = gw.X(dst)
		blocklists = gw.RDNSBL(dst)
	} else {
		log.W("alg: undoAlg: no gw(%t) or dst(%v) or alg-ip(%s)", gw == nil, dstip, algip)
	}
	return
}

// returns proxy-id, conn-id, user-id
func splitCidPidUid(decision *Mark) (cid, pid, uid string) {
	if decision == nil {
		return
	}
	return decision.CID, decision.PID, decision.UID
}
