// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package intra

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

// from: github.com/pion/transport/blob/03c807b/udp/conn.go

const maxtimeouterrors = 3

type flowkind int32

var (
	ingress flowkind = 0
	egress  flowkind = 1
)

func (f flowkind) String() string {
	if f == ingress {
		return "ingress"
	}
	return "egress"
}

type sender interface {
	id() string
	sendto([]byte, net.Addr) (int, error)
	extend(time.Time)
}

type stats struct {
	dur   time.Duration // set only once; on stop()
	start time.Time     // set only once; on ctor

	dxcount atomic.Uint32
	tx      atomic.Uint32
	rx      atomic.Uint32
}

func (s *stats) String() string {
	if s == nil {
		return "<nil>"
	}
	return fmt.Sprintf("tx: %d, rx: %d, conns: %d, dur: %ds", s.tx.Load(), s.rx.Load(), s.dxcount.Load(), int64(s.dur.Seconds()))
}

type vendor func(fwd net.Conn, dst netip.AddrPort) error

// muxer muxes multiple connections grouped by remote addr over net.PacketConn
type muxer struct {
	// cid, pid, mxconn, stats are immutable (never reassigned)
	mxconn net.PacketConn
	cid    string // connection id of mxconn
	pid    string // proxy id mxconn is listening on
	uid    string // user id owner of mxconn
	stats  *stats

	until time.Time // deadline extension

	dxconns chan *demuxconn // never closed
	doneCh  chan struct{}   // stop vending, reading, and routing
	once    sync.Once
	cb      func() // muxer.stop() callback (in a new goroutine)
	vnd     vendor // for new routes in netstack

	rmu    sync.RWMutex                  // protects routes
	routes map[netip.AddrPort]*demuxconn // remote addr -> demuxed conn

	dxconnWG *sync.WaitGroup // wait group for demuxed conns
}

// demuxconn writes to addr and reads from the muxer
type demuxconn struct {
	remux sender         // promiscuous sender
	key   netip.AddrPort // promiscuous factor (same as raddr)
	raddr net.Addr       // remote address connected to
	laddr net.Addr       // local address connected from

	incomingCh chan *slice // incoming data, never closed
	overflowCh chan *slice // overflow data, never closed

	closed chan struct{} // close signal
	once   sync.Once     // close once

	wt  *time.Ticker  // write deadline
	rt  *time.Ticker  // read deadline
	wto time.Duration // write timeout
	rto time.Duration // read timeout
}

// slice is a byte slice v and its recycler free.
type slice struct {
	v    []byte
	free func()
}

var _ sender = (*muxer)(nil)
var _ core.UDPConn = (*demuxconn)(nil)

// newMuxer creates a muxer/demuxer for a connectionless conn.
func newMuxer(cid, pid, uid string, conn net.PacketConn, vnd vendor, f func()) *muxer {
	x := &muxer{
		cid:      cid,
		pid:      pid,
		uid:      uid,
		mxconn:   conn,
		stats:    &stats{start: time.Now()},
		routes:   make(map[netip.AddrPort]*demuxconn),
		rmu:      sync.RWMutex{},
		dxconns:  make(chan *demuxconn),
		doneCh:   make(chan struct{}),
		dxconnWG: &sync.WaitGroup{},
		cb:       f,
		vnd:      vnd,
	}
	go x.readers()
	go x.awaiters()
	return x
}

// awaiters waits for a demuxed conns to close, then cleans the state up.
func (x *muxer) awaiters() {
	for {
		select {
		case c := <-x.dxconns:
			log.D("udp: mux: %s awaiter: watching %s => %s", x.cid, c.laddr, c.raddr)
			x.dxconnWG.Add(1) // accept
			core.Gx("udpmux.vend.close", func() {
				<-c.closed // conn closed
				x.unroute(c)
				x.dxconnWG.Done() // unaccept
			})
		case <-x.doneCh:
			log.I("udp: mux: %s awaiter: done", x.cid)
			return
		}
	}
}

// stop closes conns in the backlog, stops accepting new conns,
// closes muxconn, and waits for demuxed conns to close.
func (x *muxer) stop() error {
	log.D("udp: mux: %s stop", x.cid)

	var err error
	x.once.Do(func() {
		close(x.doneCh)
		x.drain()
		err = x.mxconn.Close() // close the muxed conn

		x.dxconnWG.Wait()          // all conns close / error out
		core.Go("udpmux.cb", x.cb) // dissociate
		x.stats.dur = time.Since(x.stats.start)
		log.I("udp: mux: %s stopped; stats: %s", x.cid, x.stats)
	})

	return err
}

func (x *muxer) drain() {
	x.rmu.Lock()
	defer x.rmu.Unlock()

	defer clear(x.routes)
	log.D("udp: mux: %s drain: closing %d demuxed conns", x.cid, len(x.routes))
	for _, c := range x.routes {
		clos(c) // will unroute as well
	}
}

// readers has to tasks:
//  1. Dispatching incoming packets to the correct Conn.
//     It can therefore not be ended until all Conns are closed.
//  2. Creating a new Conn when receiving from a new remote.
func (x *muxer) readers() {
	// todo: recover must call "free()" if it wasn't.
	defer core.Recover(core.Exit11, "udpmux.read")
	defer func() {
		_ = x.stop() // stop muxer
	}()

	timeouterrors := 0
	for {
		bptr := core.AllocRegion(core.B65536)
		b := *bptr
		b = b[:cap(b)]
		// todo: if panics are recovered above, free() may never be called
		free := func() {
			*bptr = b
			core.Recycle(bptr)
		}

		n, who, err := x.mxconn.ReadFrom(b)

		x.stats.tx.Add(uint32(n)) // upload

		if timedout(err) {
			timeouterrors++
			if timeouterrors < maxtimeouterrors {
				x.extend(time.Now().Add(udptimeout))
				log.D("udp: mux: %s read timeout(%d): %v", x.cid, timeouterrors, err)
				continue
			} // else: err out
		}
		if err != nil {
			log.I("udp: mux: %s read done n(%d): %v", x.cid, n, err)
			return
		}
		if who == nil || n == 0 {
			log.W("udp: mux: %s read done n(%d): nil remote addr; skip", x.cid, n)
			continue
		}

		// may be an existing route or a new route
		if dst := x.route(addr2netip(who), ingress); dst != nil {
			select {
			case dst.incomingCh <- &slice{v: b[:n], free: free}: // incomingCh is never closed
			default: // dst probably closed, but not yet unrouted
				log.W("udp: mux: %s read: drop(sz: %d); route to %s", x.cid, n, dst.raddr)
			}
			log.V("udp: mux: %s read: n(%d) from %v <= %v; err %v", x.cid, n, dst, who, err)
		} // else: ignore (who is invalid or x is closed)
	}
}

func (x *muxer) findRoute(to netip.AddrPort) *demuxconn {
	x.rmu.RLock()
	defer x.rmu.RUnlock()
	return x.routes[to]
}

func (x *muxer) route(to netip.AddrPort, flo flowkind) *demuxconn {
	if !to.IsValid() {
		log.W("udp: mux: %s route: %s invalid addr %s", x.cid, flo, to)
		return nil
	}

	if conn := x.findRoute(to); conn != nil {
		return conn
	}

	x.rmu.Lock()
	defer x.rmu.Unlock()

	conn, ok := x.routes[to]
	if conn == nil || !ok {
		// new routes created here won't really exist in netstack if
		// settings.EndpointIndependentMapping or settings.EndpointIndependentFiltering
		// is set to false.
		conn = x.newLocked(to)
		select {
		case <-x.doneCh:
			clos(conn)
			log.W("udp: mux: %s route: %s for %s; muxer closed", x.cid, flo, to)
			return nil
		case x.dxconns <- conn:
			n := x.stats.dxcount.Add(1)
			x.routes[to] = conn
			// if egress, a demuxed conn is already vended/sockisifed via netstack
			// (see: udpHandler:ProxyMux) and so it need not be vended again. Even
			// if it were to be, it'd fail with "port/addr already in use"
			// ex: route: egress vend failure 1.1.1.1:53; err connect udp 10.111.222.1:42182: port is in use
			if flo == ingress {
				core.Go("udpmux.vend", func() { // a fork in the road
					if verr := x.vnd(conn, to); verr != nil {
						clos(conn)
						log.E("udp: mux: %s route: %s vend failure %s; err %v", x.cid, flo, to, verr)
					}
				})
			}
			log.I("udp: mux: %s route: %s #%d new for %s; stats: %d", x.cid, flo, n, to, x.stats)
		}
	}
	return conn
}

func (x *muxer) unroute(c *demuxconn) {
	// don't really expect to handle panic w/ core.Recover
	x.rmu.Lock()
	defer x.rmu.Unlock()

	log.I("udp: mux: %s unrouting... %s => %s", x.cid, c.laddr, c.raddr)
	delete(x.routes, c.key)
}

func (x *muxer) id() string { return x.cid }

func (x *muxer) sendto(p []byte, addr net.Addr) (int, error) {
	// on closed(x.doneCh), x.mxconn is closed and writes will fail
	n, err := x.mxconn.WriteTo(p, addr)
	x.stats.rx.Add(uint32(n)) // download
	return n, err
}

func (x *muxer) extend(t time.Time) {
	if t.IsZero() || x.until.IsZero() {
		x.until = t
		extend(x.mxconn, time.Until(t))
		return
	}
	// extend if t is after existing deadline at x.until
	if x.until.Before(t) {
		x.until = t
		extend(x.mxconn, time.Until(t))
	}
}

// new creates a demuxed conn to r.
func (x *muxer) newLocked(r netip.AddrPort) *demuxconn {
	return &demuxconn{
		remux:      x,                          // muxer
		laddr:      x.mxconn.LocalAddr(),       // listen addr
		raddr:      net.UDPAddrFromAddrPort(r), // remote addr
		key:        r,                          // key (same as raddr)
		incomingCh: make(chan *slice, 32),      // read from muxer
		overflowCh: make(chan *slice, 16),      // overflow from read
		closed:     make(chan struct{}),        // always unbuffered
		wt:         time.NewTicker(udptimeout),
		rt:         time.NewTicker(udptimeout),
		wto:        udptimeout,
		rto:        udptimeout,
	}
}

// Read implements core.UDPConn.Read
func (c *demuxconn) Read(p []byte) (int, error) {
	defer c.rt.Reset(c.rto)
	select {
	case <-c.rt.C:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, net.ErrClosed
	case sx := <-c.overflowCh:
		return c.io(&p, sx)
	case sx := <-c.incomingCh:
		return c.io(&p, sx)
	}
}

// Write implements core.UDPConn.Write
func (c *demuxconn) Write(p []byte) (n int, err error) {
	defer c.wt.Reset(c.wto)
	sz := len(p)
	select {
	case <-c.wt.C:
		log.W("udp: mux: %s demux: write: %v => %v; timeout (sz: %d)",
			c.remux.id(), c.laddr, c.raddr, sz)
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		log.W("udp: mux: %s demux: write: %v => %v; closed (sz: %d)",
			c.remux.id(), c.laddr, c.raddr, sz)
		return 0, net.ErrClosed
	default:
		n, err = c.remux.sendto(p, c.raddr)
		logev(err)("udp: mux: %s demux: write: %v => %v; done(sz: %d/%d); err? %v",
			c.remux.id(), c.laddr, c.raddr, n, sz, err)
		return n, err
	}
}

// ReadFrom implements core.UDPConn.ReadFrom (unused)
func (c *demuxconn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.raddr, err
}

// WriteTo implements core.UDPConn.WriteTo (unused)
func (c *demuxconn) WriteTo(p []byte, to net.Addr) (int, error) {
	// todo: check if "to" is the same as c.raddr
	// if to != c.raddr {
	// 	return 0, net.ErrWriteToConnected
	// }
	return c.Write(p)
}

// Close implements core.UDPConn.Close
func (c *demuxconn) Close() error {
	log.D("udp: mux: %s demux %s => %s close, in: %d, over: %d",
		c.remux.id(), c.laddr, c.raddr, len(c.incomingCh), len(c.overflowCh))
	c.once.Do(func() {
		close(c.closed) // sig close
		defer c.wt.Stop()
		defer c.rt.Stop()
		for {
			select {
			case sx := <-c.incomingCh:
				sx.free()
			case sx := <-c.overflowCh:
				sx.free()
			default:
				log.I("udp: mux: %s demux from %s => %s closed", c.remux.id(), c.laddr, c.raddr)
				return
			}
		}
	})
	return nil
}

// LocalAddr implements core.UDPConn.LocalAddr
func (c *demuxconn) LocalAddr() net.Addr {
	return c.laddr
}

// RemoteAddr implements core.UDPConn.RemoteAddr
func (c *demuxconn) RemoteAddr() net.Addr {
	return c.raddr
}

// SetDeadline implements core.UDPConn.SetDeadline
func (c *demuxconn) SetDeadline(t time.Time) error {
	werr := c.SetReadDeadline(t)
	rerr := c.SetReadDeadline(t)
	return errors.Join(werr, rerr)
}

// SetReadDeadline implements core.UDPConn.SetReadDeadline
func (c *demuxconn) SetReadDeadline(t time.Time) error {
	if d := time.Until(t); d > 0 {
		c.rto = d
		c.rt.Reset(d)
		c.remux.extend(t)
	} else {
		c.remux.extend(time.Time{}) // no deadline
		c.rt.Stop()
	}
	return nil
}

// SetWriteDeadline implements core.UDPConn.SetWriteDeadline
func (c *demuxconn) SetWriteDeadline(t time.Time) error {
	if d := time.Until(t); d > 0 {
		c.wto = d
		c.wt.Reset(d)
		c.remux.extend(t)
	} else {
		c.remux.extend(time.Time{}) // no deadline
		c.wt.Stop()
	}
	// Write deadline of underlying connection should not be changed
	// since the connection can be shared.
	return nil
}

func (c *demuxconn) io(out *[]byte, in *slice) (int, error) {
	id := c.remux.id()
	// todo: handle the case where len(b) > len(p)
	n := copy(*out, in.v)
	q := len(in.v) - n
	if q > 0 {
		ov := &slice{v: in.v[n:], free: in.free}
		select {
		case <-c.closed:
			log.W("udp: mux: %s demux: read: %v <= %v drop(sz: %d)", id, c.laddr, c.raddr, q)
			in.free()
		case c.overflowCh <- ov: // overflowCh is never closed
			log.W("udp: mux: %s demux: read: %v <= %v overflow(sz: %d)", id, c.laddr, c.raddr, q)
		}
	} else {
		log.V("udp: mux: %s demux: read: %v <= %v done(sz: %d)", id, c.laddr, c.raddr, n)
		in.free()
	}
	return n, nil
}

func timedout(err error) bool {
	x, ok := err.(net.Error)
	return ok && x.Timeout()
}

type muxTable struct {
	sync.Mutex
	t map[string]map[netip.AddrPort]*muxer // pid -> [src -> dst] endpoint independent nat
}

type assocFn func(net, dst string) (net.PacketConn, error)

func newMuxTable() *muxTable {
	return &muxTable{t: make(map[string]map[netip.AddrPort]*muxer)}
}

func (e *muxTable) pid(src netip.AddrPort) string {
	e.Lock()
	defer e.Unlock()
	for _, pxm := range e.t {
		if mxr := pxm[src]; mxr != nil {
			return mxr.pid
		}
	}
	return ""
}

func (e *muxTable) associate(cid, pid, uid string, src, dst netip.AddrPort, mk assocFn, v vendor) (_ net.Conn, err error) {
	e.Lock() // lock

	pxm := e.t[pid]
	if pxm == nil {
		pxm = make(map[netip.AddrPort]*muxer)
		e.t[pid] = pxm
	}

	mxr := pxm[src]
	if mxr == nil {
		// dst may be of a different family than src (4to6, 6to4 etc)
		// and so, rely on dst to determine the family to listen on.
		proto := "udp"
		anyaddr := anyaddr6
		if dst.Addr().Is4() && !dialers.Use6() {
			proto = "udp4"
			anyaddr = anyaddr4
		}
		anyaddrport := netip.AddrPortFrom(anyaddr, 0)
		if settings.PortForward.Load() {
			anyaddrport = netip.AddrPortFrom(anyaddr, src.Port())
		}

		pc, err := mk(proto, anyaddrport.String())

		if err != nil {
			core.Close(pc)
			e.Unlock()      // unlock
			return nil, err // return
		}

		mxr = newMuxer(cid, pid, uid, pc, v, func() {
			e.dissociate(cid, pid, src)
		})
		pxm[src] = mxr
		log.I("udp: mux: %s new assoc for %s %s via %s",
			cid, pid, src, anyaddrport)
	}

	if mxr.pid != pid {
		log.E("udp: mux: %s assoc proxy mismatch: %s != %s or %s != %s",
			cid, mxr.pid, pid, mxr.uid, uid)
		e.Unlock()                   // unlock
		return nil, errProxyMismatch // return
	} else if mxr.uid != uid &&
		(uid != UNKNOWN_UID_STR || mxr.uid != UNKNOWN_UID_STR) {
		log.E("udp: mux: %s assoc uid mismatch: %s != %s or %s != %s",
			cid, mxr.pid, pid, mxr.uid, uid)
		e.Unlock()                 // unlock
		return nil, errUidMismatch // return
	}

	e.Unlock() // unlock
	// do not hold e.lock on calls into mxr
	c := mxr.route(dst, egress)
	if c == nil {
		log.E("udp: mux: %s vend: no conn for %s", mxr.cid, dst)
		return nil, errUdpSetupConn
	}
	return c, nil
}

func (e *muxTable) dissociate(cid, pid string, src netip.AddrPort) {
	log.I("udp: mux: %s (%s) dissoc for %s", cid, pid, src)

	e.Lock()
	defer e.Unlock()
	pxm := e.t[pid] // may be nil and that's okay
	delete(pxm, src)
}

func addr2netip(addr net.Addr) (zz netip.AddrPort) {
	if addr == nil {
		return // zz
	}
	ipp, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		log.W("udp: mux: addr2netip: %v", err)
		return // zz
	}
	return ipp // may be invalid
}
