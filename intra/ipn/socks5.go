// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/ipn/multihost"
	"github.com/celzero/firestack/intra/ipn/nop"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	tx "github.com/txthinking/socks5"
	"golang.org/x/net/proxy"
)

type socks5 struct {
	nop.NoFwd                              // no forwarding/listening
	nop.NoDNS                              // no dns
	nop.SkipRefresh                        // no refresh
	nop.GW                                 // dual stack gateway
	outbound        []proxy.Dialer         // outbound dialers connecting unto upstream proxy
	id              string                 // unique identifier
	opts            *settings.ProxyOptions // connect options
	lastdial        time.Time              // last time this transport attempted a connection
	status          *core.Volatile[int]    // status of this transport
	done            context.CancelFunc     // cancel func
}

type socks5tcpconn struct {
	*tx.Client
}

type socks5udpconn struct {
	*tx.Client
}

var _ core.TCPConn = (*socks5tcpconn)(nil)
var _ core.UDPConn = (*socks5udpconn)(nil)
var _ net.Conn = (*socks5tcpconn)(nil) // needed by golang/http transport
var _ net.Conn = (*socks5udpconn)(nil)

func (c *socks5tcpconn) CloseRead() error {
	if c.Client != nil && c.Client.TCPConn != nil {
		core.CloseOp(c.Client.TCPConn, core.CopR)
		return nil
	}
	return errNoProxyConn
}

func (c *socks5tcpconn) CloseWrite() error {
	if c.Client != nil && c.Client.TCPConn != nil {
		core.CloseOp(c.Client.TCPConn, core.CopW)
		return nil
	}
	return errNoProxyConn
}

// WriteFrom writes b to TUN using addr as the source.
func (c *socks5udpconn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if c.Client != nil && c.Client.UDPConn != nil {
		if uconn, ok := c.Client.UDPConn.(*net.UDPConn); ok {
			return uconn.WriteTo(b, addr)
		}
		return c.Client.UDPConn.Write(b)
	}
	return 0, errNoProxyConn
}

// ReceiveTo is incoming TUN packet b to be sent to addr.
func (c *socks5udpconn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if c.Client != nil && c.Client.UDPConn != nil {
		if uconn, ok := c.Client.UDPConn.(*net.UDPConn); ok {
			return uconn.ReadFrom(b)
		}
		return 0, nil, errNotUDPConn
	}
	return 0, nil, errNoProxyConn
}

func NewSocks5Proxy(id string, ctx context.Context, ctl protect.Controller, po *settings.ProxyOptions) (_ *socks5, err error) {
	tx.Debug = settings.Debug
	if po == nil {
		log.W("proxy: err setting up socks5(%v): %v", po, err)
		return nil, errMissingProxyOpt
	}

	ctx, done := context.WithCancel(ctx)
	// always with a network namespace aware dialer
	dialer := protect.MakeNsRDial(id, ctx, ctl)
	// todo: support connecting from src
	tx.DialTCP = func(n string, _, d string) (net.Conn, error) {
		return dialer.Dial(n, d)
	}
	tx.DialUDP = func(n string, _, d string) (net.Conn, error) {
		return dialer.Dial(n, d)
	}

	portnumber, _ := strconv.Atoi(po.Port)
	mh := multihost.New(id)
	mh.Add([]string{po.Host, po.IP}) // resolves if ip is name

	var clients []proxy.Dialer
	// x.net.proxy doesn't yet support udp
	// github.com/golang/net/blob/62affa334/internal/socks/socks.go#L233
	// if po.Auth.User and po.Auth.Password are empty strings, the upstream
	// socks5 server may throw err when dialing with golang/net/x/proxy;
	// although, txthinking/socks5 deals gracefully with empty auth strings
	// fproxy, err = proxy.SOCKS5("udp", po.IPPort, po.Auth, proxy.Direct)
	for _, ip := range mh.PreferredAddrs() {
		ipport := netip.AddrPortFrom(ip.Addr(), uint16(portnumber))
		c, cerr := tx.NewClient(ipport.String(), po.Auth.User, po.Auth.Password, tcptimeoutsec, udptimeoutsec)
		if cerr != nil {
			err = errors.Join(err, cerr)
		} else {
			clients = append(clients, c)
		}
	}

	if len(clients) == 0 && err != nil {
		defer done()
		log.W("proxy: err creating socks5 for %v (opts: %v): %v",
			mh, po, err)
		return nil, err
	}

	h := &socks5{
		outbound: clients,
		id:       id,
		opts:     po,
		done:     done,
	}

	log.D("proxy: socks5: created %s with clients(%d), opts(%s)",
		h.ID(), len(clients), po)

	return h, nil
}

// Handle implements Proxy.
func (h *socks5) Handle() uintptr {
	return core.Loc(h)
}

// Dial implements Proxy.
func (h *socks5) Dial(network, addr string) (c protect.Conn, err error) {
	return h.dial(network, "", addr)
}

// DialBind implements Proxy.
func (h *socks5) DialBind(network, local, remote string) (c protect.Conn, err error) {
	log.D("proxy: socks5: %s dialbind(%s) %s => %s; not supported",
		h.ID(), network, local, remote)
	return h.dial(network, local, remote)
}

// todo: bind to local
func (h *socks5) dial(network, _, remote string) (c protect.Conn, err error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	h.lastdial = time.Now()
	// todo: tx.Client can only dial in to ip:port and not host:port even for server addr
	// tx.Client.Dial does not support dialing into client addr as hostnames
	if c, err = dialers.ProxyDials(h.outbound, network, remote); err == nil {
		// github.com/txthinking/socks5/blob/39268fae/client.go#L15
		if uc, ok := c.(*tx.Client); ok {
			if uc.UDPConn != nil { // a udp conn will always have an embedded tcp conn
				c = &socks5udpconn{uc}
			} else if uc.TCPConn != nil { // a tcp conn will never also have a udp conn
				c = &socks5tcpconn{uc}
			} else {
				log.W("proxy: socks5: %s conn not tcp nor udp %s => %s",
					h.ID(), h.GetAddr(), remote)
				core.CloseConn(c)
				c = nil
				err = errNoProxyConn
			}
		} else {
			log.W("proxy: socks5: %s conn not a tx.Client(%s) %s => %s",
				h.ID(), network, h.GetAddr(), remote)
			core.CloseConn(c)
			c = nil
			err = core.OneErr(err, errNoProxyConn)
		}
	} else {
		log.W("proxy: socks5: %s dial(%s) failed %s => %s: %v",
			h.ID(), network, h.GetAddr(), remote, err)
	}
	if err == nil {
		log.I("proxy: socks5: %s dial(%s) from %s => %s",
			h.ID(), network, h.GetAddr(), remote)
		h.status.Store(TOK)
	} else {
		h.status.Store(TKO)
	}
	return
}

// Dialer implements Proxy.
func (h *socks5) Dialer() protect.RDialer {
	return h
}

// ID implements Proxy.
func (h *socks5) ID() string {
	return h.id
}

// Type implements Proxy.
func (h *socks5) Type() string {
	return SOCKS5
}

// Router implements Proxy.
func (h *socks5) Router() x.Router {
	return h
}

// Reaches implements x.Router.
func (h *socks5) Reaches(hostportOrIPPortCsv string) bool {
	return Reaches(h, hostportOrIPPortCsv)
}

// GetAddr implements Proxy.
func (h *socks5) GetAddr() string {
	return h.opts.IPPort
}

// Status implements Proxy.
func (h *socks5) Status() int {
	s := h.status.Load()
	if s != END && idling(h.lastdial) {
		return TZZ
	}
	return s
}

// Stop implements Proxy.
func (h *socks5) Stop() error {
	h.status.Store(END)
	h.done()
	log.I("proxy: socks5: stopped %s", h.id)
	return nil
}

// OnProtoChange implements Proxy.
func (h *socks5) OnProtoChange() (string, bool) {
	return h.opts.FullUrl(), true
}
