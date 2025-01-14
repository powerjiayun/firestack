// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"

	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/ipn/nop"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
)

// exit is a proxy that always dials out to the internet.
type exit struct {
	nop.NoDNS
	nop.ProtoAgnostic
	nop.SkipRefresh
	nop.GW
	outbound *protect.RDial // outbound dialer
	addr     string
	status   *core.Volatile[int]
	done     context.CancelFunc
}

// NewExitProxy returns a new exit proxy.
func NewExitProxy(ctx context.Context, c protect.Controller) *exit {
	ctx, done := context.WithCancel(ctx)
	h := &exit{
		addr:     "127.0.0.127:1337",
		outbound: protect.MakeNsRDial(Exit, ctx, c),
		status:   core.NewVolatile(TUP),
		done:     done,
	}
	return h
}

// Handle implements Proxy.
func (h *exit) Handle() uintptr {
	return core.Loc(h)
}

// Dial implements Proxy.
func (h *exit) Dial(network, addr string) (protect.Conn, error) {
	return h.dial(network, "", addr)
}

func (h *exit) DialBind(network, local, remote string) (protect.Conn, error) {
	return h.dial(network, local, remote)
}

func (h *exit) dial(network, local, remote string) (protect.Conn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}

	// exit always splits
	c, err := localDialStrat(h.outbound, network, local, remote)
	defer localDialStatus(h.status, err)

	maybeKeepAlive(c)
	log.I("proxy: exit: dial(%s) %s => %s; err? %v", network, local, remote, err)
	return c, err
}

// Announce implements Proxy.
func (h *exit) Announce(network, local string) (protect.PacketConn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}
	c, err := dialers.ListenPacket(h.outbound, network, local)
	defer localDialStatus(h.status, err)
	log.I("proxy: exit: announce(%s) on %s; err? %v", network, local, err)
	return c, err
}

// Accept implements Proxy.
func (h *exit) Accept(network, local string) (protect.Listener, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}
	return dialers.Listen(h.outbound, network, local)
}

// Probe implements Proxy.
func (h *exit) Probe(network, local string) (protect.PacketConn, error) {
	if h.status.Load() == END {
		return nil, errProxyStopped
	}
	c, err := dialers.Probe(h.outbound, network, local)
	defer localDialStatus(h.status, err)
	log.I("proxy: exit: probe(%s) on %s; err? %v", network, local, err)
	return c, err
}

func (h *exit) Dialer() protect.RDialer {
	return h
}

func (h *exit) ID() string {
	return Exit
}

func (h *exit) Type() string {
	return INTERNET
}

func (h *exit) Router() x.Router {
	return h
}

// Reaches implements x.Router.
func (h *exit) Reaches(hostportOrIPPortCsv string) bool {
	return Reaches(h, hostportOrIPPortCsv)
}

func (h *exit) GetAddr() string {
	return h.addr
}

func (h *exit) Status() int {
	return h.status.Load()
}

func (h *exit) Stop() error {
	h.status.Store(END)
	h.done()
	log.I("proxy: exit: stopped")
	return nil
}

func localDialStatus(status *core.Volatile[int], err error) {
	if status.Load() == END {
		return
	}
	if err != nil {
		status.Store(TKO)
	} else {
		status.Store(TOK)
	}
}
