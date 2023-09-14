// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dnsx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

const (
	// DNS transport types
	DOH      = "DNS-over-HTTPS"
	DNSCrypt = "DNSCrypt"
	DNS53    = "DNS"
	DOT      = "DNS-over-TLS"
	ODOH     = "Oblivious DNS-over-HTTPS"

	CT = "Cache" // cached transport prefix

	// special singleton DNS transports (IDs)
	System    = "System"    // network/os provided dns
	Local     = "mdns"      // mdns
	Default   = "Default"   // default (fallback) dns
	Preferred = "Preferred" // user preferred dns, primary for alg
	BlockFree = "BlockFree" // no local blocks; if not set, default is used
	BlockAll  = "BlockAll"  // all blocks
	Alg       = "Alg"       // dns application-level gateway
	DcProxy   = "DcProxy"   // dnscrypt.Proxy as a transport

	invalidQname = "invalid.query"

	// preferred network to use with t.Query
	NetTypeUDP = "udp"
	NetTypeTCP = "tcp"

	ttl10m = 10 * time.Minute // 10m ttl

	// pseudo transport ID to tag dns64 responses
	d64prefix = "d64."
)

var (
	ErrNoDcProxy           = errors.New("no dnscrypt-proxy")
	errNoSuchTransport     = errors.New("missing transport")
	errBlockFreeTransport  = errors.New("block free transport")
	errNoRdns              = errors.New("no rdns")
	errRdnsLocalIncorrect  = errors.New("rdns local is not remote")
	errRdnsRemoteIncorrect = errors.New("rdns remote is not local")
	errTransportNotMult    = errors.New("not a multi-transport")
	errMissingQueryName    = errors.New("no query name")
)

// Transport represents a DNS query transport.  This interface is exported by gobind,
// so it has to be very simple.
type Transport interface {
	// uniquely identifies this transport
	ID() string
	// one of DNS53, DOH, DNSCrypt, System
	Type() string
	// Given a DNS query (including ID), returns a DNS response with matching
	// ID, or an error if no response was received.  The error may be accompanied
	// by a SERVFAIL response if appropriate.
	Query(network string, q []byte, summary *Summary) ([]byte, error)
	// Median round-trip time for this transport, in millis.
	P50() int64
	// Return the server host address used to initialize this transport.
	GetAddr() string
	// State of the transport after previous query (see: queryerror.go)
	Status() int
}

// TransportMult is a hybrid: transport and a multi-transport.
type TransportMult interface {
	Mult
	Transport
}

type Mult interface {
	// Add adds a transport to this multi-transport.
	Add(t Transport) bool
	// Remove removes a transport from this multi-transport.
	Remove(id string) bool
	// Start starts a multi-transport, returns number of live-servers and errors if any.
	Start() (string, error)
	// Get returns a transport from this multi-transport.
	Get(id string) (Transport, error)
	// Stop stops this multi-transport.
	Stop() error
	// Refresh re-registers transports and returns a csv of active ones.
	Refresh() (string, error)
	// LiveTransports returns a csv of active transports.
	LiveTransports() string
}

type Resolver interface {
	Mult
	RdnsResolver

	AddSystemDNS(t Transport) bool
	RemoveSystemDNS() int

	// special purpose pre-defined transports
	// Gateway implements a DNS ALG transport
	Gateway() Gateway
	// GetMult returns multi-transport, if available
	GetMult(id string) (TransportMult, error)

	IsDnsAddr(network, ipport string) bool
	Forward(q []byte) ([]byte, error)
	Serve(conn ipn.Conn)
}

type resolver struct {
	sync.RWMutex
	Resolver
	tunmode      *settings.TunMode
	tcpaddrs     []*net.TCPAddr
	udpaddrs     []*net.UDPAddr
	systemdns    []Transport
	transports   map[string]Transport
	pool         map[string]*oneTransport
	localdomains RadixTree
	rdnsl        BraveDNS
	rdnsr        BraveDNS
	natpt        ipn.DNS64
	listener     Listener
}

type oneTransport struct {
	ipn.Resolver
	t Transport
}

func NewResolver(fakeaddrs string, defaultdns Transport, tunmode *settings.TunMode, l Listener, pt ipn.DNS64) Resolver {
	r := &resolver{
		listener:     l,
		natpt:        pt,
		transports:   make(map[string]Transport),
		pool:         make(map[string]*oneTransport),
		tunmode:      tunmode,
		localdomains: newUndelegatedDomainsTrie(),
		systemdns:    make([]Transport, 0),
	}
	ok1 := r.Add(defaultdns)
	ok2 := r.Add(NewDNSGateway(defaultdns, r))

	log.I("dns: new! default? %t, gw? %t", ok1, ok2)
	r.loadaddrs(fakeaddrs)
	return r
}

func (r *resolver) Gateway() Gateway {
	r.RLock()
	defer r.RUnlock()

	if gw, ok := r.transports[Alg]; ok {
		return gw.(Gateway)
	}
	return nil
}

// Implements ipn.Exchange
func (one *oneTransport) Exchange(q []byte) (r []byte, err error) {
	ans1, err1 := one.t.Query(NetTypeUDP, q, &Summary{})
	if err1 != nil {
		return ans1, err1
	}
	// for odoh/dot/doh, dns ans is never truncated
	if one.t.Type() == DOH || one.t.Type() == ODOH || one.t.Type() == DOT {
		return ans1, err1
	}

	msg1 := &dns.Msg{}
	err1 = msg1.Unpack(ans1)
	if err != nil {
		return ans1, err1
	}
	if !msg1.Truncated {
		return ans1, err1
	}

	// else if: returned response is truncated dns ans, retry over tcp
	return one.t.Query(NetTypeTCP, q, &Summary{})
}

// Implements RdnsResolver
func (r *resolver) SetRdnsLocal(b BraveDNS) error {
	if b == nil {
		r.rdnsl = nil
	} else if b.OnDeviceBlock() {
		r.rdnsl = b
	} else {
		return errRdnsLocalIncorrect
	}
	return nil
}

// Implements RdnsResolver
func (r *resolver) SetRdnsRemote(b BraveDNS) error {
	if b == nil {
		r.rdnsr = nil
	} else if !b.OnDeviceBlock() {
		r.rdnsr = b
	} else {
		return errRdnsRemoteIncorrect
	}
	return nil
}

// Implements RdnsResolver
func (r *resolver) GetRdnsLocal() BraveDNS {
	return r.rdnsl
}

// Implements RdnsResolver
func (r *resolver) GetRdnsRemote() BraveDNS {
	return r.rdnsr
}

func (r *resolver) AddSystemDNS(t Transport) bool {
	defer r.addSystemDnsIfAbsent(t)
	r.Lock()
	r.systemdns = append(r.systemdns, t)
	r.Unlock()
	return true
}

func (r *resolver) RemoveSystemDNS() int {
	defer r.Remove(System)
	r.Lock()
	d := len(r.systemdns)
	r.systemdns = make([]Transport, 0)
	r.Unlock()

	return d
}

// Implements Resolver
func (r *resolver) Add(t Transport) (ok bool) {
	if t == nil {
		return false
	}

	switch t.Type() {
	case DNS53, DNSCrypt, DOH, DOT, ODOH:
		// DNSCrypt transports are also registered with DcProxy
		// Alg transports are also registered with Gateway
		// Remove cleans those up
		r.Remove(t.ID())

		// these IDs are reserved for internal use
		if isReserved(t.ID()) {
			log.I("dns: updating reserved transport %s@%s", t.ID(), t.GetAddr())
		}

		ct := NewCachingTransport(t, ttl10m)
		onet := &oneTransport{t: t}
		ctonet := &oneTransport{t: ct}

		r.Lock()
		// regular transports
		r.transports[t.ID()] = t
		r.pool[t.ID()] = onet
		// cached transports
		r.transports[ct.ID()] = ct
		r.pool[ct.ID()] = ctonet
		r.Unlock()

		log.I("dns: add transport %s@%s", t.ID(), t.GetAddr())

		// if resetting default transport, update underlying transport for alg
		if gw := r.Gateway(); (t.ID() == Preferred || t.ID() == BlockFree) && gw != nil {
			gw.withTransport(t)
		} else {
			log.D("dns: no gw? %t / not blkfree/preffered %s@%s", gw == nil, t.ID(), t.GetAddr())
		}
		return true
	default:
		log.E("dns: unknown transport(%s) type: %s", t.ID(), t.Type())
	}
	return false
}

func (r *resolver) GetMult(id string) (TransportMult, error) {
	r.RLock()
	defer r.RUnlock()

	if t, ok := r.transports[id]; ok {
		if tm, ok := t.(TransportMult); ok {
			return tm, nil
		}
		return nil, errTransportNotMult
	}
	return nil, errNoSuchTransport
}

func (r *resolver) dcProxy() (TransportMult, error) {
	return r.GetMult(DcProxy)
}

func (r *resolver) addSystemDnsIfAbsent(t Transport) (ok bool) {
	r.RLock()
	_, ok = r.transports[t.ID()]
	r.RUnlock()
	if !ok {
		// r.Add before r.registerSystemDns64, since r.pool must be populated
		ok = r.Add(t)
		go r.registerSystemDns64(r.pool[t.ID()])
	}
	return ok
}

func (r *resolver) registerSystemDns64(ur ipn.Resolver) (ok bool) {
	return r.natpt.AddResolver(ipn.UnderlayResolver, ur)
}

func (r *resolver) Get(id string) (Transport, error) {
	if t, _ := r.determineTransports(id); t == nil {
		return nil, errNoSuchTransport
	} else {
		return t, nil
	}
}

func (r *resolver) Remove(id string) (ok bool) {

	// these IDs are reserved for internal use
	if isReserved(id) {
		log.I("dns: removing reserved transport %s", id)
	}

	ctid := CT + id
	var ok1, ok2 bool
	var t Transport

	r.Lock()
	if t, ok1 = r.transports[id]; ok1 {
		delete(r.transports, id)
		delete(r.transports, ctid)
	}
	if _, ok2 = r.pool[id]; ok2 {
		delete(r.pool, id)
		delete(r.pool, ctid)
	}
	r.Unlock()

	if tm, err := r.dcProxy(); err == nil {
		tm.Remove(id)
		tm.Remove(ctid)
	}
	if gw := r.Gateway(); gw != nil {
		gw.withoutTransport(t)
	}

	ok = ok1 || ok2
	if ok {
		log.I("dns: remove(%t) transport %s@%s", ok, t.ID(), t.GetAddr())
	} else {
		log.I("dns: remove(%t) transport %s", ok, id)
	}
	return
}

func (r *resolver) IsDnsAddr(network, ipport string) bool {
	if len(ipport) <= 0 {
		return false
	}
	return r.isDns(network, ipport)
}

func (r *resolver) Forward(q []byte) ([]byte, error) {
	var gw Gateway
	starttime := time.Now()
	summary := &Summary{
		QName:  invalidQname,
		Status: Start,
	}
	// always call up to the listener
	defer func() {
		go r.listener.OnResponse(summary)
	}()

	msg, err := unpack(q)
	if err != nil {
		log.W("dns: not a dns packet %v", err)
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = BadQuery
		return nil, err
	}

	// figure out transport to use
	qname := qname(msg)
	qtyp := qtype(msg)
	summary.QName = qname
	summary.QType = qtyp
	id := r.requiresSystemOrLocal(qname)
	sid := ""
	if len(id) > 0 {
		log.I("dns: udp: suggest dns(%s) for %s", id, qname)
	}
	pref := r.listener.OnQuery(qname, qtyp, id)
	id, sid, _ = preferencesFrom(pref)
	t, onet := r.determineTransports(id)
	if t == nil || onet == nil {
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = TransportError
		return nil, errNoSuchTransport
	}
	var t2 Transport
	if len(sid) > 0 {
		t2, _ = r.determineTransports(sid)
	}

	if t.ID() == Alg { // also: Local?
		gw = nil // transport implicitly implements Gateway
	} else {
		gw = r.Gateway()
	}

	// block skipped if the transport is alg/block-free
	res1, blocklists, err := r.blockQ(t, t2, msg)
	if err == nil {
		b, e := res1.Pack()
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = Complete
		summary.Blocklists = blocklists
		summary.RData = xdns.GetInterestingRData(res1)
		log.V("dns: udp: query blocked %s by %s", qname, blocklists)
		return b, e
	} else {
		log.V("dns: udp: query NOT blocked %s; why? %v", qname, err)
	}

	summary.Type = t.Type()
	summary.ID = t.ID()
	var res2 []byte
	// query explicitly via the gateway gw, if present;
	// or use transport t, which could be Gateway's impl of Transport
	if gw == nil {
		res2, err = t.Query(NetTypeUDP, q, summary)
	} else { // with t2 as the secondary transport, which could be nil
		res2, err = gw.q(t, t2, NetTypeUDP, q, summary)
	}

	algerr := isAlgErr(err) // not set when gw.translate is off
	if algerr {
		log.W("dns: udp: alg error %s for %s", err, qname)
	}
	// in the case of an alg transport, if there's no-alg,
	// err is set which should be ignored if res2 is not nil
	if err != nil && !algerr {
		// summary latency, ips, response, status already set by transport t
		return res2, err
	}
	ans1, err := unpack(res2)
	if err != nil {
		summary.Status = BadResponse
		return res2, err
	}
	answerblocked := false
	ans2, blocklistnames := r.blockA(t, t2, msg, ans1, summary.Blocklists)
	if len(blocklistnames) > 0 {
		// summary latency, response, status, ips also set by transport t
		summary.Status = Complete
		summary.Blocklists = blocklistnames
		summary.RData = xdns.GetInterestingRData(ans2)
		log.V("dns: udp: answer blocked %s by %s", qname, blocklistnames)
	}

	// overwrite response when blocked
	if ans2 != nil {
		ans1 = ans2
		answerblocked = true
	} else {
		log.V("dns: udp: answer NOT blocked %s", qname)
	}

	if onet != nil {
		if !answerblocked {
			d64 := r.natpt.D64(t.ID(), res2, onet)
			if len(d64) >= xdns.MinDNSPacketSize {
				r.withDNS64SummaryIfNeeded(d64, summary)
				return d64, nil
			} // else: d64 is nil on no D64 or error
		} // else: answer is blocked, no dns64
	} else {
		log.D("dns: dns64: missing onetransport for %s", t.ID())
	}

	return ans1.Pack()
}

func (r *resolver) Serve(x ipn.Conn) {
	if c, ok := x.(io.ReadWriteCloser); ok {
		r.accept(c)
	}
}

func (r *resolver) withDNS64SummaryIfNeeded(d64 []byte, s *Summary) {
	if !settings.Debug {
		return
	}
	msg, err := unpack(d64)
	if err != nil {
		return // should not happen
	}
	// append dns64 rdata to summary
	if rdata := xdns.GetInterestingRData(msg); len(rdata) > 0 {
		if len(s.RData) > 0 {
			s.RData = s.RData + "," + rdata
		} else {
			s.RData = rdata
		}
	}
	if len(s.Server) > 0 {
		s.Server = d64prefix + s.Server
	}

}

func (r *resolver) determineTransports(id string) (Transport, *oneTransport) {
	r.RLock()
	defer r.RUnlock()

	if id == Local { // mdns never cached
		return r.transports[Local], r.pool[Local]
	}

	if id == Alg {
		// if no firewall is setup, alg isn't possible
		if r.tunmode.BlockMode == settings.BlockModeNone {
			return r.transports[CT+Default], r.pool[CT+Default]
		}
		return r.transports[Alg], r.pool[CT+Preferred]
	}

	if t, ok := r.transports[id]; ok {
		if onet, ok := r.pool[id]; ok {
			return t, onet
		}
	}

	// if none of the reserved transports are available, use the default
	if isReserved(id) {
		return r.transports[CT+Default], r.pool[CT+Default]
	}

	return nil, nil
}

// Perform a query using the transport, and send the response to the writer.
func (r *resolver) forwardQuery(q []byte, c io.Writer) error {
	var gw Gateway
	starttime := time.Now()
	summary := &Summary{
		QName:  invalidQname,
		Status: Start,
	}
	// always call up to the listener
	defer func() {
		go r.listener.OnResponse(summary)
	}()

	msg, err := unpack(q)
	if err != nil {
		log.W("dns: not a valid packet %v", err)
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = BadQuery
		return err
	}

	// figure out transport to use
	qname := qname(msg)
	qtyp := qtype(msg)
	summary.QName = qname
	summary.QType = qtyp
	id := r.requiresSystemOrLocal(qname)
	sid := ""
	if len(id) > 0 {
		log.I("dns: tcp: suggest system-dns %s for %s", id, qname)
	}
	pref := r.listener.OnQuery(qname, qtyp, id)
	id, sid, _ = preferencesFrom(pref)
	// retrieve transport
	t, onet := r.determineTransports(id)
	if t == nil || onet == nil {
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = TransportError
		return errNoSuchTransport
	}
	var t2 Transport = nil
	if len(sid) > 0 {
		t2, _ = r.determineTransports(sid)
	}
	if t.ID() == Alg { // also: Local?
		gw = nil // transport implicitly implements Gateway
	} else {
		gw = r.Gateway()
	}

	// block query if needed (skipped for alg/block-free)
	res1, blocklists, err := r.blockQ(t, t2, msg)
	if err == nil {
		b, e := res1.Pack()
		summary.Latency = time.Since(starttime).Seconds()
		summary.Status = Complete
		summary.Blocklists = blocklists
		summary.RData = xdns.GetInterestingRData(res1)
		writeto(c, b, len(b))
		log.V("dns: udp: query blocked %s by %s", qname, blocklists)
		return e
	} else {
		log.V("dns: tcp: query NOT blocked %s; why? %v", qname, err)
	}

	summary.Type = t.Type()
	summary.ID = t.ID()
	var res2 []byte
	// query explicitly via the gateway gw, if present;
	// or use transport t, which could be Gateway's impl of Transport
	if gw == nil {
		res2, err = t.Query(NetTypeTCP, q, summary)
	} else { // with t2 as the secondary transport, which could be nil
		res2, err = gw.q(t, t2, NetTypeTCP, q, summary)
	}

	algerr := isAlgErr(err) // not set when gw.translate is off
	if algerr {
		log.W("dns: tcp: alg error %s for %s", err, qname)
	}
	// in the case of an alg transport, if there's no-alg,
	// err is set which should be ignored if res2 is not nil
	if err != nil && !algerr {
		// summary latency, ips, response, status already set by transport t
		return err
	}
	ans1, qerr := unpack(res2)
	if qerr != nil {
		summary.Status = BadResponse
		return qerr
	}

	answerblocked := false
	ans2, blocklistnames := r.blockA(t, t2, msg, ans1, summary.Blocklists)
	// overwrite response when blocked
	if len(blocklistnames) > 0 {
		// summary latency, response, status, ips also set by transport t
		summary.Status = Complete
		summary.Blocklists = blocklistnames
		summary.RData = xdns.GetInterestingRData(ans2)
		log.V("dns: tcp: answer blocked %s by %s", qname, blocklistnames)
	}
	// overwrite response when blocked
	if ans2 != nil {
		ans1 = ans2
		answerblocked = true
	} else {
		log.V("dns: tcp: answer NOT blocked %s", qname)
	}

	resp, qerr := ans1.Pack()
	if qerr != nil {
		summary.Status = BadResponse
		return qerr
	}
	if len(resp) > xdns.MaxDNSPacketSize {
		summary.Status = BadResponse
		return fmt.Errorf("dns: tcp: oversize response: %d", len(resp))
	}

	// override original resp with dns64 if needed
	if onet != nil {
		if !answerblocked {
			d64 := r.natpt.D64(t.ID(), res2, onet)
			if len(d64) > xdns.MinDNSPacketSize {
				r.withDNS64SummaryIfNeeded(d64, summary)
				resp = d64
			} // else: d64 is nil on no D64 or error
		} // else answer is blocked, no dns64
	} else {
		log.D("dns: dns64: missing onetransport for %s", t.ID())
	}

	rlen := len(resp)
	n, err := writeto(c, resp, rlen)
	if err != nil {
		summary.Status = InternalError
		return err
	}
	if n != rlen {
		summary.Status = InternalError
		return fmt.Errorf("dns: incomplete write: n(%d) != r(%d)", n, rlen)
	}
	return qerr
}

// Perform a query using the transport, send the response to the writer,
// and close the writer if there was an error.
func (r *resolver) forwardQueryAndCheck(q []byte, c io.WriteCloser) {
	if err := r.forwardQuery(q, c); err != nil {
		log.W("dns: query forwarding err: %v", err)
		c.Close()
	}
}

// Accept a DNS-over-TCP socket from a stub resolver, and connect the socket
// to this DNSTransport.
func (r *resolver) accept(c io.ReadWriteCloser) {
	defer c.Close()

	qlbuf := make([]byte, 2)
	for {
		n, err := c.Read(qlbuf)
		if n == 0 {
			log.D("dns: tcp: query socket shutdown")
			break
		}
		if err != nil {
			log.W("dns: tcp: err reading from socket: %v", err)
			break
		}
		// TODO: inform the listener?
		if n < 2 {
			log.W("dns: tcp: incomplete query length")
			break
		}
		qlen := binary.BigEndian.Uint16(qlbuf)
		q := make([]byte, qlen)
		n, err = c.Read(q)
		if err != nil {
			log.W("dns: tcp: err reading query: %v", err)
			break
		}
		if n != int(qlen) {
			log.W("dns: tcp: incomplete query: %d < %d", n, qlen)
			break
		}
		go r.forwardQueryAndCheck(q, c)
	}
	// TODO: Cancel outstanding queries.
}

func isReserved(id string) (ok bool) {
	return id == Alg || id == DcProxy || id == BlockAll || id == Preferred || id == BlockFree || id == System
}

func unpack(q []byte) (*dns.Msg, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(q)
	return msg, err
}

func qname(msg *dns.Msg) string {
	n := xdns.QName(msg)
	n, _ = xdns.NormalizeQName(n)
	return n
}

func qtype(msg *dns.Msg) int {
	return int(xdns.QType(msg))
}

func (r *resolver) loadaddrs(csvaddr string) {
	r.fakeTcpAddr(csvaddr)
	r.fakeUdpAddr(csvaddr)
}

func writeto(w io.Writer, b []byte, l int) (int, error) {
	prependsz := 2
	rlbuf := make([]byte, l+prependsz)
	binary.BigEndian.PutUint16(rlbuf, uint16(l))
	copy(rlbuf[prependsz:], b)
	// Use a combined write to ensure atomicity.
	// Otherwise, writes from two responses could be interleaved.
	n, err := w.Write(rlbuf)
	return max(0, n-prependsz), err
}

func (r *resolver) Start() (string, error) {
	if dc, err := r.dcProxy(); err == nil {
		return dc.Start()
	}
	return "", ErrNoDcProxy
}

func (r *resolver) Stop() error {
	if gw := r.Gateway(); gw != nil {
		gw.stop()
	}
	if dc, err := r.dcProxy(); err == nil {
		return dc.Stop()
	}
	// nothing to stop / no error
	return nil
}

func (r *resolver) refresh() {
	r.RLock()
	defer r.RUnlock()

	for _, t := range r.transports {
		// re-adding creates NEW cached transports
		// which is akin to a cache flush
		go r.Add(t)
	}
}

func (r *resolver) Refresh() (string, error) {
	go r.refresh()
	s := map2csv(r.transports)
	if dc, err := r.dcProxy(); err == nil {
		if x, err := dc.Refresh(); err == nil {
			s += "," + x
		}
	}
	return trimcsv(s), nil
}

func (r *resolver) LiveTransports() string {
	s := map2csv(r.transports)
	if dc, err := r.dcProxy(); err == nil {
		x := dc.LiveTransports()
		if len(x) > 0 {
			s += x
		}
	}
	return trimcsv(s)
}

func preferencesFrom(s string) (id1, id2, ips string) {
	x := strings.Split(s, ",")
	l := len(x)
	if l <= 0 { // cannot happen
		// no-op
	} else if l == 1 {
		id1 = x[0] // id for transport t1
	} else if l == 2 {
		id1, id2 = x[0], x[1] // ids for transport t1, t2
	} else if l >= 3 {
		id1, id2, ips = x[0], x[1], x[2] // ids for transport t1, t2; preferred IP
	}
	return
}

func map2csv(ts map[string]Transport) string {
	s := ""
	for _, t := range ts {
		s += t.ID() + ","
	}
	return trimcsv(s)
}

func trimcsv(s string) string {
	return strings.Trim(s, ",")
}
