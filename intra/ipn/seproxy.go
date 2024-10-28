// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     SPDX-License-Identifier: MIT
//
//     Copyright (c) 2021 Snawoot

package ipn

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	se "github.com/Snawoot/opera-proxy/seclient"
	x "github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/dialers"
	"github.com/celzero/firestack/intra/ipn/nop"
	"github.com/celzero/firestack/intra/ipn/seasy"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/noql-net/certpool"
	"golang.org/x/net/proxy"
)

// from: https://github.com/Snawoot/opera-proxy/blob/27b3da3004/upstream.go

const (
	protoH1       = "HTTP/1.1"
	methodConnect = "CONNECT"
	hdrHost       = "Host"
	hdrProxyAuthz = "Proxy-Authorization"
	seHostname    = "sec-tunnel.com"
)

var crlf = []byte("\r\n\r\n")

var (
	errSEProxyBlocks   = errors.New("se: remote blocked request")
	errSEProxyResponse = errors.New("se: bad response")
	errSENoEndpoints   = errors.New("se: no endpoints")
	errSEOnlyTcp       = errors.New("se: supports only tcp")
)

type authFn func() (cred string)

type seproxy struct {
	nop.NoFwd
	nop.NoDNS
	nop.SkipRefresh
	nop.ProtoAgnostic
	nop.GW

	addrs     []se.SEIPEntry
	outbounds []proxy.Dialer
	status    *core.Volatile[int]
}

type sedialer struct {
	addr, sni string
	auth      authFn
	cert      *x509.Certificate
	dialer    protect.RDialer
}

var _ Proxy = (*seproxy)(nil)
var _ proxy.Dialer = (*sedialer)(nil)

func NewSEasyProxy(ctx context.Context, c protect.Controller, exit Proxy) (*seproxy, error) {
	sec, endpoints, err := seasy.NewSEasyClient(ctx, exit)
	if err != nil {
		return nil, err
	}
	if len(endpoints) <= 0 {
		return nil, errSENoEndpoints
	}

	authfn := func() string {
		return headerBasicAuth(sec.GetProxyCredentials())
	}

	var missingcert *x509.Certificate
	if der, _ := pem.Decode([]byte(seasy.MISSING_CHAIN_CERT)); der != nil {
		missingcert, _ = x509.ParseCertificate(der.Bytes)
	}

	now := time.Now()
	if missingcert != nil && missingcert.NotAfter.Before(now) {
		log.E("proxy: se: missing cert expired on %s (today: %s)",
			missingcert.NotAfter, now)
		missingcert = nil
	}

	outbound := protect.MakeNsRDial(RpnSE, ctx, c)
	seds := make([]proxy.Dialer, 0)
	for _, ep := range endpoints {
		seds = append(seds, newSEDialer(ep, authfn, missingcert, outbound))
	}

	log.I("proxy: se: started with %d endpoints %v", len(seds), endpoints)

	return &seproxy{
		addrs:     endpoints,
		outbounds: seds,
		status:    core.NewVolatile(TUP),
	}, nil
}

func newSEDialer(ep se.SEIPEntry, auth authFn, x *x509.Certificate, d protect.RDialer) *sedialer {
	return &sedialer{
		addr:   ep.NetAddr(),
		sni:    fmt.Sprintf("%s0.%s", ep.Geo.Country, seHostname),
		auth:   auth,
		cert:   x,
		dialer: d,
	}
}

// Dial implements proxy.Dialer.
func (sed *sedialer) Dial(network, dest string) (conn net.Conn, err error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errSEOnlyTcp
	}

	conn, err = sed.dialer.Dial(network, sed.addr)

	defer func() {
		closif(err)(conn)
	}()

	if err != nil {
		log.E("se: %s err outbound: %v", sed.addr, err)
		return conn, err
	}

	// Verify peer cert chain with missing cert ourselves
	conn = tls.Client(conn, &tls.Config{
		ServerName:         "", // avoid sending sni
		InsecureSkipVerify: true,
		VerifyConnection:   sed.tlsVerify,
	})

	req := &http.Request{
		Method:     methodConnect,
		Proto:      protoH1,
		ProtoMajor: 1,
		ProtoMinor: 1,
		RequestURI: dest,
		Host:       dest,
		Header: http.Header{
			hdrHost: []string{dest},
		},
	}

	// auth is refreshed async; never cache it
	req.Header.Set(hdrProxyAuthz, sed.auth())

	rawreq, err := httputil.DumpRequest(req, false)
	if err != nil {
		return conn, err
	}

	_, err = conn.Write(rawreq)
	if err != nil {
		log.E("se: %s err writing req: %v", sed.addr, err)
		return conn, err
	}

	res, err := readPartial(conn, req)
	if err != nil {
		log.E("se: %s err reading res: %v", sed.addr, err)
		return conn, err
	}

	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusForbidden &&
			res.Header.Get("X-Hola-Error") == "Forbidden Host" {
			return conn, errSEProxyBlocks
		}
		log.E("se: %s bad proxy response: %s", sed.addr, res.Status)
		return conn, errSEProxyResponse
	}

	log.I("se: %s connected to %s (via %s)", sed.sni, dest, sed.addr)

	return conn, nil
}

// github.com/Snawoot/opera-proxy/blob/27b3da3004/upstream.go#L129
func (sed *sedialer) tlsVerify(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) < 2 {
		return nil // no intermediates
	}
	// todo: return nil if sed.cert is nil?
	opts := x509.VerifyOptions{
		DNSName:       sed.sni,
		Intermediates: x509.NewCertPool(),
		Roots:         certpool.Roots(),
	}
	linkNeeded := false
	for _, cert := range cs.PeerCertificates[1:] {
		// add all peer certs except the leaf
		opts.Intermediates.AddCert(cert)
		// add missing cert if it is not already in the chain
		if sed.cert != nil && !linkNeeded {
			linkNeeded = bytes.Equal(cert.AuthorityKeyId, sed.cert.SubjectKeyId)
		}
	}
	// add missing cert if it's needed in the chain
	if linkNeeded {
		opts.Intermediates.AddCert(sed.cert)
	}

	chain, err := cs.PeerCertificates[0].Verify(opts)
	logev(err)("se: %s tls verify (w missing cert? %t); len(chain): %d; err? %v",
		sed.sni, linkNeeded, len(chain), err)
	return err
}

func headerBasicAuth(u, pwd string) string {
	return "Basic " + base64.StdEncoding.EncodeToString(
		[]byte(u+":"+pwd))
}

// readPartial reads http response headers from r into a new http.Response.
func readPartial(r io.Reader, req *http.Request) (*http.Response, error) {
	acc := &bytes.Buffer{} // accumulator
	b := make([]byte, 1)   // one byte at a time
	for {
		n, err := r.Read(b)
		if n < 1 && err == nil {
			continue
		}

		acc.Write(b)
		sl := acc.Bytes()
		if len(sl) < len(crlf) {
			continue
		}

		if bytes.Equal(sl[len(sl)-4:], crlf) {
			break
		}

		if err != nil {
			return nil, err
		}
	}
	return http.ReadResponse(bufio.NewReader(acc), req)
}

// Handle implements Proxy.
func (h *seproxy) Handle() uintptr {
	return core.Loc(h)
}

// ID implements Proxy.
func (*seproxy) ID() string {
	return RpnSE
}

// Type implements Proxy.
func (*seproxy) Type() string {
	return RPN
}

// Router implements Proxy.
func (h *seproxy) Router() x.Router {
	return h
}

// Dial implements Proxy.
func (h *seproxy) Dial(network, addr string) (protect.Conn, error) {
	c, err := dialers.ProxyDials(h.outbounds, network, addr)
	defer localDialStatus(h.status, err)

	if err != nil { // shuffle if any error
		h.outbounds = shuffle(h.outbounds)
	}
	return c, err
}

// DialBind implements Proxy.
func (d *seproxy) DialBind(network, local, remote string) (net.Conn, error) {
	log.D("se: dialbind(%s) from %s to %s not supported", network, local, remote)
	// TODO: error instead?
	return d.Dial(network, remote)
}

// Dialer implements Proxy.
func (d *seproxy) Dialer() protect.RDialer {
	return d
}

// Reaches implements Proxy.
func (h *seproxy) Reaches(hostportOrIPPortCsv string) bool {
	return Reaches(h, hostportOrIPPortCsv)
}

// GetAddr implements Proxy.
func (h *seproxy) GetAddr() string {
	if len(h.addrs) <= 0 {
		return ""
	}
	n := rand.IntN(len(h.addrs))
	return h.addrs[n].NetAddr()
}

func (h *seproxy) Status() int {
	return h.status.Load()
}

func (h *seproxy) Stop() error {
	h.status.Store(END)
	log.I("proxy: se: stopped")
	return nil
}

func closif(err error) func(io.Closer) {
	return func(c io.Closer) {
		if err != nil {
			core.Close(c)
		}
	}
}

func shuffle[T any](a []T) []T {
	rand.Shuffle(len(a), func(i, j int) { a[i], a[j] = a[j], a[i] })
	return a
}
