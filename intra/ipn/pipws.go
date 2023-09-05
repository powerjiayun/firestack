// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ipn

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/core/ipmap"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/intra/split"
	"nhooyr.io/websocket"
)

const (
	writeTimeout time.Duration = 10 * time.Second
)

type pipws struct {
	id       string      // some unique identifier
	url      string      // ws proxy url
	hostname string      // ws proxy hostname
	port     int         // ws proxy port
	ips      ipmap.IPMap // ws proxy working ips
	token    string      // hex, client token
	toksig   string      // hex, authorizer (rdns) signed client token
	rsasig   string      // hex, authorizer unblinded signature
	client   http.Client // ws client
	dialer   *net.Dialer // ws dialer
	status   int         // proxy status: TOK, TKO, END
}

var _ core.TCPConn = &pipwsconn{}

// pipwsconn minimally adapts net.Conn to the core.TCPConn interface
type pipwsconn struct {
	net.Conn
}

func (c *pipwsconn) CloseRead() error  { return c.Close() }
func (c *pipwsconn) CloseWrite() error { return c.Close() }

func (t *pipws) dial(network, addr string) (net.Conn, error) {
	log.D("pipws: dialing %s", addr)
	domain, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	tcpaddr := func(ip net.IP) *net.TCPAddr {
		return &net.TCPAddr{IP: ip, Port: port}
	}

	var conn net.Conn
	ips := t.ips.Get(domain)
	confirmed := ips.Confirmed()
	if confirmed != nil {
		if conn, err = split.DialWithSplitRetry(t.dialer, tcpaddr(confirmed), nil); err == nil {
			log.I("pipws: confirmed IP %s worked", confirmed.String())
			return conn, nil
		}
		log.D("pipws: confirmed IP %s failed with err %v", confirmed.String(), err)
		ips.Disconfirm(confirmed)
	}

	log.D("pipws: trying all IPs")
	for _, ip := range ips.GetAll() {
		if ip.Equal(confirmed) {
			continue
		}
		if conn, err = split.DialWithSplitRetry(t.dialer, tcpaddr(ip), nil); err == nil {
			log.I("pipws: found working IP: %s", ip.String())
			return conn, nil
		}
	}
	return nil, err
}

func (t *pipws) wsconn(rurl, msg string) (c net.Conn, res *http.Response, err error) {
	var ws *websocket.Conn
	ctx := context.Background()
	msgmac := t.claim(msg)
	hdrs := http.Header{}
	hdrs.Set("User-Agent", "")
	if msgmac != nil {
		hdrs.Set("x-nile-pip-claim", msgmac[0])
		hdrs.Set("x-nile-pip-mac", msgmac[1])
		// msg is implicitly hex(sha256(url.Path))
		// hdrs.Set("x-nile-pip-msg", msg)
	}

	log.D("connecting to %s", rurl)

	ws, res, err = websocket.Dial(ctx, rurl, &websocket.DialOptions{
		// compression does not work with Workers
		// CompressionMode: websocket.CompressionNoContextTakeover,
		HTTPClient: &t.client,
		HTTPHeader: hdrs,
	})
	if err != nil {
		log.E("websocket: %v\n", err)
		return
	}

	conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	c = &pipwsconn{conn}
	return
}

func NewPipWsProxy(id string, ctl protect.Controller, po *settings.ProxyOptions) (Proxy, error) {
	parsedurl, err := url.Parse(po.Url())
	if err != nil {
		return nil, err
	}
	// may be "pipws"
	if parsedurl.Scheme != "wss" {
		parsedurl.Scheme = "wss"
	}
	portStr := parsedurl.Port()
	var port int
	if len(portStr) > 0 {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
	} else {
		port = 443
	}

	splitpath := strings.Split(parsedurl.Path, "/")
	// todo: check if the len(rsasig) is 64/128 hex chars?
	if len(splitpath) < 3 {
		return nil, errNoSig
	}
	if splitpath[1] != "ws" {
		return nil, errProxyConfig
	}
	dialer := protect.MakeNsDialer(ctl)
	t := &pipws{
		id:       id,
		url:      parsedurl.String(),
		hostname: parsedurl.Hostname(),
		port:     port,
		dialer:   dialer,
		token:    po.Auth.User,
		toksig:   po.Auth.Password,
		rsasig:   splitpath[2],
		ips:      ipmap.NewIPMap(dialer.Resolver),
		status:   TOK,
	}

	ipset := t.ips.Of(t.hostname, po.Addrs) // po.Addrs may be nil or empty
	if ipset.Empty() {
		log.W("pipws: zero bootstrap ips %s", t.hostname)
	}

	t.client.Transport = &http.Transport{
		Dial:                  t.dial,
		TLSHandshakeTimeout:   writeTimeout,
		ResponseHeaderTimeout: writeTimeout,
	}
	return t, nil
}

func (t *pipws) ID() string {
	return t.id
}

func (t *pipws) Type() string {
	return PIPWS
}

func (t *pipws) GetAddr() string {
	return t.hostname + ":" + strconv.Itoa(t.port)
}

func (t *pipws) Stop() error {
	t.status = END
	return nil
}

func (t *pipws) Status() int {
	return t.status
}

func (h *pipws) Refresh() error { return nil }

// Scenario 4: privacypass.github.io/protocol
func (t *pipws) claim(msg string) []string {
	if len(t.token) == 0 || len(t.toksig) == 0 {
		return nil
	}
	// hmac msg keyed by token's sig
	msgmac := hmac256(hex2byte(msg), hex2byte(t.toksig))
	return []string{t.token, byte2hex(msgmac)}
}

func (t *pipws) Dial(network, addr string) (Conn, error) {
	if t.status == END {
		return nil, errProxyStopped
	}
	if network != "tcp" {
		return nil, errUnexpectedProxy
	}

	u, err := url.Parse(t.url)
	if err != nil {
		return nil, err
	}
	ipp, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}

	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.Path += ipp.Addr().String() + "/" + strconv.Itoa(int(ipp.Port())) + "/" + network

	msg := hexurl(u.Path)
	if err != nil {
		log.E("pipws: nonce err: %v", err)
		return nil, err
	}

	rurl := u.String()
	c, res, err := t.wsconn(rurl, msg)
	if err != nil {
		log.E("pipws: req err: %v", err)
		t.status = TKO
		return nil, err
	}
	if res.StatusCode != 101 {
		log.E("pipws: res not ws %d", res.StatusCode)
		t.status = TKO
		return nil, err
	}

	log.D("pipws: duplex %s", rurl)

	t.status = TOK
	return c, nil
}
