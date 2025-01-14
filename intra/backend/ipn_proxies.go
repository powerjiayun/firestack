// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

const ( // see ipn/proxies.go
	// nb: Base proxies are Catch-All / fallback proxies
	// IDs for default proxies

	Block   = "Block"       // blocks all traffic
	Base    = "Base"        // does not proxy traffic; in sync w dnsx.NetNoProxy
	Exit    = "Exit"        // always connects to the Internet (exit node); in sync w dnsx.NetExitProxy
	Ingress = "Ingress"     // incoming connections
	Auto    = "Auto"        // auto uses ipn.Exit or any of the RPN proxies
	RpnWg   = WG + RPN      // RPN Warp
	RpnWs   = PIPWS + RPN   // RPN WebSockets
	RpnH2   = PIPH2 + RPN   // RPN HTTP/2
	Rpn64   = NAT64 + RPN   // RPN Exit hopping over NAT64
	RpnSE   = SE + RPN      // RPN SurfEasy
	OrbotS5 = "OrbotSocks5" // Orbot: Base Tor-as-a-SOCKS5 proxy
	OrbotH1 = "OrbotHttp1"  // Orbot: Base Tor-as-a-HTTP/1.1 proxy

	// type of proxies

	SOCKS5   = "socks5" // SOCKS5 proxy
	HTTP1    = "http1"  // HTTP/1.1 proxy
	WG       = "wg"     // WireGuard-as-a-proxy
	WGFAST   = "gsro"   // WireGuard-as-a-proxy w/ UDP GRO/GSO prefix
	PIPH2    = "piph2"  // PIP: HTTP/2 proxy
	PIPWS    = "pipws"  // PIP: WebSockets proxy
	NOOP     = "noop"   // No proxy, ex: Base, Block
	INTERNET = "net"    // egress network, ex: Exit
	RPN      = "rpn"    // Rethink Proxy Network
	NAT64    = "nat64"  // A NAT64 router
	SE       = "se"     // SurfEasy

	// status of proxies

	TNT = 2  // proxy UP but not responding
	TZZ = 1  // proxy idle
	TUP = 0  // proxy UP but not yet OK
	TOK = -1 // proxy OK
	TKO = -2 // proxy not OK
	END = -3 // proxy stopped
)

type Rpn interface {
	// RegisterWarp registers a new Warp public key.
	RegisterWarp(publicKeyBase64 string) (json []byte, err error)
	// RegisterSE registers a new SurfEasy user.
	RegisterSE() error
	// TestWarp connects to some Warp IPs and returns reachable ones.
	TestWarp() (ips string, errs error)
	// TestSE connects to some SurfEasy IPs and returns reachable ones.
	TestSE() (ips string, errs error)
	// Warp returns a RpnWg proxy.
	Warp() (wg Proxy, err error)
	// Pip returns a RpnWs proxy.
	Pip() (ws Proxy, err error)
	// Exit returns the Exit proxy.
	Exit() (exit Proxy, err error)
	// Exit64 returns a Exit proxy hopping over NAT64.
	Exit64() (nat64 Proxy, err error)
	// SE returns a SurfEasy proxy.
	SE() (se Proxy, err error)
}

type Proxy interface {
	// ID returns the ID of this proxy.
	ID() string
	// Type returns the type of this proxy.
	Type() string
	// Returns x.Router.
	Router() Router
	// GetAddr returns the address of this proxy.
	GetAddr() string
	// DNS returns the ip:port or doh/dot url or dnscrypt stamp for this proxy.
	DNS() string
	// Status returns the status of this proxy.
	Status() int
	// Ping pings this proxy.
	Ping() bool
	// Stop stops this proxy.
	Stop() error
	// Refresh re-registers this proxy, if necessary.
	Refresh() error
}

type Proxies interface {
	// Add adds a proxy to this multi-transport.
	AddProxy(id, url string) (Proxy, error)
	// Remove removes a transport from this multi-transport.
	RemoveProxy(id string) bool
	// GetProxy returns a transport from this multi-transport.
	GetProxy(id string) (Proxy, error)
	// Router returns a lowest common denomination router for this multi-transport.
	Router() Router
	// RPN returns the Rethink Proxy Network interface.
	Rpn() Rpn
	// Refresh re-registers proxies and returns a csv of active ones.
	RefreshProxies() (string, error)
}

type Router interface {
	// IP4 returns true if this router supports IPv4.
	IP4() (y bool)
	// IP6 returns true if this router supports IPv6.
	IP6() (y bool)
	// MTU returns the MTU of this router.
	MTU() (mtu int, err error)
	// Stats returns the stats of this router.
	Stat() *RouterStats
	// Reaches returns true if any host:port or ip:port is dialable.
	Reaches(hostportOrIPPortCsv string) (y bool)
	// Contains returns true if this router can route ipprefix.
	Contains(ipprefix string) (y bool)
}

// ProxyListener is a listener for proxy events.
type ProxyListener interface {
	// OnProxyAdded is called when a proxy is added.
	OnProxyAdded(id string)
	// OnProxyRemoved is called when a proxy is removed except when all
	// proxies are stopped, in which case OnProxiesStopped is called.
	OnProxyRemoved(id string)
	// OnProxiesStopped is called when all proxies are stopped.
	// Note: OnProxyRemoved is not called for each proxy.
	OnProxiesStopped()
}

// RouterStats lists interesting stats of a Router.
type RouterStats struct {
	Addr   string // address of the router
	Rx     int64  // bytes received
	Tx     int64  // bytes transmitted
	ErrRx  int64  // receive errors
	ErrTx  int64  // transmit errors
	LastRx int64  // last receive in millis
	LastTx int64  // last transmit in millis
	LastOK int64  // last handshake or ping or connect millis
	Since  int64  // uptime in millis
}
