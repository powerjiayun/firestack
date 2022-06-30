// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    ISC License
//
//    Copyright (c) 2018-2021
//    Frank Denis <j at pureftpd dot org>

package dnscrypt

import (
	"context"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/celzero/firestack/intra/dnsx"
	"github.com/celzero/firestack/intra/ipn"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/xdns"

	clocksmith "github.com/jedisct1/go-clocksmith"
	stamps "github.com/jedisct1/go-dnsstamps"
	"github.com/k-sone/critbitgo"
	"golang.org/x/crypto/curve25519"
)

// Controller represents an dnscrypt session.
type Controller interface {
	// StartProxy starts a dnscrypt proxy, returns number of live-servers and errors if any.
	StartProxy() (string, error)
	// StopProxy stops the dnscrypt proxy
	StopProxy() error
	// Refresh registers servers.
	Refresh() (int, error)
	// AddServers adds new dns-crypt resolvers given csv-separated list of "unqiue-id#dns-stamp"
	AddServers(string) (int, error)
	// RemoveServers removes existing dns-crypt resolvers given csv-separated list of "unqiue-id"s
	RemoveServers(string) (int, error)
	// AddRoutes adds new dns-crypt relay given csv-separated list of "dns-stamp"
	AddRoutes(string) (int, error)
	// RemoveRoutes removes existing dns-crypt relays given csv-separated list of "dns-stamp"
	RemoveRoutes(string) (int, error)
	// LiveServers returns a csv of currently in-use dnscrypt-server names
	LiveServers() string
}

type Proxy struct {
	Controller
	sync.RWMutex
	undelegatedSet               *critbitgo.Trie
	proxyPublicKey               [32]byte
	proxySecretKey               [32]byte
	serversInfo                  ServersInfo
	timeout                      time.Duration
	certRefreshDelay             time.Duration
	certRefreshDelayAfterFailure time.Duration
	certIgnoreTimestamp          bool
	mainProto                    string
	registeredServers            map[string]RegisteredServer
	registeredRelays             []RegisteredServer
	routes                       []string
	quit                         chan bool
	listener                     dnsx.Listener
	liveServers                  []string
	sigterm                      context.CancelFunc
	bravedns                     dnsx.BraveDNS
	natpt                        ipn.NatPt
}

func (proxy *Proxy) exchangeWithTCPServer(serverInfo *ServerInfo, sharedKey *[32]byte, encryptedQuery []byte, clientNonce []byte) ([]byte, error) {
	upstreamAddr := serverInfo.TCPAddr
	if serverInfo.RelayTCPAddr != nil {
		upstreamAddr = serverInfo.RelayTCPAddr
	}
	var pc net.Conn
	pc, err := net.DialTCP("tcp", nil, upstreamAddr)
	if err != nil {
		log.Errorf("failed to dial %s upstream because %v", serverInfo.String(), err)
		return nil, err
	}
	defer pc.Close()
	if err := pc.SetDeadline(time.Now().Add(serverInfo.Timeout)); err != nil {
		log.Errorf("failed to set timeout because %v", err)
		return nil, err
	}
	if serverInfo.RelayTCPAddr != nil {
		proxy.prepareForRelay(serverInfo.TCPAddr.IP, serverInfo.TCPAddr.Port, &encryptedQuery)
	}
	encryptedQuery, err = xdns.PrefixWithSize(encryptedQuery)
	if err != nil {
		log.Errorf("failed prefix(encrypted-query) from %s because %v", serverInfo.String(), err)
		return nil, err
	}
	if _, err := pc.Write(encryptedQuery); err != nil {
		log.Errorf("failed to write to remote-addr at %s because %v", serverInfo.String(), err)
		return nil, err
	}
	encryptedResponse, err := xdns.ReadPrefixed(&pc)
	if err != nil {
		log.Errorf("failed to read(encrypted-response) from %s because %v", serverInfo.String(), err)
		return nil, err
	}
	return proxy.Decrypt(serverInfo, sharedKey, encryptedResponse, clientNonce)
}

func (proxy *Proxy) prepareForRelay(ip net.IP, port int, encryptedQuery *[]byte) {
	anonymizedDNSHeader := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00}
	relayedQuery := append(anonymizedDNSHeader, ip.To16()...)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[0:2], uint16(port))
	relayedQuery = append(relayedQuery, tmp[:]...)
	relayedQuery = append(relayedQuery, *encryptedQuery...)
	*encryptedQuery = relayedQuery
}

func (proxy *Proxy) query(q []byte, trunc bool) (r []byte, blocklists string, s *ServerInfo, qerr error) {
	return proxy.queryServer(q, trunc, nil)
}

func (proxy *Proxy) queryServer(packet []byte, truncate bool, preferredServer *ServerInfo) (response []byte, blocklists string, serverInfo *ServerInfo, qerr error) {
	if len(packet) < xdns.MinDNSPacketSize {
		log.Warnf("DNS query size too short, cannot process dns-crypt query.")
		qerr = dnsx.NewBadQueryError(fmt.Errorf("dns-crypt query size too short"))
		return
	}

	intercept := NewIntercept(proxy.undelegatedSet, proxy.bravedns)
	// serverName := "-"
	// needsEDNS0Padding = (serverInfo.Proto == stamps.StampProtoTypeDoH || serverInfo.Proto == stamps.StampProtoTypeTLS)
	needsEDNS0Padding := false

	query, err := intercept.HandleRequest(packet, needsEDNS0Padding)
	state := intercept.state

	saction := state.action
	sr := state.response
	blocklists = state.blocklists
	if err != nil || saction == ActionDrop {
		log.Errorf("ActionDrop or err on request %w", err)
		qerr = dnsx.NewBadQueryError(err)
		return
	}
	if saction == ActionSynth {
		if sr != nil {
			log.Debugf("send intercepted synth response")
			response, err = sr.PackBuffer(response)
			// XXX: when the query is blocked and pack-buffer fails
			// doh falls back to forwarding the query instead.
			if err != nil {
				qerr = dnsx.NewBadResponseQueryError(err)
			}
			return
		}
		log.Warnf("missing synth response, forwarding query...")
	}
	if len(query) < xdns.MinDNSPacketSize {
		err = errors.New("dns query size too short, drop dns-crypt query")
		qerr = dnsx.NewBadQueryError(err)
		return
	}
	if len(query) > xdns.MaxDNSPacketSize {
		err = errors.New("dns query size too large, drop dns-crypt query")
		qerr = dnsx.NewBadQueryError(err)
		return
	}

	if preferredServer == nil {
		serverInfo = proxy.serversInfo.getOne()
	} else {
		serverInfo = preferredServer
	}

	if serverInfo == nil {
		err = errors.New("server-info nil, drop dns-crypt query")
		qerr = dnsx.NewInternalQueryError(err)
		return
	}

	if serverInfo.Proto == stamps.StampProtoTypeDNSCrypt {
		sharedKey, encryptedQuery, clientNonce, err := proxy.Encrypt(serverInfo, query, proxy.mainProto)

		if err != nil {
			log.Warnf("Encryption failure with dns-crypt query to %s.", serverInfo.String())
			qerr = dnsx.NewInternalQueryError(err)
			return
		}

		response, err = proxy.exchangeWithTCPServer(serverInfo, sharedKey, encryptedQuery, clientNonce)

		if err != nil {
			log.Warnf("dns crypt query exchange with %s failed: %v", serverInfo.String(), err)
			qerr = dnsx.NewSendFailedQueryError(err)
			return
		}
	} else if serverInfo.Proto == stamps.StampProtoTypeDoH {
		// FIXME: implement
		log.Errorf("Unsupported dns-crypt transport protocol")
		qerr = dnsx.NewSendFailedQueryError(errors.New("doh not supported with dns-crypt proxy"))
		return
	} else {
		log.Errorf("Unsupported dns-crypt transport protocol")
		qerr = dnsx.NewTransportQueryError(fmt.Errorf("dns-crypt: unknown protocol"))
		return
	}

	if len(response) < xdns.MinDNSPacketSize || len(response) > xdns.MaxDNSPacketSize {
		log.Errorf("response packet size from %s too small or too large", serverInfo.String())
		qerr = dnsx.NewBadResponseQueryError(errors.New("response packet size too small or too big"))
		return
	}

	response, err = intercept.HandleResponse(response, truncate)

	if err != nil {
		log.Errorf("failed to intercept %s response %w", serverInfo.String(), err)
		qerr = dnsx.NewBadResponseQueryError(err)
		return
	}

	if state.action == ActionSynth && state.response != nil {
		blocklists = state.blocklists // refresh blocklists
		response, err = state.response.PackBuffer(response)
		// XXX: when the query is blocked and pack-buffer fails doh falls
		// back to forwarding the query instead, but here we don't.
		if err != nil {
			qerr = dnsx.NewBadResponseQueryError(err)
		}
		return
	}

	return
}

// HandleUDP handles incoming udp connection speaking plain old DNS
func HandleUDP(proxy *Proxy, data []byte) (response []byte, err error) {
	if proxy == nil {
		return nil, fmt.Errorf("dnscrypt proxy not set")
	}

	before := time.Now()
	response, b, s, err := proxy.query(data, true)
	after := time.Now()
	if len(b) <= 0 && err == nil && proxy.natpt != nil {
		response = proxy.natpt.D64(s.Name, response, proxy.ExchangeWith(s))
	}

	if proxy.listener != nil {
		latency := after.Sub(before)
		status := dnsx.Complete

		var resolver string
		var relay string
		if s != nil {
			resolver = s.TCPAddr.IP.String()
			if s.RelayTCPAddr != nil {
				relay = s.RelayTCPAddr.IP.String()
			}
		}

		var qerr *dnsx.QueryError
		if errors.As(err, &qerr) {
			status = qerr.Status()
		}

		proxy.listener.OnResponse(&dnsx.Summary{
			Type:        dnsx.DNSCrypt,
			Latency:     latency.Seconds(),
			Query:       data,
			Response:    response,
			Server:      resolver,
			RelayServer: relay,
			Status:      status,
			Blocklists:  b,
		})
	}

	return response, err
}

func (proxy *Proxy) forward(conn net.Conn) (q []byte, response []byte, blocklists string, serverInfo *ServerInfo, err error) {

	// Unlike Intra's handling of DoH (?), DNSCrypt strictly closes
	// connection after a single read-response cycle.
	if err = conn.SetDeadline(time.Now().Add(proxy.timeout)); err != nil {
		q, err = xdns.ReadPrefixed(&conn)
	}
	if err != nil {
		log.Errorf("could not read dns query %v", err)
		return
	}

	response, blocklists, serverInfo, err = proxy.query(q, false)

	if err != nil {
		log.Errorf("failed forwarding dnscrypt query %w", err)
		return
	}
	response, err = xdns.PrefixWithSize(response)
	if err != nil {
		log.Errorf("failed reading answer for dnscrypt query %w", err)
	}
	return
}

// HandleTCP handles incoming tcp connection speaking plain old DNS
func HandleTCP(proxy *Proxy, conn net.Conn) {
	defer conn.Close()

	if proxy == nil {
		log.Errorf("dnscrypt proxy not set")
		return
	}

	before := time.Now()
	query, response, b, s, err := proxy.forward(conn)
	after := time.Now()
	if len(b) <= 0 && err == nil && proxy.natpt != nil {
		response = proxy.natpt.D64(s.Name, response, proxy.ExchangeWith(s))
	}

	if proxy.listener != nil {
		latency := after.Sub(before)
		status := dnsx.Complete

		var resolver string
		var relay string
		if s != nil {
			resolver = s.TCPAddr.IP.String()
			relay = s.RelayTCPAddr.IP.String()
		}

		var qerr *dnsx.QueryError
		if errors.As(err, &qerr) {
			status = qerr.Status()
		}

		proxy.listener.OnResponse(&dnsx.Summary{
			Type:        dnsx.DNSCrypt,
			Latency:     latency.Seconds(),
			Query:       query,
			Response:    response,
			Server:      resolver,
			RelayServer: relay,
			Status:      status,
			Blocklists:  b,
		})
	}

	/*number of byte, err*/
	_, err = conn.Write(response)
	if err != nil {
		log.Errorf("failed writing dns response: %w", err)
	}
}

func (p *Proxy) SetBraveDNS(b dnsx.BraveDNS) {
	p.bravedns = b
}

func (proxy *Proxy) SetNatPt(pt ipn.NatPt) {
	proxy.natpt = pt
	// TODO: pt.AddResolver(t.url, t.Query)
}

type OneServerProxy struct {
	server *ServerInfo
	inner  *Proxy
}

// Implements ipn.DnsExchange
func (sp *OneServerProxy) Exchange(x []byte) (r []byte, err error) {
	// TODO: support truncation
	r, _, _, err = sp.inner.queryServer(x, false, sp.server)
	return
}

func (proxy *Proxy) ExchangeWith(s *ServerInfo) ipn.Resolver {
	return &OneServerProxy{
		server: s,
		inner:  proxy,
	}
}

// LiveServers returns csv of dnscrypt server-names currently in-use
func (proxy *Proxy) LiveServers() string {
	if len(proxy.liveServers) <= 0 {
		return ""
	}
	return strings.Join(proxy.liveServers[:], ",")
}

// Refresh re-registers servers
func (proxy *Proxy) Refresh() (string, error) {
	for _, registeredServer := range proxy.registeredServers {
		proxy.serversInfo.registerServer(registeredServer.name, registeredServer.stamp)
	}
	var err error
	proxy.liveServers, err = proxy.serversInfo.refresh(proxy)
	if len(proxy.liveServers) > 0 {
		proxy.certIgnoreTimestamp = false
	} else if err != nil {
		// ignore error if live-servers are around
		return "", err
	}
	return proxy.LiveServers(), nil
}

// StartProxy fetches server-list and starts a dnscrypt stub resolver
func (proxy *Proxy) StartProxy() (string, error) {
	if proxy.sigterm != nil {
		return "", fmt.Errorf("proxy already started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	proxy.sigterm = cancel
	if _, err := crypto_rand.Read(proxy.proxySecretKey[:]); err != nil {
		return "", err
	}
	curve25519.ScalarBaseMult(&proxy.proxyPublicKey, &proxy.proxySecretKey)
	_, err := proxy.Refresh()
	if len(proxy.serversInfo.registeredServers) > 0 {
		go func(ctx context.Context) {
			for {
				select {
				case <-ctx.Done():
					log.Infof("cert refresh go rountine stopped.")
					return
				default:
					delay := proxy.certRefreshDelay
					if len(proxy.liveServers) == 0 {
						delay = proxy.certRefreshDelayAfterFailure
					}
					clocksmith.Sleep(delay)
					proxy.liveServers, _ = proxy.serversInfo.refresh(proxy)
					if len(proxy.liveServers) > 0 {
						proxy.certIgnoreTimestamp = false
					}
					runtime.GC()
				}
			}
		}(ctx)
	}
	return proxy.LiveServers(), err
}

func (proxy *Proxy) StopProxy() error {
	if proxy.sigterm != nil {
		proxy.sigterm()
	}
	proxy.sigterm = nil
	return nil
}

// AddRoutes set anonymous dnscrypt relay routes
func (proxy *Proxy) AddRoutes(routescsv string) (int, error) {
	if len(routescsv) <= 0 {
		return 0, fmt.Errorf("specify atleast one dns-crypt route")
	}

	proxy.Lock()
	defer proxy.Unlock()

	r := xdns.FindUnique(proxy.routes, strings.Split(routescsv, ","))
	proxy.routes = append(proxy.routes, r...)
	return len(r), nil
}

func (proxy *Proxy) RemoveRoutes(routescsv string) (int, error) {
	if len(routescsv) <= 0 {
		return 0, fmt.Errorf("specify atleast one dns-crypt route")
	}

	proxy.Lock()
	defer proxy.Unlock()

	rm := strings.Split(routescsv, ",")
	l := len(proxy.routes)
	proxy.routes = xdns.FindUnique(rm, proxy.routes)
	return l - len(proxy.routes), nil
}

func (proxy *Proxy) RemoveServers(servernamescsv string) (int, error) {
	if len(servernamescsv) <= 0 {
		return 0, fmt.Errorf("specify at least one dns-crypt resolver endpoint")
	}

	proxy.Lock()
	defer proxy.Unlock()

	servernames := strings.Split(servernamescsv, ",")
	var c int
	for _, name := range servernames {
		if len(name) == 0 {
			continue
		}
		// TODO: handle err
		n, _ := proxy.serversInfo.unregisterServer(name)
		delete(proxy.registeredServers, name)

		c = c + n
	}

	return c, nil
}

// AddServers registers additional dnscrypt servers
func (proxy *Proxy) AddServers(serverscsv string) (int, error) {
	if len(serverscsv) <= 0 {
		return 0, fmt.Errorf("specify at least one dns-crypt resolver endpoint")
	}

	proxy.Lock()
	defer proxy.Unlock()

	servers := strings.Split(serverscsv, ",")
	for i, serverStampPair := range servers {
		if len(serverStampPair) == 0 {
			return i, fmt.Errorf("Missing stamp for the stamp [%s] definition", serverStampPair)
		}
		serverStamp := strings.Split(serverStampPair, "#")
		// TODO: skip duplicates.
		stamp, err := stamps.NewServerStampFromString(serverStamp[1])
		if err != nil {
			return i, fmt.Errorf("Stamp error for the stamp [%s] definition: [%v]", serverStampPair, err)
		}
		if stamp.Proto == stamps.StampProtoTypeDoH {
			// TODO: Implement doh
			return i, fmt.Errorf("DoH with DNSCrypt client not supported", serverStamp)
		}
		proxy.registeredServers[serverStamp[0]] = RegisteredServer{name: serverStamp[0], stamp: stamp}
	}
	return len(servers), nil
}

// NewProxy creates a dnscrypt proxy
func NewProxy(l dnsx.Listener) *Proxy {
	return &Proxy{
		routes:                       nil,
		registeredServers:            make(map[string]RegisteredServer),
		undelegatedSet:               dnsx.UndelegatedDomainsTrie(),
		certRefreshDelay:             time.Duration(240) * time.Minute,
		certRefreshDelayAfterFailure: time.Duration(10 * time.Second),
		certIgnoreTimestamp:          false,
		timeout:                      time.Duration(20000) * time.Millisecond,
		mainProto:                    "tcp",
		serversInfo:                  NewServersInfo(),
		liveServers:                  nil,
		listener:                     l,
	}
}
