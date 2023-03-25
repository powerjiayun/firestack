// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    SPDX-License-Identifier: MIT
//
//    Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.

// from: github.com/WireGuard/wireguard-go/blob/5819c6af/tun/netstack/tun.go

package ipn

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/celzero/firestack/intra/ipn/wg"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	// epsize is the size of the channel endpoint.
	epsize = 1024
	// eventssize is the size of the events channel.
	eventssize = 16
	// wgnic is the id of the WireGuard network interface.
	wgnic = 999
)

// unused
type wgifc struct {
	id         string        // name of the wg interface
	privkey    string        // private key
	pubkey     string        // public key
	ifaddrs    []*netip.Addr // wg interface addresses
	dnsaddrs   []*netip.Addr // wg interface dns addresses
	listenport int           // listen for incoming conns
	mtu        int           // preferred mtu
}

// unused
type wgpeerc struct {
	psk        string          // preshared key
	pubkey     string          // public key
	keepalive  time.Duration   // keepalive interval in seconds
	endpoint   *netip.AddrPort // remote endpoint
	allowedips []*netip.Addr   // allowed ips
}

type wgtun struct {
	id             string
	addrs          []*netip.Addr
	status         int
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	incomingPacket chan *bufferv2.View
	mtu            int
	dnsaddrs       []*netip.Addr
	hasV4, hasV6   bool
}

var _ WgProxy = (*wgproxy)(nil)
var _ Proxy = (*wgproxy)(nil)

type wgproxy struct {
	*wgtun
	*device.Device
}

// BatchSize implements WgProxy
func (w *wgproxy) BatchSize() int {
	return w.wgtun.BatchSize()
}

// Close implements WgProxy
func (w *wgproxy) Close() error {
	w.Device.Close()
	return w.wgtun.Close()
}

type WgProxy interface {
	Proxy
	tun.Device
	IpcSet(txt string) error
}

func wglogger() *device.Logger {
	lvl := device.LogLevelError
	tag := WG
	if settings.Debug {
		lvl = device.LogLevelVerbose
	}
	return device.NewLogger(lvl, tag)
}

func wgIfConfigOf(txtptr *string) (ifaddrs, dnsaddrs []*netip.Addr, mtu int, err error) {
	txt := *txtptr
	pcfg := strings.Builder{}
	r := bufio.NewScanner(strings.NewReader(txt))
	for r.Scan() {
		line := r.Text()
		if len(line) <= 0 {
			// Blank line means terminate operation.
			if (len(ifaddrs) <= 0) || (len(dnsaddrs) <= 0) || (mtu <= 0) {
				err = errProxyConfig
			}
			return
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			err = fmt.Errorf("proxy: wg: failed to parse line %q", line)
			return
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.ToLower(strings.TrimSpace(v))

		var ip netip.Addr
		// process interface config; Address, DNS, ListenPort, MTU
		// github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/src/main/java/com/wireguard/config/Interface.java#L232
		switch k {
		case "address":
			if ip, err = netip.ParseAddr(v); err != nil {
				var ipnet netip.Prefix
				if ipnet, err = netip.ParsePrefix(v); err != nil {
					return
				}
				ip = ipnet.Addr()
			}
			ifaddrs = append(ifaddrs, &ip)
		case "dns":
			if ip, err = netip.ParseAddr(v); err != nil {
				return
			}
			dnsaddrs = append(dnsaddrs, &ip)
		case "mtu":
			if mtu, err = strconv.Atoi(v); err != nil {
				return
			}
		default:
			pcfg.WriteString(line + "\n")
		}
	}
	*txtptr = pcfg.String()
	if err == nil && (len(ifaddrs) <= 0) || (len(dnsaddrs) <= 0) || (mtu <= 0) {
		err = errProxyConfig
	}
	return
}

func bindWgSockets(wgdev *device.Device, ctl protect.Controller) bool {
	var ok4, ok6 bool

	// ref: github.com/WireGuard/wireguard-go/blob/1417a47c8/conn/bind_std.go#L130
	// bind: github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/tools/libwg-go/api-android.go#L180
	// protect: https://github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/src/main/java/com/wireguard/android/backend/GoBackend.java#L316
	bind := wgdev.Bind().(conn.PeekLookAtSocketFd)
	if bind == nil {
		log.E("proxy: wg: bind: failed to get wg socket")
		return false
	}

	if fd4, err := bind.PeekLookAtSocketFd4(); err != nil {
		log.W("proxy: wg: bind4: failed to get wg4 socket %v", err)
	} else {
		ctl.Bind4(fd4)
		ok4 = true
	}

	if fd6, err := bind.PeekLookAtSocketFd6(); err != nil {
		log.W("proxy: wg: bind6: failed to get wg6 socket %v", err)
	} else {
		ctl.Bind6(fd6)
		ok6 = true
	}

	return ok4 || ok6
}

// ref: github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/tools/libwg-go/api-android.go#L76
func NewWgProxy(id string, ctl protect.Controller, cfg string) (w WgProxy, err error) {
	ifaddrs, dnsaddrs, mtu, err := wgIfConfigOf(&cfg)
	uapicfg := cfg
	if err != nil {
		return nil, err
	}

	wgtun, err := makeWgTun(id, ifaddrs, dnsaddrs, mtu)
	if err != nil {
		return nil, err
	}

	wgdev := device.NewDevice(wgtun, wg.NewBind(), wglogger())

	err = wgdev.IpcSet(uapicfg)
	if err != nil {
		return nil, err
	}

	// github.com/WireGuard/wireguard-android/blob/713947e432/tunnel/tools/libwg-go/api-android.go#L99
	wgdev.DisableSomeRoamingForBrokenMobileSemantics()

	err = wgdev.Up()
	if err != nil {
		return nil, err
	}

	// nb: call after StdNetBind conn has been "Open"ed
	// not needed for wg.NewBind2; see: wg:wgconn2.go
	bindok := bindWgSockets(wgdev, ctl)

	w = &wgproxy{
		wgtun,
		wgdev,
	}

	log.D("proxy: wg: new %s for cfg %s / bound? %t", id, cfg, bindok)

	return
}

func makeWgTun(id string, ifaddrs, dnsaddrs []*netip.Addr, mtu int) (*wgtun, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        true,
	}
	// uint32(mtu) - 80 is the maximum payload size of a WireGuard packet.
	tunmtu := uint32(mtu) - 80 // 80 is the overhead of the WireGuard header

	s := stack.New(opts)
	sackEnabledOpt := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	ep := channel.New(epsize, tunmtu, "")
	t := &wgtun{
		id:             id,
		addrs:          ifaddrs,
		ep:             ep,
		stack:          s,
		events:         make(chan tun.Event, eventssize),
		incomingPacket: make(chan *bufferv2.View),
		dnsaddrs:       dnsaddrs,
		mtu:            mtu,
	}
	// see WriteNotify below
	ep.AddNotify(t)

	if err := s.CreateNIC(wgnic, ep); err != nil {
		return nil, fmt.Errorf("wg: create nic: %v", err)
	}

	for _, ip := range ifaddrs {
		var protoid tcpip.NetworkProtocolNumber
		if ip.Is4() {
			protoid = ipv4.ProtocolNumber
		} else if ip.Is6() {
			protoid = ipv6.ProtocolNumber
		}
		protoaddr := tcpip.ProtocolAddress{
			Protocol:          protoid,
			AddressWithPrefix: tcpip.Address(ip.AsSlice()).WithPrefix(),
		}
		if err := s.AddProtocolAddress(wgnic, protoaddr, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("wg: add addr(%v): %v", ip, err)
		}
		t.hasV4 = t.hasV4 || ip.Is4()
		t.hasV6 = t.hasV6 || ip.Is6()
	}
	if t.hasV4 {
		s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: wgnic})
	}
	if t.hasV6 {
		s.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: wgnic})
	}

	// commence the wireguard state machine
	t.events <- tun.EventUp

	return t, nil
}

// implements tun.Device

func (tun *wgtun) Name() (string, error) {
	return tun.id, nil
}

func (tun *wgtun) File() *os.File {
	return nil
}

func (tun *wgtun) Events() <-chan tun.Event {
	return tun.events
}

func (tun *wgtun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-tun.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}

	n, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (tun *wgtun) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) == 0 {
			continue
		}

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: bufferv2.MakeWithData(pkt)})
		defer pkb.DecRef()
		switch pkt[0] >> 4 {
		case 4: // IPv4
			tun.ep.InjectInbound(header.IPv4ProtocolNumber, pkb) // write to ep
		case 6: // IPv6
			tun.ep.InjectInbound(header.IPv6ProtocolNumber, pkb) // write to ep
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}

	return len(bufs), nil
}

// WriteNotify is called by channel notifier on readable events
// github.com/google/gvisor/blob/acf460d0d73/pkg/tcpip/link/channel/channel.go#L31
func (tun *wgtun) WriteNotify() {
	pkt := tun.ep.Read()
	if pkt.IsNil() {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	tun.incomingPacket <- view
}

func (tun *wgtun) Close() error {
	tun.status = END
	tun.stack.RemoveNIC(wgnic)

	if tun.events != nil {
		close(tun.events)
	}

	tun.ep.Close()

	if tun.incomingPacket != nil {
		close(tun.incomingPacket)
	}

	return nil
}

func (tun *wgtun) MTU() (int, error) {
	return tun.mtu, nil
}

func (tun *wgtun) BatchSize() int {
	return 1
}

// implements Proxy

func (h *wgtun) Dial(network, address string) (c Conn, err error) {
	if h.status == END {
		return nil, errProxyStopped
	}

	if c, err = h.DialContext(context.Background(), network, address); err != nil {
		h.status = TKO
	} else {
		h.status = TOK
	}

	log.I("wg: dial: %s %s; err %v", network, address, err)
	return
}

func (h *wgtun) ID() string {
	return h.id
}

func (h *wgtun) GetAddr() string {
	return h.addrs[0].String()
}

func (h *wgtun) Type() string {
	return WG
}

func (h *wgtun) Status() int {
	return h.status
}

func (h *wgtun) Stop() error {
	h.status = END
	log.I("proxy: wg: stopped %s", h.id)
	return h.Close()
}