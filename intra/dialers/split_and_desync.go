// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dialers

import (
	"context"
	secrand "crypto/rand"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"golang.org/x/sys/unix"
)

const (
	probeSize   = 8
	default_ttl = 64

	desync_http1_1str = "POST / HTTP/1.1\r\nHost: 10.0.0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 9999999\r\n\r\n"
	// from: github.com/bol-van/zapret/blob/c369f11638/nfq/darkmagic.h#L214-L216
	desync_max_ttl     = 20
	desync_noop_ttl    = 3
	desync_delta_ttl   = 1
	desync_invalid_ttl = -1

	desync_cache_ttl = 30 * time.Second
)

// ttlcache stores the TTL for a given IP address for a limited time.
// TODO: invalidate cache on network changes.
// TODO: with context.TODO, expmap's reaper goroutine will leak.
var ttlcache = core.NewSieve[netip.Addr, int](context.TODO(), desync_cache_ttl)

// Combines direct split with TCB Desynchronization Attack
// Inspired by byedpi: github.com/hufrea/byedpi/blob/82e5229df00/desync.c#L69-L123
type overwriteSplitter struct {
	conn    *net.TCPConn // underlying connection
	used    atomic.Bool  // set to true to stop desync writer
	ttl     int          // desync TTL
	ip6     bool         // IPv6
	payload []byte       // must be smaller than 1st written packet
	// note: Normal ClientHello generated by browsers is 517 bytes. If kyber is enabled, the ClientHello can be larger.
}

var _ core.DuplexConn = (*overwriteSplitter)(nil)

// exceedsHopLimit checks if cmsgs contains an ICMPv6 hop limit exceeded SockExtendedErr
//
//	type SockExtendedErr struct {
//		Errno  uint32
//		Origin uint8
//		Type   uint8
//		Code   uint8
//		Pad    uint8
//		Info   uint32
//		Data   uint32
//	}
//
// https://www.rfc-editor.org/rfc/rfc4443.html#section-3.3
func exceedsHopLimit(cmsgs []unix.SocketControlMessage) bool {
	for _, cmsg := range cmsgs {
		if cmsg.Header.Level == unix.IPPROTO_IPV6 && cmsg.Header.Type == unix.IPV6_RECVERR {
			eeOrigin := cmsg.Data[4]
			if eeOrigin == unix.SO_EE_ORIGIN_ICMP6 {
				eeType := cmsg.Data[5]
				eeCode := cmsg.Data[6]
				if eeType == 3 && eeCode == 0 {
					return true
				}
			}
		}
	}
	return false
}

// exceedsTTL checks if cmsgs contains an ICMPv4 time to live exceeded SockExtendedErr.
// https://www.rfc-editor.org/rfc/rfc792.html#page-6
func exceedsTTL(cmsgs []unix.SocketControlMessage) bool {
	for _, cmsg := range cmsgs {
		if cmsg.Header.Level == unix.IPPROTO_IP && cmsg.Header.Type == unix.IP_RECVERR {
			eeOrigin := cmsg.Data[4]
			if eeOrigin == unix.SO_EE_ORIGIN_ICMP {
				eeType := cmsg.Data[5]
				eeCode := cmsg.Data[6]
				if eeType == 11 && eeCode == 0 {
					return true
				}
			}
		}
	}
	return false
}

// tracert dials a UDP conn to the target address over a port range basePort to basePort+DESYNC_MAX_TTL, with TTL
// set to 2, 3, ..., DESYNC_MAX_TTL. It does not take ownership of the conn (which must be closed by the caller).
func tracert(d *protect.RDial, ipp netip.AddrPort, basePort int) (*net.UDPConn, int, error) {
	udpAddr := net.UDPAddrFromAddrPort(ipp)
	udpAddr.Port = 1 // unset port

	isIPv6 := ipp.Addr().Is6()

	// explicitly prefer udp4 for IPv4 to prevent OS from giving cmsg(s) which mix IPPROTO_IPV6 cmsg level
	// & IPv4-related cmsg data, because exceedsTTL() returns false when cmsg.Header.Level == IPPROTO_IPV6.
	// that is: "udp" dials a dual-stack connection, which we don't want.
	proto := "udp4"
	if isIPv6 {
		proto = "udp6"
	}

	var udpFD int
	uc, err := d.AnnounceUDP(proto, ":0")
	if err != nil {
		log.E("desync: err announcing udp: %v", err)
		return uc, udpFD, err
	}
	if uc == nil {
		return uc, udpFD, errNoConn
	}

	rawConn, err := uc.SyscallConn()
	if err != nil {
		return uc, udpFD, err
	}
	if rawConn == nil {
		return uc, udpFD, errNoSysConn
	}
	err = rawConn.Control(func(fd uintptr) {
		udpFD = int(fd)
	})
	if err != nil {
		return uc, udpFD, err
	}

	if isIPv6 {
		err = unix.SetsockoptInt(udpFD, unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1)
	} else {
		err = unix.SetsockoptInt(udpFD, unix.IPPROTO_IP, unix.IP_RECVERR, 1)
	}
	if err != nil {
		return uc, udpFD, err
	}

	var msgBuf [probeSize]byte
	for ttl := 2; ttl <= desync_max_ttl; ttl += desync_delta_ttl {
		_, err = secrand.Read(msgBuf[:])
		if err != nil {
			return uc, udpFD, err
		}
		if isIPv6 {
			err = unix.SetsockoptInt(udpFD, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
		} else {
			err = unix.SetsockoptInt(udpFD, unix.IPPROTO_IP, unix.IP_TTL, ttl)
		}
		if err != nil {
			return uc, udpFD, err
		}
		udpAddr.Port = basePort + ttl
		_, err = uc.WriteToUDP(msgBuf[:], udpAddr)
		if err != nil {
			return uc, udpFD, err
		}
	}
	return uc, udpFD, nil
}

// desyncWithTraceroute estimates the TTL with UDP traceroute,
// then returns a TCP connection that may launch TCB Desynchronization Attack and split the initial upstream segment
// If `payload` is smaller than the initial upstream segment, it launches the attack and splits.
// This traceroute is not accurate, because of time limit (TCP handshake).
// Note: The path the UDP packet took to reach the destination may differ from the path the TCP packet took.
func desyncWithTraceroute(d *protect.RDial, local, remote netip.AddrPort) (*overwriteSplitter, error) {
	const maxport = 65535
	measureTTL := true
	isIPv6 := remote.Addr().Is6()
	basePort := 1 + rand.Intn(maxport-desync_max_ttl) //#nosec G404

	uc, udpFD, err := tracert(d, remote, basePort)
	defer core.Close(uc)

	logeif(err)("desync: dialUDP %s => %s %d: err? %v", local, remote, udpFD, err)
	if err != nil {
		measureTTL = false
	}

	oc, err := desyncWithFixedTtl(d, local, remote, desync_noop_ttl)
	if err != nil {
		return nil, err
	}
	if oc == nil { // nilaway
		return nil, errNoDesyncConn
	}

	var msgBuf [probeSize]byte

	bptr := core.Alloc()
	cmsgBuf := *bptr
	cmsgBuf = cmsgBuf[:cap(cmsgBuf)]
	defer func() {
		*bptr = cmsgBuf
		core.Recycle(bptr)
	}()

	// after TCP handshake, check received ICMP messages, if measureTTL is true.
	for i := 0; i < desync_max_ttl-1 && measureTTL; i += desync_delta_ttl {
		_, cmsgN, _, from, err := unix.Recvmsg(udpFD, msgBuf[:], cmsgBuf[:], unix.MSG_ERRQUEUE)
		if err != nil {
			log.V("desync: recvmsg %v, err: %v", remote, err)
			break
		}

		cmsgs, err := unix.ParseSocketControlMessage(cmsgBuf[:cmsgN])
		if err != nil {
			log.W("desync: parseSocketControlMessage %v failed: %v", remote, err)
			continue
		}

		if isIPv6 {
			if exceedsHopLimit(cmsgs) {
				fromPort := from.(*unix.SockaddrInet6).Port
				ttl := fromPort - basePort
				if ttl <= desync_max_ttl {
					oc.ttl = max(oc.ttl, ttl)
				} // else: corrupted packet?
			}
		} else {
			if exceedsTTL(cmsgs) {
				fromPort := from.(*unix.SockaddrInet4).Port
				ttl := fromPort - basePort
				if ttl <= desync_max_ttl {
					oc.ttl = max(oc.ttl, ttl)
				} // else: corrupted packet?
			}
		}
	}

	// skip or apply desync depending on whether
	// the measurement is successful.
	avoidDesync := oc.ttl <= desync_noop_ttl

	oc.used.Store(avoidDesync)

	log.D("desync: done: %v, do desync? %t, ttl: %d", remote, !avoidDesync, oc.ttl)

	return oc, nil
}

func desyncWithFixedTtl(d *protect.RDial, local, remote netip.AddrPort, initialTTL int) (*overwriteSplitter, error) {
	var raddr *net.TCPAddr = net.TCPAddrFromAddrPort(remote)
	var laddr *net.TCPAddr // nil is valid
	if local.IsValid() {
		laddr = net.TCPAddrFromAddrPort(local)
	}

	isIPv6 := remote.Addr().Is6()
	// skip desync if no measurement is done
	avoidDesync := initialTTL <= desync_noop_ttl

	proto := "tcp4"
	if isIPv6 {
		proto = "tcp6"
	}

	tcpConn, err := d.DialTCP(proto, laddr, raddr)

	logeif(err)("desync: dialTCP: %s => %s, do desync? %t, ttl: %d",
		laddr, raddr, !avoidDesync, initialTTL)

	if err != nil {
		return nil, err
	}
	if tcpConn == nil {
		return nil, errNoConn
	}

	s := &overwriteSplitter{
		conn:    tcpConn,
		ttl:     initialTTL,
		payload: []byte(desync_http1_1str),
		ip6:     isIPv6,
	}
	s.used.Store(avoidDesync)

	return s, nil
}

// DialWithSplitAndDesync estimates the TTL with UDP traceroute,
// then returns a TCP connection that may launch TCB Desynchronization
// and split the initial upstream segment.
// ref: github.com/bol-van/zapret/blob/c369f11638/docs/readme.eng.md#dpi-desync-attack
func dialWithSplitAndDesync(d *protect.RDial, laddr, raddr *net.TCPAddr) (*overwriteSplitter, error) {
	remote := raddr.AddrPort() // must not be invalid
	local := laddr.AddrPort()  // can be invalid

	if !remote.IsValid() {
		log.E("desync: invalid raddr: conv %s to %s", raddr, remote)
		return nil, errNoIps
	}

	ttl, ok := ttlcache.Get(remote.Addr())
	if ok {
		return desyncWithFixedTtl(d, local, remote, ttl)
	}
	conn, err := desyncWithTraceroute(d, local, remote)
	if err == nil && conn != nil { // go vet (incorrectly) complains conn being nil when err is nil
		ttlcache.Put(remote.Addr(), conn.ttl)
	}
	return conn, err
}

// Close implements core.DuplexConn.
func (s *overwriteSplitter) Close() error { core.CloseTCP(s.conn); return nil }

// CloseRead implements core.DuplexConn.
func (s *overwriteSplitter) CloseRead() error { core.CloseTCPRead(s.conn); return nil }

// CloseWrite implements core.DuplexConn.
func (s *overwriteSplitter) CloseWrite() error { core.CloseTCPWrite(s.conn); return nil }

// LocalAddr implements core.DuplexConn.
func (s *overwriteSplitter) LocalAddr() net.Addr { return laddr(s.conn) }

// RemoteAddr implements core.DuplexConn.
func (s *overwriteSplitter) RemoteAddr() net.Addr { return raddr(s.conn) }

// SetDeadline implements core.DuplexConn.
func (s *overwriteSplitter) SetDeadline(t time.Time) error {
	if c := s.conn; c != nil {
		return c.SetDeadline(t)
	}
	return nil // no-op
}

// SyscallConn implements core.PoolableConn.
func (s *overwriteSplitter) SyscallConn() (syscall.RawConn, error) {
	if c := s.conn; c != nil {
		return c.SyscallConn()
	}
	return nil, syscall.EINVAL
}

// SetReadDeadline implements core.DuplexConn.
func (s *overwriteSplitter) SetReadDeadline(t time.Time) error {
	if c := s.conn; c != nil {
		return c.SetReadDeadline(t)
	}
	return nil // no-op
}

// SetWriteDeadline implements core.DuplexConn.
func (s *overwriteSplitter) SetWriteDeadline(t time.Time) error {
	if c := s.conn; c != nil {
		return c.SetWriteDeadline(t)
	}
	return nil // no-op
}

// Read implements core.DuplexConn.
func (s *overwriteSplitter) Read(b []byte) (int, error) { return s.conn.Read(b) }

// Write implements core.DuplexConn.
// ref: github.com/hufrea/byedpi/blob/82e5229df00/desync.c#L69-L123
func (s *overwriteSplitter) Write(b []byte) (n int, err error) {
	conn := s.conn
	laddr := laddr(s.conn)
	raddr := raddr(s.conn)

	noop := len(b) == 0 // go vet has us handle this case
	avoidDesync := s.ttl <= desync_noop_ttl
	short := len(b) < len(s.payload)
	swapped := false
	used := s.used.Load() // also true when s.ttl <= desync_noop_ttl
	if noop {
		n, err = 0, nil
	} else if used || avoidDesync {
		// after the first write, there is no special write behavior.
		// used may also be set to true to avoid desync.
		n, err = conn.Write(b)
	} else if swapped = s.used.CompareAndSwap(false, true); !swapped {
		// set `used` to ensure this code only runs once per conn;
		// if !swapped, some other goroutine has already swapped it.
		n, err = conn.Write(b)
	} else if short {
		n, err = conn.Write(b)
	}
	if used || short || !swapped || noop {
		logeif(err)("desync: write: %s => %s; desync done %d; (noop? %t, used? %t, short? %t, race? %t); err? %v",
			laddr, raddr, n, noop, used, short, !swapped, err)
		return n, err
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	if rawConn == nil {
		return 0, errNoSysConn
	}

	var sockFD int
	err = rawConn.Control(func(fd uintptr) {
		sockFD = int(fd)
	})
	if err != nil {
		log.E("desync: %s => %s get sock fd failed; %v", laddr, raddr, err)
		return 0, err
	}

	fileFD, err := unix.MemfdCreate("haar", unix.O_RDWR)
	if err != nil {
		return 0, err
	}

	defer core.CloseFD(fileFD)

	err = unix.Ftruncate(fileFD, int64(len(s.payload)))
	if err != nil {
		return 0, err
	}
	firstSegment, err := unix.Mmap(fileFD, 0, len(s.payload), unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = unix.Munmap(firstSegment)
	}()

	// restrict TTL to ensure s.Payload is seen by censors, but not by the server.
	copy(firstSegment, s.payload)
	if s.ip6 {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, s.ttl)
	} else {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IP, unix.IP_TTL, s.ttl)
	}
	if err != nil {
		log.E("desync: %s => %s setsockopt(ttl) err: %v", laddr, raddr, err)
		return 0, err
	}
	var offset int64 = 0
	n1, err := unix.Sendfile(sockFD, fileFD, &offset, len(s.payload))
	if err != nil {
		log.E("desync: %s => %s sendfile() %d err: %v", laddr, raddr, n1, err)
		return n1, err
	}

	// also: github.com/hufrea/byedpi/blob/bbe95222/desync.c#L115
	time.Sleep(3 * time.Microsecond)
	// restore the first-half of the payload so that it gets picked up on retranmission.
	copy(firstSegment, b[:len(s.payload)])

	// restore default TTL
	if s.ip6 {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, default_ttl)
	} else {
		err = unix.SetsockoptInt(sockFD, unix.IPPROTO_IP, unix.IP_TTL, default_ttl)
	}
	if err != nil {
		log.E("desync: %s => %s setsockopt(ttl) err: %v", laddr, raddr, err)
		return n1, err
	}

	// write the second segment
	n2, err := conn.Write(b[len(s.payload):])
	logeif(err)("desync: write: n1: %d, n2: %d, err: %v", n1, n2, err)
	return n1 + n2, err
}

// ReadFrom reads from the reader and writes to s.
func (s *overwriteSplitter) ReadFrom(reader io.Reader) (bytes int64, err error) {
	if !s.used.Load() {
		bytes, err = copyOnce(s, reader)
		logeif(err)("desync: readfrom: copyOnce; sz: %d; err: %v", bytes, err)
		if err != nil {
			return
		}
	}

	b, err := s.conn.ReadFrom(reader)
	bytes += b
	log.V("desync: readfrom: done; sz: %d; err: %v", bytes, err)

	return
}
