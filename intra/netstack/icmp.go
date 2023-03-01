// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package netstack

import (
	"fmt"
	"net"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
)

type Pong func(reply []byte) error
type GICMPHandler interface {
	Ping(source *net.UDPAddr, destination *net.UDPAddr, payload []byte, pong Pong) bool
}

// ref: github.com/SagerNet/LibSagerNetCore/blob/632d6b892e/gvisor/icmp.go
func setupIcmpHandler(s *stack.Stack, ep stack.LinkEndpoint, handler GICMPHandler) {
	// ICMPv4
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, func(id stack.TransportEndpointID, packet *stack.PacketBuffer) bool {
		icmpin := header.ICMPv4(packet.TransportHeader().View())
		if icmpin.Type() != header.ICMPv4Echo {
			// let netstack handles other msgs except echo / ping
			return false
		}

		src := remoteUDPAddr(id)
		dst := localUDPAddr(id)

		b := make([]byte, ep.MTU())
		din8 := buffer.NewWithData(b)
		din8.Append(packet.NetworkHeader().View())
		l4 := packet.TransportHeader().View()
		if len(l4) > 8 {
			l4 = l4[:8]
		}
		din8.AppendOwned(l4)
		req := din8.Flatten()

		// github.com/google/gvisor/blob/9b4a7aa00/pkg/tcpip/network/ipv6/icmp.go#L1180
		r := make([]byte, ep.MTU())
		din := buffer.NewWithData(r)
		din.Append(packet.TransportHeader().View())
		l7 := packet.Data().AsBuffer()
		din.Merge(&l7)
		data := din.Flatten()
		datalen := len(data)

		l3 := packet.NetworkHeader().View()
		if !handler.Ping(src, dst, data, func(reply []byte) error {
			// sendICMP: github.com/google/gvisor/blob/8035cf9ed/pkg/tcpip/transport/tcp/testing/context/context.go#L404
			// parseICMP: github.com/google/gvisor/blob/8035cf9ed/pkg/tcpip/header/parse/parse.go#L194
			// makeICMP: https://github.com/google/gvisor/blob/8035cf9ed/pkg/tcpip/tests/integration/iptables_test.go#L2100
			// Allocate a buffer data and headers.
			icmpout := header.ICMPv4(reply)
			if icmpout.Type() == header.ICMPv4DstUnreachable {
				const ICMPv4HeaderSize = 4
				d := make([]byte, len(req)+header.ICMPv4MinimumErrorPayloadSize)
				icmpunreach := header.ICMPv4(d)
				copy(icmpunreach[:ICMPv4HeaderSize], reply)
				copy(icmpunreach[header.ICMPv4MinimumErrorPayloadSize:], req)
				icmpout = icmpunreach
			}

			x := make([]byte, ep.MTU())
			res := buffer.NewWithData(x)

			if len(icmpout) != datalen {
				ip := header.IPv4(l3)
				l3len := ip.TotalLength()
				ip.SetTotalLength(uint16(len(l3) + len(reply)))
				ip.SetChecksum(^header.ChecksumCombine(^ip.Checksum(), header.ChecksumCombine(ip.TotalLength(), ^l3len)))
				res.Append(ip.Payload())
			} else {
				res.Append(l3)
			}
			res.Append(icmpout.Payload())

			respkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: res})
			defer respkt.DecRef()

			var pout stack.PacketBufferList
			pout.PushBack(respkt)
			if _, err := ep.WritePackets(pout); err != nil {
				return fmt.Errorf("err writing upstream res to tun: %v", err)
			}

			if icmpout.Type() == header.ICMPv4DstUnreachable {
				return unix.ENETUNREACH
			}
			// inform the client that it can continue to listen for more packets
			return nil
		}) {
			// if unhandled by the handler, send a reply ourselves
			icmpin.SetType(header.ICMPv4EchoReply)
			icmpin.SetChecksum(0)
			icmpin.SetChecksum(header.ICMPv4Checksum(icmpin, packet.Data().AsRange().Checksum()))
			var pout stack.PacketBufferList
			pout.PushBack(packet)
			_, err := ep.WritePackets(pout)
			if err != nil {
				log.Errorf("icmp: err writing default reply to tun: %v", err)
				return false
			}
		}

		return true
	})

	// ICMPv6
	s.SetTransportProtocolHandler(icmp.ProtocolNumber6, func(id stack.TransportEndpointID, packet *stack.PacketBuffer) bool {
		icmpin := header.ICMPv6(packet.TransportHeader().View())
		if icmpin.Type() != header.ICMPv6EchoRequest {
			// let netstack handles other msgs except echo / ping
			return false
		}

		src := remoteUDPAddr(id)
		dst := localUDPAddr(id)

		b := make([]byte, ep.MTU())
		din8 := buffer.NewWithData(b)
		din8.Append(packet.NetworkHeader().View())
		l4 := packet.TransportHeader().View()
		if len(l4) > 8 {
			l4 = l4[:8]
		}
		din8.Append(l4)
		req := din8.Flatten()

		// github.com/google/gvisor/blob/9b4a7aa00/pkg/tcpip/network/ipv6/icmp.go#L1180
		r := make([]byte, ep.MTU())
		din := buffer.NewWithData(r)
		din.Append(packet.TransportHeader().View())
		l7 := packet.Data().AsBuffer()
		din.Merge(&l7)
		data := din.Flatten()
		dlen := len(data)

		l3 := packet.NetworkHeader().View()
		if !handler.Ping(src, dst, data, func(reply []byte) error {
			icmpout := header.ICMPv6(reply)
			if icmpout.Type() == header.ICMPv6DstUnreachable {
				d := make([]byte, len(req)+header.ICMPv6DstUnreachableMinimumSize)
				icmpunreach := header.ICMPv6(d)
				copy(icmpunreach[:header.ICMPv6HeaderSize], reply)
				copy(icmpunreach[header.ICMPv6DstUnreachableMinimumSize:], req)
				icmpout = icmpunreach
			}

			x := make([]byte, ep.MTU())
			res := buffer.NewWithData(x)

			if len(icmpout) != dlen {
				ip := header.IPv6(l3)
				ip.SetPayloadLength(uint16(len(icmpout)))
				res.Append(ip.Payload())
			} else {
				res.Append(l3)
			}
			res.Append(icmpout)

			icmpout.SetChecksum(0)
			icmpout.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header: icmpout,
				Src:    id.RemoteAddress, // src
				Dst:    id.LocalAddress,  // dst
			}))

			respkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: res})
			defer respkt.DecRef()

			var pout stack.PacketBufferList
			pout.PushBack(respkt)
			if _, err := ep.WritePackets(pout); err != nil {
				return fmt.Errorf("err writing upstream res to tun %v", err)
			}

			if icmpout.Type() == header.ICMPv6DstUnreachable {
				return unix.ENETUNREACH
			}

			return nil
		}) {
			icmpin.SetType(header.ICMPv6EchoReply)
			icmpin.SetChecksum(0)
			icmpin.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header:      icmpin,
				Src:         id.LocalAddress,  // dst
				Dst:         id.RemoteAddress, // src
				PayloadCsum: packet.Data().AsRange().Checksum(),
				PayloadLen:  packet.Data().Size(),
			}))

			var pout stack.PacketBufferList
			pout.PushBack(packet)
			if _, err := ep.WritePackets(pout); err != nil {
				log.Errorf("icmp: err writing default echo pkt to tun %v", err)
				return false
			}
		}
		return true
	})
}
