// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2018 The gVisor Authors.
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

// Package netstack provides the implemention of data-link layer endpoints
// backed by boundary-preserving file descriptors (e.g., TUN devices,
// seqpacket/datagram sockets).
//
// Adopted from: github.com/google/gvisor/blob/f33d034/pkg/tcpip/link/fdbased/endpoint.go
package netstack

import (
	"fmt"
	"sync/atomic"

	"github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.InjectableLinkEndpoint = (*endpoint)(nil)

// linkDispatcher reads packets from the link FD and dispatches them to the
// NetworkDispatcher.
type linkDispatcher interface {
	stop()
	dispatch() (bool, tcpip.Error)
}

type fdInfo struct {
	fd int
}

type endpoint struct {
	// fds is the set of file descriptors each identifying one inbound/outbound
	// channel. The endpoint will dispatch from all inbound channels as well as
	// hash outbound packets to specific channels based on the packet hash.
	fds []fdInfo

	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu uint32

	// hdrSize specifies the link-layer header size. If set to 0, no header
	// is added/removed; otherwise an ethernet header is used.
	hdrSize int

	// addr is the address of the endpoint.
	addr tcpip.LinkAddress

	// caps holds the endpoint capabilities.
	caps stack.LinkEndpointCapabilities

	inboundDispatchers []linkDispatcher
	dispatcher         stack.NetworkDispatcher

	// wg keeps track of running goroutines.
	wg sync.WaitGroup

	// maxSyscallHeaderBytes has the same meaning as
	// Options.MaxSyscallHeaderBytes.
	maxSyscallHeaderBytes uintptr

	// writevMaxIovs is the maximum number of iovecs that may be passed to
	// rawfile.NonBlockingWriteIovec, as possibly limited by
	// maxSyscallHeaderBytes. (No analogous limit is defined for
	// rawfile.NonBlockingSendMMsg, since in that case the maximum number of
	// iovecs also depends on the number of mmsghdrs. Instead, if sendBatch
	// encounters a packet whose iovec count is limited by
	// maxSyscallHeaderBytes, it falls back to writing the packet using writev
	// via WritePacket.)
	writevMaxIovs int
}

// Options specify the details about the fd-based endpoint to be created.
type Options struct {
	// FDs is a set of FDs used to read/write packets.
	FDs []int

	// MTU is the mtu to use for this endpoint.
	MTU uint32

	// EthernetHeader if true, indicates that the endpoint should read/write
	// ethernet frames instead of IP packets.
	EthernetHeader bool

	// Address is the link address for this endpoint. Only used if
	// EthernetHeader is true.
	Address tcpip.LinkAddress

	// SaveRestore if true, indicates that this NIC capability set should
	// include CapabilitySaveRestore
	SaveRestore bool

	// DisconnectOk if true, indicates that this NIC capability set should
	// include CapabilityDisconnectOk.
	DisconnectOk bool

	// TXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityTXChecksumOffload.
	TXChecksumOffload bool

	// RXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityRXChecksumOffload.
	RXChecksumOffload bool

	// If MaxSyscallHeaderBytes is non-zero, it is the maximum number of bytes
	// of struct iovec, msghdr, and mmsghdr that may be passed by each host
	// system call.
	MaxSyscallHeaderBytes int
}

// fanoutID is used for AF_PACKET based endpoints to enable PACKET_FANOUT
// support in the host kernel. This allows us to use multiple FD's to receive
// from the same underlying NIC. The fanoutID needs to be the same for a given
// set of FD's that point to the same NIC. Trying to set the PACKET_FANOUT
// option for an FD with a fanoutID already in use by another FD for a different
// NIC will return an EINVAL.
//
// Since fanoutID must be unique within the network namespace, we start with
// the PID to avoid collisions. The only way to be sure of avoiding collisions
// is to run in a new network namespace.
//
// Must be accessed using atomic operations.
var fanoutID int32 = int32(unix.Getpid())

// New creates a new fd-based endpoint.
//
// Makes fd non-blocking, but does not take ownership of fd, which must remain
// open for the lifetime of the returned endpoint (until after the endpoint has
// stopped being using and Wait returns).
func NewFdbasedInjectableEndpoint(opts *Options) (stack.LinkEndpoint, error) {
	caps := stack.LinkEndpointCapabilities(0)
	if opts.RXChecksumOffload {
		caps |= stack.CapabilityRXChecksumOffload
	}

	if opts.TXChecksumOffload {
		caps |= stack.CapabilityTXChecksumOffload
	}

	hdrSize := 0
	if opts.EthernetHeader {
		hdrSize = header.EthernetMinimumSize
		caps |= stack.CapabilityResolutionRequired
	}

	if opts.SaveRestore {
		caps |= stack.CapabilitySaveRestore
	}

	if opts.DisconnectOk {
		caps |= stack.CapabilityDisconnectOk
	}

	if len(opts.FDs) == 0 {
		return nil, fmt.Errorf("opts.FD is empty, at least one FD must be specified")
	}

	if opts.MaxSyscallHeaderBytes < 0 {
		return nil, fmt.Errorf("opts.MaxSyscallHeaderBytes is negative")
	}

	e := &endpoint{
		mtu:     opts.MTU,
		caps:    caps,
		addr:    opts.Address,
		hdrSize: hdrSize,
		// MaxSyscallHeaderBytes remains unused
		maxSyscallHeaderBytes: uintptr(opts.MaxSyscallHeaderBytes),
		writevMaxIovs:         rawfile.MaxIovs,
	}
	if e.maxSyscallHeaderBytes != 0 {
		if max := int(e.maxSyscallHeaderBytes / rawfile.SizeofIovec); max < e.writevMaxIovs {
			e.writevMaxIovs = max
		}
	}

	// Increment fanoutID to ensure that we don't re-use the same fanoutID for
	// the next endpoint.
	fid := atomic.AddInt32(&fanoutID, 1)

	// Create per channel dispatchers; usually only one.
	for _, fd := range opts.FDs {
		if err := unix.SetNonblock(fd, true); err != nil {
			return nil, fmt.Errorf("unix.SetNonblock(%v) failed: %v", fd, err)
		}

		e.fds = append(e.fds, fdInfo{fd: fd})

		inboundDispatcher, err := createInboundDispatcher(e, fd, fid)
		if err != nil {
			return nil, fmt.Errorf("createInboundDispatcher(...) = %v", err)
		}
		e.inboundDispatchers = append(e.inboundDispatchers, inboundDispatcher)
	}

	return e, nil
}

func createInboundDispatcher(e *endpoint, fd int, fID int32) (linkDispatcher, error) {
	// By default use the readv() dispatcher as it works with all kinds of
	// FDs (tap/tun/unix domain sockets and af_packet).
	inboundDispatcher, err := newReadVDispatcher(fd, e)
	if err != nil {
		return nil, fmt.Errorf("newReadVDispatcher(%d, %+v) = %v", fd, e, err)
	}
	return inboundDispatcher, nil
}

// Attach launches the goroutine that reads packets from the file descriptor and
// dispatches them via the provided dispatcher.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	// nil means the NIC is being removed.
	if dispatcher == nil && e.dispatcher != nil {
		for _, dispatcher := range e.inboundDispatchers {
			dispatcher.stop()
		}
		e.Wait()
		e.dispatcher = nil
		return
	}
	if dispatcher != nil && e.dispatcher == nil {
		e.dispatcher = dispatcher
		// Link endpoints are not savable. When transportation endpoints are
		// saved, they stop sending outgoing packets and all incoming packets
		// are rejected.
		for i := range e.inboundDispatchers {
			e.wg.Add(1)
			go func(i int) { // S/R-SAFE: See above.
				e.dispatchLoop(e.inboundDispatchers[i])
				e.wg.Done()
			}(i)
		}
	}
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *endpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.caps
}

// MaxHeaderLength returns the maximum size of the link-layer header.
func (e *endpoint) MaxHeaderLength() uint16 {
	return uint16(e.hdrSize)
}

// LinkAddress returns the link address of this endpoint.
func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return e.addr
}

// Wait implements stack.LinkEndpoint.Wait. It waits for the endpoint to stop
// reading from its FD.
func (e *endpoint) Wait() {
	e.wg.Wait()
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *endpoint) AddHeader(pkt *stack.PacketBuffer) {
	if e.hdrSize > 0 {
		// Add ethernet header if needed.
		eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
		eth.Encode(&header.EthernetFields{
			SrcAddr: pkt.EgressRoute.LocalLinkAddress,
			DstAddr: pkt.EgressRoute.RemoteLinkAddress,
			Type:    pkt.NetworkProtocolNumber,
		})
	}
}

// writePackets writes outbound packets to the file descriptor. If it is not
// currently writable, the packet is dropped.
// Way more simplified than og impl, ref: github.com/google/gvisor/issues/7125
func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	// Preallocate to avoid repeated reallocation as we append to batch.
	// batchSz is 47 because when SWGSO is in use then a single 65KB TCP
	// segment can get split into 46 segments of 1420 bytes and a single 216
	// byte segment.
	const batchSz = 47
	fd := e.fds[0].fd
	batch := make([]unix.Iovec, 0, batchSz)
	packets := 0
	// for _, pkt := range pkts.AsSlice() {
	for pkt := pkts.Front(); pkt != nil; pkt = pkt.Next() {
		views := pkt.Views()
		for _, v := range views {
			batch = rawfile.AppendIovecFromBytes(batch, v, len(views))
		}
		packets += 1
	}

	// TODO: a single pkt.View may be spread out across two writes
	l := len(batch)
	for i := 0; i < l; i += e.writevMaxIovs {
		j := i + e.writevMaxIovs
		if j > l {
			j = l
		}
		if err := rawfile.NonBlockingWriteIovec(fd, batch[i:j]); err != nil {
			log.Errorf("ns.e.WritePackets: err(%v); wrote iovec(%d/%d) in pkts(%d)", err, i, l, packets)
			return 0, err
		}
	}

	log.Infof("ns.e.WritePackets (to tun): bytes(%d)/pkts(%d)", l, packets)
	return packets, nil
}

// dispatchLoop reads packets from the file descriptor in a loop and dispatches
// them to the network stack.
func (e *endpoint) dispatchLoop(inboundDispatcher linkDispatcher) tcpip.Error {
	for {
		cont, err := inboundDispatcher.dispatch()
		if err != nil || !cont {
			return err
		}
	}
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (e *endpoint) ARPHardwareType() header.ARPHardwareType {
	if e.hdrSize > 0 {
		return header.ARPHardwareEther
	}
	return header.ARPHardwareNone
}

// Unused: InjectInbound injects an inbound packet.
func (e *endpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	log.Debugf("ns.e.inject-inbound(from-tun) %d pkt(%v)", protocol, pkt.Hash)
	e.dispatcher.DeliverNetworkPacket(protocol, pkt)
}

// Unused: InjectOutobund implements stack.InjectableEndpoint.InjectOutbound.
func (e *endpoint) InjectOutbound(dest tcpip.Address, packet []byte) tcpip.Error {
	log.Debugf("ns.e.inject-outbound(to-tun) to dst(%v)", dest)
	return rawfile.NonBlockingWrite(e.fds[0].fd, packet)
}
