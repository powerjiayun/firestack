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
//     Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.

package wg

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"unsafe"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"golang.org/x/sys/unix"
)

// from: github.com/WireGuard/wireguard-go/blob/12269c27/conn/gso_linux.go

// TODO: GSO/GRO and mmsgs in pkg net: github.com/golang/go/issues/45886

const sizeOfGSOData = 2

// gsoControlSize returns the recommended buffer size for pooling UDP
// offloading control data.
var gsoControlSize = unix.CmsgSpace(sizeOfGSOData)

// getGSOSize parses control for UDP_GRO and if found returns its GSO size data.
func getGSOSize(control []byte) (int, error) {
	var (
		hdr  unix.Cmsghdr
		data []byte
		rem  = control
		err  error
	)

	for len(rem) > unix.SizeofCmsghdr {
		hdr, data, rem, err = unix.ParseOneSocketControlMessage(rem)
		if err != nil {
			return 0, fmt.Errorf("error parsing socket control message: %w", err)
		}
		if hdr.Level == unix.SOL_UDP && hdr.Type == unix.UDP_GRO && len(data) >= sizeOfGSOData {
			var gso uint16
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&gso)), sizeOfGSOData), data[:sizeOfGSOData])
			return int(gso), nil
		}
	}
	return 0, nil
}

// setGSOSize sets a UDP_SEGMENT in control based on gsoSize. It leaves existing
// data in control untouched.
func setGSOSize(control *[]byte, gsoSize uint16) {
	existingLen := len(*control)
	avail := cap(*control) - existingLen
	space := unix.CmsgSpace(sizeOfGSOData)
	if avail < space {
		return
	}
	*control = (*control)[:cap(*control)]
	gsoControl := (*control)[existingLen:]
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&(gsoControl)[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(sizeOfGSOData))
	// github.com/WireGuard/wireguard-go/commit/f502ec3fad116d11109529bcf283e464f4822c18
	copy((gsoControl)[unix.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&gsoSize)), sizeOfGSOData))
	*control = (*control)[:existingLen+space]
}

// from: github.com/WireGuard/wireguard-go/blob/12269c276/conn/features_linux.go
func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool) {
	rc, err := conn.SyscallConn()
	if err != nil {
		log.W("wg: gso: syscall err: %v", err)
		return
	}
	if rc == nil || core.IsNil(rc) {
		log.W("wg: gso: syscall conn nil")
		return
	}
	err = rc.Control(func(fd uintptr) {
		_, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		txOffload = errSyscall == nil
		opt, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO)
		rxOffload = errSyscall == nil && opt == 1
	})
	if err != nil {
		log.W("wg: gso: no support; err: %v", err)
		return false, false
	}
	log.I("wg: gso: txOffload: %v, rxOffload: %v", txOffload, rxOffload)
	return txOffload, rxOffload
}

func supportsBatchRw() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "android"
}

// from: github.com/WireGuard/wireguard-go/blob/12269c276/conn/errors_linux.go#
func shouldDisableUDPGSOOnError(err error) bool {
	if err == nil {
		return false
	}
	var serr *os.SyscallError
	if errors.As(err, &serr) {
		// EIO is returned by udp_send_skb() if the device driver does not have
		// tx checksumming enabled, which is a hard requirement of UDP_SEGMENT.
		// See:
		// https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/tree/man7/udp.7?id=806eabd74910447f21005160e90957bde4db0183#n228
		// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/udp.c?h=v6.2&id=c9c3395d5e3dcc6daee66c6908354d47bf98cb0c#n942
		eio := serr != nil && serr.Err == unix.EIO
		if eio {
			log.W("wg: gso: EIO: %v", eio)
		}
		return eio
	}
	return false
}
