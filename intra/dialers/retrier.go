// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     Copyright 2019 The Outline Authors
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

package dialers

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/celzero/firestack/intra/core"
	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/protect"
	"github.com/celzero/firestack/intra/settings"
)

type zeroNetAddr struct{}

func (zeroNetAddr) Network() string { return "no" }
func (zeroNetAddr) String() string  { return "none" }

const maxRetryCount = 3

// retrier implements the DuplexConn interface and must
// be typecastable to *net.TCPConn (see: xdial.DialTCP)
// inheritance: go.dev/play/p/mMiQgXsPM7Y
type retrier struct {
	dialer     *protect.RDial
	dialerOpts settings.DialerOpts
	raddr      *net.TCPAddr
	laddr      *net.TCPAddr // laddr may be nil; TCPAddr.IP may be nil.

	// Flags indicating whether the caller has called CloseRead and CloseWrite.
	readDone  atomic.Bool
	writeDone atomic.Bool

	// mutex is a lock that guards conn, retryCount, tee, timeout,
	// retryErr, retryDoneCh, readDeadline, and writeDeadline.
	// After retryDoneCh is closed, these values will not be
	// modified again so locking is no longer required for reads.
	mutex sync.Mutex

	// the current underlying connection.  It is only modified by the reader
	// thread, so the reader functions may access it without acquiring a lock.
	// nb: if embedding TCPConn; override its WriteTo instead of just ReadFrom
	// as io.Copy prefers WriteTo over ReadFrom; or use core.Pipe
	conn core.DuplexConn

	// External read and write deadlines.  These need to be stored here so that
	// they can be re-applied in the event of a retry.
	readDeadline  time.Time
	writeDeadline time.Time
	// Time to wait between the 1st write & the 1st read before triggering a retry.
	timeout time.Duration
	// tee is the contents written before the first read.  It is initially empty,
	// and is cleared when the first byte is received.
	tee []byte
	// retryErr is set to the error from the last retry, if any.
	retryErr   error
	retryCount uint8
	// Flag indicating when retry is finished or unnecessary.
	retryDoneCh chan struct{} // always unbuffered
}

var _ core.DuplexConn = (*retrier)(nil)

// Helper functions for reading flags.
// In this package, a "flag" is a thread-safe single-use status indicator that
// starts in the "open" state and transitions to "closed" when close() is called.
// It is implemented as a channel over which no data is ever sent.
// Some advantages of this implementation:
//   - The language enforces the one-way transition.
//   - Nonblocking and blocking access are both straightforward.
//   - Checking the status of a closed flag should be extremely fast (although currently
//     it's not optimized: https://github.com/golang/go/issues/32529)
func closed(c <-chan struct{}) bool {
	select {
	case <-c: // The channel has been closed.
		return true
	default:
		return false
	}
}

// retryCompleted returns true if the retry is complete or unnecessary.
func (r *retrier) retryCompleted() bool {
	return closed(r.retryDoneCh)
}

// Given rtt of a successful socket connection (SYN sent - SYNACK received),
// returns a timeout for replies to the first segment sent on this socket.
func calcTimeout(rtt time.Duration) time.Duration {
	// These values were chosen to have a <1% false positive rate based on test data.
	// False positives trigger an unnecessary retry, which can make connections slower, so they are
	// worth avoiding.  However, overly long timeouts make retry slower and less useful.
	return 800*time.Millisecond + max(2*rtt, 100*time.Millisecond)
}

// DialWithSplitRetry returns a TCP connection that transparently retries by
// splitting the initial upstream segment if the socket closes without receiving a
// reply.  Like net.Conn, it is intended for two-threaded use, with one thread calling
// Read and CloseRead, and another calling Write, ReadFrom, and CloseWrite.
// `dialer` will be used to establish the connection.
// `addr` is the destination.
func DialWithSplitRetry(d *protect.RDial, laddr, raddr *net.TCPAddr) (*retrier, error) {
	r := &retrier{
		dialer:      d,
		dialerOpts:  settings.GetDialerOpts(),
		laddr:       laddr, // may be nil
		raddr:       raddr, // must not be nil
		retryDoneCh: make(chan struct{}),
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, err := r.dialLocked(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *retrier) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := r.conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	log.W("retrier: not a syscall.Conn: %T", r.conn)
	return nil, syscall.EINVAL
}

func (r *retrier) dialStratLocked() (strat int32, err error) {
	auto := r.dialerOpts.Strat == settings.SplitAuto
	retryStrat := r.dialerOpts.Retry
	split := r.dialerOpts.Strat != settings.SplitNever

	switch retryStrat {
	case settings.RetryNever:
		if r.retryCount >= 1 {
			err = errNoRetrier // retry not allowed
			return
		}
		split = split && r.retryCount == 0 // split at 1st attempt
	case settings.RetryWithSplit:
		split = split && r.retryCount >= 1 // split after 1st attempt
	case settings.RetryAfterSplit:
		split = split && r.retryCount == 0 // split at 1st attempt
		if auto {
			// split at all attempts except the last
			split = split && r.retryCount < maxRetryCount
		}
	}

	if !split {
		strat = settings.SplitNever
	} else if auto {
		cycle := r.retryCount % maxRetryCount
		switch retryStrat {
		case settings.RetryNever:
			// only one attempt allowed; neither retried nor split
			strat = settings.SplitTCPOrTLS
		case settings.RetryWithSplit:
			// if retrying (retryCount > 0), always split
			if cycle == 1 {
				strat = settings.SplitTCPOrTLS
			} else if cycle == 2 {
				strat = settings.SplitDesync
			} else { // split is either true or false
				strat = settings.SplitTCP
			}
		case settings.RetryAfterSplit:
			// split for the first two attempts
			if cycle == 0 {
				strat = settings.SplitTCPOrTLS
			} else if cycle == 1 {
				strat = settings.SplitDesync
			} else { // split is false, so strat does not matter
				strat = settings.SplitTCP
			}
		}
	} else {
		strat = r.dialerOpts.Strat
	}

	return
}

// dialLocked establishes a new connection to r.raddr and closes existing, if any.
// Sets r.conn on non-errors and timeout as calculated from round-trip time.
func (r *retrier) dialLocked() (c core.DuplexConn, err error) {
	clos(r.conn) // close existing connection, if any

	strat, err := r.dialStratLocked()
	if err != nil {
		return
	}

	begin := time.Now()
	c, err = r.doDialLocked(strat)
	rtt := time.Since(begin)

	r.conn = c // c may be nil
	r.timeout = calcTimeout(rtt)

	logeif(err)("retrier: dial(%s) %s->%s; strat: %d, rtt: %dms; err? %v",
		r.dialerOpts, laddr(c), r.raddr, strat, rtt.Milliseconds(), err)

	return
}

// dialStrat returns a core.DuplexConn to r.raddr using a specified strategy, strat,
// which is one of the settings.Split* constants.
func (r *retrier) doDialLocked(dialStrat int32) (_ core.DuplexConn, err error) {
	var conn *net.TCPConn

	// r.raddr may be nil or laddr.IP may be nil.
	switch dialStrat {
	case settings.SplitNever:
		return r.dialer.DialTCP(r.raddr.Network(), r.laddr, r.raddr)
	case settings.SplitDesync:
		return dialWithSplitAndDesync(r.dialer, r.laddr, r.raddr)
	case settings.SplitTCP, settings.SplitTCPOrTLS:
		fallthrough
	default:
	}
	conn, err = r.dialer.DialTCP(r.raddr.Network(), r.laddr, r.raddr)
	if err != nil || conn == nil {
		return nil, err
	}
	// todo: strat must be tcp or tls
	return &splitter{conn: conn, strat: dialStrat}, nil
}

// retryWriteReadLocked closes the current connection, dials a new one, and writes
// the first segment after splitting according to specified dial strategy.
// Returns an error if the dial fails or if the splits could not be written.
func (r *retrier) retryWriteReadLocked(buf []byte) (int, error) {
	// r.dialLocked also closes provisional socket
	newConn, err := r.dialLocked()
	if err != nil || newConn == nil {
		return 0, core.OneErr(err, errNoConn)
	}

	var nw int
	nw, r.retryErr = newConn.Write(r.tee)
	logeif(r.retryErr)("retrier: retryLocked: strat(%s) %s->%s; write? %d/%d; err? %v",
		r.dialerOpts, laddr(newConn), r.raddr, nw, len(r.tee), r.retryErr)
	if r.retryErr != nil {
		return 0, r.retryErr
	}

	// while we were creating the new socket, the caller might have called CloseRead
	// or CloseWrite on the old socket. Copy that state to the new socket.
	// CloseRead and CloseWrite are idempotent, so this is safe even if the user's
	// action actually affected the new socket.
	readdone := r.readDone.Load()
	writedone := r.writeDone.Load()
	if readdone {
		core.CloseTCPRead(newConn)
	} else {
		_ = newConn.SetReadDeadline(r.readDeadline)
	}
	// caller might have set read or write deadlines before the retry.
	if writedone {
		core.CloseTCPWrite(newConn)
	} else {
		_ = newConn.SetWriteDeadline(r.writeDeadline)
	}

	return newConn.Read(buf)
}

// CloseRead closes r.conn for reads, and the read flag.
func (r *retrier) CloseRead() error {
	r.readDone.Store(true)
	r.mutex.Lock()
	defer r.mutex.Unlock()
	core.CloseOp(r.conn, core.CopR)
	return nil
}

// Read data from r.conn into buf
func (r *retrier) Read(buf []byte) (n int, err error) {
	c := r.conn
	if c == nil || core.IsNil(c) { // should rarely happen
		log.E("retrier: read: [] <= %s, no conn", r.raddr)
		return 0, errNoConn
	}

	note := log.V

	n, err = c.Read(buf)      // r.conn may be provisional or final connection
	if n == 0 && err == nil { // no data and no error
		note("retrier: read: no data; retrying [%s<=%s]", laddr(c), r.raddr)
		return // nothing yet to retry; on to next read
	}
	logeor(err, note)("retrier: read: [%s<=%s] %d; err: %v", laddr(c), r.raddr, n, err)

	note = log.D
	if !r.retryCompleted() {
		r.mutex.Lock()
		defer r.mutex.Unlock()

		if !r.retryCompleted() {
			defer close(r.retryDoneCh) // signal that retry is complete or unnecessary
			// retry on errs like timeouts or connection resets
			for (c == nil || err != nil) && r.retryCount < maxRetryCount {
				r.retryCount++
				n, err = r.retryWriteReadLocked(buf)
				c = r.conn // re-assign c to newConn, if any; may be nil
				if c == nil {
					err = core.OneErr(err, errNoConn)
				}
				logeor(err, log.I)("retrier: read# %d: [%s<=%s] %d; err? %v",
					r.retryCount, laddr(c), r.raddr, n, err)
			}
			if c != nil && core.IsNotNil(c) {
				_ = c.SetReadDeadline(r.readDeadline)
				_ = c.SetWriteDeadline(r.writeDeadline)
			}
			r.tee = nil // discard teed data
			return
		}
		logeor(err, note)("retrier: read: already retried! [%s<=%s] %d; err? %v", laddr(c), r.raddr, n, err)
	} // else: just one read is enough; no retry needed
	return
}

func (r *retrier) teeSend(b []byte) (n int, didWrite bool, src net.Addr, err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	c := r.conn
	if c == nil || core.IsNil(c) {
		err = errNilConn
		log.E("retrier: send(tee): [] => %s, no conn; sz(%d)", r.raddr, len(b))
		return
	}
	src = laddr(c)
	if !r.retryCompleted() { // first write
		n, err = c.Write(b)
		// capture first write, aka "hello"
		r.tee = append(r.tee, b...)
		// all of b was written to r.tee if not to c
		// require a response or another write within a short timeout.
		_ = c.SetReadDeadline(time.Now().Add(r.timeout))
		didWrite = true
	}
	return
}

// Write data in b to retrier's underlying conn, r.conn
func (r *retrier) Write(b []byte) (int, error) {
	// Double-checked locking pattern.  This avoids lock acquisition on
	// every packet after retry completes, while also ensuring that r.tee is
	// empty at steady-state.
	if !r.retryCompleted() {
		n, sentAndCopied, src, err := r.teeSend(b)

		note := log.D
		if sentAndCopied {
			note = log.I
		}

		logeor(err, note)("retrier: write: first?(%t) [%s=>%s] %d; 1st write-err? %v",
			sentAndCopied, src, r.raddr, n, err)

		if sentAndCopied {
			// since Write() does not wait for <-retryDoneCh if there are no errors,
			// it is possible that ReadFrom() -> copyOnce() is called before retryDoneCh
			// is closed, resulting in two Write() calls, and r.tee containing buffers
			// the size of two Writes()
			if err == nil {
				return n, nil
			}

			start := time.Now()
			// write error on the provisional socket should be handled
			// by the retry procedure. Block until we have a final socket (which will
			// already have replayed r.tee), and retry.
			<-r.retryDoneCh

			r.mutex.Lock()
			elapsed := time.Since(start).Milliseconds()
			if r.retryErr != nil {
				r.mutex.Unlock()
				// r.conn may be nil or closed
				log.E("retrier: write: retry failed [%s=>%s] in %dms; old -> new: %v => %v",
					laddr(r.conn), r.raddr, elapsed, err, r.retryErr)
				return n, err // pass on the og error
			}
			r.mutex.Unlock()

			// if len(leftover) > 0 {
			//	m, err = newConn.Write(leftover)
			//  return n + m, err
			// }

			// retry succeeded, nil error
			// all of b was written to r.tee which was replayed
			return len(b), nil
		} // not sent by teeSend; do a normal write
	}

	// retryCompleted() is true, so r.conn is final and doesn't need locking
	if c := r.conn; c == nil {
		log.E("retrier: write: [] => %s, no conn", r.raddr)
		return 0, errNilConn
	} else {
		return c.Write(b)
	}
}

// ReadFrom reads data from reader via r.conn.ReadFrom, after (as needed)
// retries are done; before which reads are delegated to copyOnce.
func (r *retrier) ReadFrom(reader io.Reader) (bytes int64, err error) {
	copies := 0
	for !r.retryCompleted() {
		b, e := copyOnce(r, reader)
		copies++
		bytes += b
		logeif(err)("retrier: readfrom: copyOnce #%d; sz: %d/%d; err: %v", copies, b, bytes, err)
		if e != nil {
			return bytes, e
		}
	}

	c := r.conn
	if c == nil || core.IsNil(c) {
		log.E("retrier: readfrom: [] <= %s, no conn; after# %d: sz(%d)", r.raddr, copies, bytes)
		return bytes, io.ErrUnexpectedEOF
	}

	// retryCompleted() is true, so r.conn is final and doesn't need locking
	var b int64
	b, err = c.ReadFrom(reader)
	bytes += b

	logeif(err)("retrier: readfrom: done; sz: %d; err: %v", bytes, err)
	return
}

// CloseWrite closes r.conn for writes, the write flag.
func (r *retrier) CloseWrite() error {
	r.writeDone.Store(true)
	r.mutex.Lock()
	defer r.mutex.Unlock()
	core.CloseOp(r.conn, core.CopW)
	return nil
}

// Close closes the connection and the read and write flags.
func (r *retrier) Close() error {
	// also close the read and write flags
	return errors.Join(r.CloseRead(), r.CloseWrite())
}

// LocalAddr behaves slightly strangely: its value may change as a
// result of a retry.  However, LocalAddr is largely useless for
// TCP client sockets anyway, so nothing should be relying on this.
func (r *retrier) LocalAddr() net.Addr {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if c := r.conn; c != nil && core.IsNotNil(c) {
		return c.LocalAddr()
	}
	return zeroNetAddr{}
}

// RemoteAddr returns the remote address of the connection.
func (r *retrier) RemoteAddr() net.Addr {
	return r.raddr
}

// SetReadDeadline sets the read deadline for the connection
// if the retry is complete, otherwise it does so after the retry.
func (r *retrier) SetReadDeadline(t time.Time) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.readDeadline = t
	// Don't enforce read deadlines until after the retry
	// is complete. Retry relies on setting its own read
	// deadline, and we don't want this to interfere.
	if r.retryCompleted() {
		if c := r.conn; c != nil && core.IsNotNil(c) {
			return c.SetWriteDeadline(t)
		}
		return errNoConn
	}
	return nil
}

// SetWriteDeadline sets the write deadline for the connection.
func (r *retrier) SetWriteDeadline(t time.Time) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.writeDeadline = t
	if c := r.conn; c != nil && core.IsNotNil(c) {
		return c.SetWriteDeadline(t)
	}
	return errNoConn
}

// SetDeadline sets the read and write deadlines for the connection.
// Read deadlines are set eventually depending on the status of retries.
func (r *retrier) SetDeadline(t time.Time) error {
	e1 := r.SetReadDeadline(t)
	e2 := r.SetWriteDeadline(t)
	return errors.Join(e1, e2)
}
