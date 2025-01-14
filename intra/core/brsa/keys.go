// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//    BSD-3-Clause License
//
//    Copyright (c) 2009 The Go Authors. All rights reserved.
//    Use of this source code is governed by a BSD-style
//    license that can be found in the LICENSE file.

// from: https://github.com/cloudflare/circl/tree/v1.3.7/blindsign

package blindrsa

import (
	"crypto/rsa"
	"math/big"
)

// BigPublicKey is the same as an rsa.PublicKey struct, except the public
// key is represented as a big integer as opposed to an int. For the partially
// blind scheme, this is required since the public key will typically be
// any value in the RSA group.
type BigPublicKey struct {
	N *big.Int
	E *big.Int
}

// Size returns the size of the public key.
func (pub *BigPublicKey) Size() int {
	return (pub.N.BitLen() + 7) / 8
}

// Marshal encodes the public key exponent (e).
func (pub *BigPublicKey) Marshal() []byte {
	buf := make([]byte, (pub.E.BitLen()+7)/8)
	pub.E.FillBytes(buf)
	return buf
}

// NewBigPublicKey creates a BigPublicKey from a rsa.PublicKey.
func NewBigPublicKey(pk *rsa.PublicKey) *BigPublicKey {
	return &BigPublicKey{
		N: pk.N,
		E: new(big.Int).SetInt64(int64(pk.E)),
	}
}

// CustomPublicKey is similar to rsa.PrivateKey, containing information needed
// for a private key used in the partially blind signature protocol.
type BigPrivateKey struct {
	Pk *BigPublicKey
	D  *big.Int
	P  *big.Int
	Q  *big.Int
}

// NewBigPrivateKey creates a BigPrivateKey from a rsa.PrivateKey.
func NewBigPrivateKey(sk *rsa.PrivateKey) *BigPrivateKey {
	return &BigPrivateKey{
		Pk: &BigPublicKey{
			N: sk.N,
			E: new(big.Int).SetInt64(int64(sk.PublicKey.E)),
		},
		D: sk.D,
		P: sk.Primes[0],
		Q: sk.Primes[1],
	}
}
