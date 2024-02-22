// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package android

import "fmt"

const SummaryProxyLabel = "proxy:"

// DNSSummary is a summary of a DNS transaction, reported when it is complete.
type DNSSummary struct {
	Type        string  // dnscrypt, dns53, doh, odoh, dot
	ID          string  // transport id
	Latency     float64 // Response (or failure) latency in seconds
	QName       string  // query domain
	QType       int     // A, AAAA, SVCB, HTTPS, etc.
	RData       string  // response data, usually a csv of ips
	RCode       int     // response code
	RTtl        int     // response ttl
	Server      string
	RelayServer string // hop, if any; proxy or a relay server
	Status      int
	Blocklists  string // csv separated list of blocklists names, if any.
	Msg         string // final status message, if any
}

type NsOpts struct {
	// pid is the proxy to use for this query.
	PID string
	// csv of ips to answer for this query.
	IPCSV string
	// csv of transports ids to use for this query.
	TIDCSV string
}

func (s *DNSSummary) Str() string {
	return fmt.Sprintf("type: %s, id: %s, latency: %f, qname: %s, rdata: %s, rcode: %d, rttl: %d, server: %s, relay: %s, status: %d, blocklists: %s",
		s.Type, s.ID, s.Latency, s.QName, s.RData, s.RCode, s.RTtl, s.Server, s.RelayServer, s.Status, s.Blocklists)
}

func (s *DNSSummary) Copy() *DNSSummary {
	clone := new(DNSSummary)
	*clone = *s
	return clone
}

// FillInto copies non-zero values into other.
func (s *DNSSummary) FillInto(other *DNSSummary) {
	if other == nil || s == other {
		return
	}
	if len(s.Type) != 0 {
		other.Type = s.Type
	}
	if len(s.ID) != 0 {
		other.ID = s.ID
	}
	if s.Latency != 0 {
		other.Latency = s.Latency
	}

	// query portions are only filled in if they are empty
	if len(other.QName) == 0 {
		other.QName = s.QName
	}
	// dns.TypeNone = 0
	if other.QType == 0 {
		other.QType = s.QType
	}

	if len(s.RData) != 0 {
		other.RData = s.RData
	}
	// RcodeSuccess = 0
	other.RCode = s.RCode
	other.RTtl = s.RTtl
	other.Server = s.Server
	other.RelayServer = s.RelayServer
	other.Status = s.Status
	other.Blocklists = s.Blocklists
}

// DNSListener receives Summaries.
type DNSListener interface {
	OnQuery(domain string, qtyp int) *NsOpts
	OnResponse(*DNSSummary)
}