package dnsx

import (
	"net/netip"
	"strings"

	"github.com/celzero/firestack/intra/log"
	"github.com/celzero/firestack/intra/settings"
)

func (h *resolver) isDnsIpPort(addr netip.AddrPort) bool {
	for _, dnsaddr := range h.dnsaddrs {
		if addr.Addr().Compare(dnsaddr.Addr()) == 0 && addr.Port() == dnsaddr.Port() {
			return true
		}
	}
	return false
}

func (h *resolver) isDnsPort(addr netip.AddrPort) bool {
	// isn't h.fakedns.Port always expected to be 53?
	for _, dnsaddr := range h.dnsaddrs {
		if addr.Port() == dnsaddr.Port() {
			return true
		}
	}
	return false
}

func (h *resolver) isDns(ipport string) bool {
	if ipp, err := netip.ParseAddrPort(ipport); err != nil {
		return false
	} else {
		if !ipp.IsValid() || len(h.dnsaddrs) <= 0 {
			log.E("missing dst-addr(%v) or dns(%v)", ipp, h.dnsaddrs)
			return false
		}
		if h.trapIP() {
			if yes := h.isDnsIpPort(ipp); yes {
				return true
			}
		} else if h.trapPort() {
			if yes := h.isDnsPort(ipp); yes {
				return true
			}
		}
		return false
	}
}

func (h *resolver) trapIP() bool {
	return h.tunmode.DNSMode == settings.DNSModeIP
}

func (h *resolver) trapPort() bool {
	return h.tunmode.DNSMode == settings.DNSModePort
}

func (r *resolver) addDnsAddrs(csvaddr string) {
	addrs := strings.Split(csvaddr, ",")
	dnsaddrs := make([]netip.AddrPort, 0, len(addrs))
	count := 0
	for _, a := range addrs {
		if ipp, err := netip.ParseAddrPort(a); ipp.IsValid() && err == nil {
			dnsaddrs = append(dnsaddrs, ipp)
			count += 1
		} else {
			log.W("not valid fake udpaddr(%s <=> %s): %v", ipp, a, err)
		}
	}
	r.dnsaddrs = dnsaddrs[:count]
}
