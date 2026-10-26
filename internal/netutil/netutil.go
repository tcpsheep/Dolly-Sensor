// Package netutil contains small network-address helpers shared across Dolly
// Sensor. Everything here is safe for concurrent readers once constructed.
package netutil

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// PrefixSet is an immutable set of CIDR ranges.
type PrefixSet struct {
	prefixes []netip.Prefix
	raw      []string
}

// ParsePrefixes parses and normalises a list of IP addresses and CIDR ranges.
// Bare addresses become host prefixes.
func ParsePrefixes(values []string) (*PrefixSet, error) {
	set := &PrefixSet{}
	seen := make(map[netip.Prefix]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		p, err := ParseIPOrPrefix(value)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		set.prefixes = append(set.prefixes, p)
		set.raw = append(set.raw, p.String())
	}
	sort.Slice(set.prefixes, func(i, j int) bool {
		a, b := set.prefixes[i], set.prefixes[j]
		if a.Bits() != b.Bits() {
			return a.Bits() < b.Bits()
		}
		return a.String() < b.String()
	})
	return set, nil
}

// ParseIPOrPrefix parses a single address or a CIDR range.
func ParseIPOrPrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("parse CIDR %q: %w", value, err)
		}
		addr := p.Addr().Unmap()
		if !addr.IsValid() {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", value)
		}
		bits := p.Bits()
		if addr.Is4() && p.Addr().Is6() {
			// IPv4-mapped IPv6 prefix: convert the address family and adjust bits.
			bits -= 96
		}
		if bits < 0 || bits > addr.BitLen() {
			return netip.Prefix{}, fmt.Errorf("invalid prefix length in %q", value)
		}
		return netip.PrefixFrom(addr, bits).Masked(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse address %q: %w", value, err)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// Contains reports whether addr is inside any prefix in the set.
func (s *PrefixSet) Contains(addr netip.Addr) bool {
	if s == nil || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, p := range s.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ContainsPrefix reports whether every address in prefix is covered by one
// prefix in the set. A host prefix is covered when its address is contained.
func (s *PrefixSet) ContainsPrefix(prefix netip.Prefix) bool {
	if s == nil || !prefix.IsValid() {
		return false
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return false
		}
		addr := prefix.Addr().Unmap()
		prefix = netip.PrefixFrom(addr, prefix.Bits()-96).Masked()
	}
	if !prefix.IsValid() {
		return false
	}
	for _, own := range s.prefixes {
		if own.Addr().BitLen() != prefix.Addr().BitLen() {
			continue
		}
		if own.Bits() <= prefix.Bits() && own.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

// PrefixFor returns the most specific prefix containing addr.
func (s *PrefixSet) PrefixFor(addr netip.Addr) (netip.Prefix, bool) {
	if s == nil || !addr.IsValid() {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	var best netip.Prefix
	found := false
	for _, p := range s.prefixes {
		if p.Contains(addr) && (!found || p.Bits() > best.Bits()) {
			best = p
			found = true
		}
	}
	return best, found
}

// Overlaps reports whether any prefix in the set overlaps p.
func (s *PrefixSet) Overlaps(p netip.Prefix) bool {
	if s == nil || !p.IsValid() {
		return false
	}
	for _, own := range s.prefixes {
		if own.Overlaps(p) {
			return true
		}
	}
	return false
}

// Len returns the number of prefixes.
func (s *PrefixSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.prefixes)
}

// Strings returns the normalised prefixes.
func (s *PrefixSet) Strings() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.raw))
	copy(out, s.raw)
	return out
}

// Prefixes returns a copy of the normalised prefixes.
func (s *PrefixSet) Prefixes() []netip.Prefix {
	if s == nil {
		return nil
	}
	out := make([]netip.Prefix, len(s.prefixes))
	copy(out, s.prefixes)
	return out
}

// ClampHost returns a host prefix for addr.
func ClampHost(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen())
}

// AddrString formats an address, returning an empty string for invalid values.
func AddrString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.Unmap().String()
}

// PrefixString formats a prefix, returning an empty string for invalid values.
func PrefixString(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return p.String()
}

// IsDefaultRoute reports whether p covers an entire address family.
func IsDefaultRoute(p netip.Prefix) bool {
	return p.IsValid() && p.Bits() == 0
}
