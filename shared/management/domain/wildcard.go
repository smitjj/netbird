package domain

import (
	"errors"
	"strings"
)

const wildcardPrefix = "*."

// IsWildcard reports whether d is a wildcard pattern such as *.example.com.
func IsWildcard(d string) bool {
	return strings.HasPrefix(d, wildcardPrefix)
}

// ValidateWildcard checks that pattern is a wildcard of the form *.example.com:
// a single leading "*" label followed by a valid domain of at least two labels.
// Wildcards elsewhere in the name and bare top-level wildcards such as *.com are
// rejected.
func ValidateWildcard(pattern string) error {
	if !IsWildcard(pattern) {
		return errors.New("wildcard domain must start with \"*.\"")
	}
	parent := strings.TrimPrefix(pattern, wildcardPrefix)
	if strings.Contains(parent, "*") {
		return errors.New("wildcard domain may only contain a single leading \"*.\" label")
	}
	if !IsValidDomainNoWildcard(parent) {
		return errors.New("wildcard domain must be \"*.\" followed by a valid domain name")
	}
	if !strings.Contains(parent, ".") {
		return errors.New("wildcard domain must cover a domain with at least two labels, such as *.example.com")
	}
	return nil
}

// WildcardFor returns the wildcard pattern that covers host with exactly one
// label, so foo.example.com yields *.example.com. Like certificate wildcards
// (RFC 6125 section 6.4.3), a pattern never covers deeper names or its own
// parent. It reports false when host cannot be covered by a valid pattern.
func WildcardFor(host string) (string, bool) {
	if strings.Contains(host, "*") {
		return "", false
	}
	label, parent, ok := strings.Cut(host, ".")
	if !ok || label == "" || !strings.Contains(parent, ".") {
		return "", false
	}
	return wildcardPrefix + parent, true
}

// LookupHost returns the entry registered for host, preferring an exact entry
// over the wildcard pattern that covers it. A host that itself contains a
// wildcard never matches, so a client cannot address a pattern directly.
func LookupHost[K ~string, V any](entries map[K]V, host string) (V, bool) {
	var zero V
	if strings.Contains(host, "*") {
		return zero, false
	}
	if v, ok := entries[K(host)]; ok {
		return v, true
	}
	pattern, ok := WildcardFor(host)
	if !ok {
		return zero, false
	}
	v, ok := entries[K(pattern)]
	return v, ok
}
