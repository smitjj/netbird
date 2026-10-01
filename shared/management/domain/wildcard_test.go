package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateWildcard(t *testing.T) {
	tests := []struct {
		pattern string
		valid   bool
	}{
		{pattern: "*.example.com", valid: true},
		{pattern: "*.prototypes.proxy.example.com", valid: true},
		{pattern: "*.xn--bcher-kva.example", valid: true},
		{pattern: "example.com", valid: false},
		{pattern: "*", valid: false},
		{pattern: "*.", valid: false},
		{pattern: "*.com", valid: false},
		{pattern: "**.example.com", valid: false},
		{pattern: "*foo.example.com", valid: false},
		{pattern: "foo.*.example.com", valid: false},
		{pattern: "*.*.example.com", valid: false},
		{pattern: "*.example.*", valid: false},
		{pattern: "*..example.com", valid: false},
		{pattern: "*.-bad.example.com", valid: false},
		{pattern: "*.exa mple.com", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			err := ValidateWildcard(tt.pattern)
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestWildcardFor(t *testing.T) {
	tests := []struct {
		host    string
		pattern string
		ok      bool
	}{
		{host: "foo.example.com", pattern: "*.example.com", ok: true},
		{host: "a.prototypes.proxy.example.com", pattern: "*.prototypes.proxy.example.com", ok: true},
		// The parent of a two-label host would be a top-level wildcard.
		{host: "example.com", ok: false},
		{host: "localhost", ok: false},
		{host: "", ok: false},
		{host: ".example.com", ok: false},
		{host: "*.example.com", ok: false},
		{host: "foo.*.example.com", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			pattern, ok := WildcardFor(tt.host)
			assert.Equal(t, tt.ok, ok, "ok for host %q", tt.host)
			assert.Equal(t, tt.pattern, pattern, "pattern for host %q", tt.host)
		})
	}
}

func TestLookupHost(t *testing.T) {
	type key string
	entries := map[key]string{
		"*.prototypes.example.com":   "wildcard",
		"api.prototypes.example.com": "exact",
		"plain.example.com":          "plain",
	}

	tests := []struct {
		name  string
		host  string
		want  string
		found bool
	}{
		{name: "exact host", host: "plain.example.com", want: "plain", found: true},
		{name: "wildcard a", host: "a.prototypes.example.com", want: "wildcard", found: true},
		{name: "wildcard b", host: "b.prototypes.example.com", want: "wildcard", found: true},
		{name: "wildcard test123", host: "test123.prototypes.example.com", want: "wildcard", found: true},
		{name: "exact overrides wildcard", host: "api.prototypes.example.com", want: "exact", found: true},
		{name: "wildcard does not cover its parent", host: "prototypes.example.com", found: false},
		{name: "wildcard covers a single label only", host: "a.b.prototypes.example.com", found: false},
		{name: "unrelated host", host: "a.other.example.com", found: false},
		{name: "suffix without label boundary", host: "aprototypes.example.com", found: false},
		{name: "literal pattern as host", host: "*.prototypes.example.com", found: false},
		{name: "empty host", host: "", found: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := LookupHost(entries, tt.host)
			assert.Equal(t, tt.found, found, "found for host %q", tt.host)
			assert.Equal(t, tt.want, got, "entry for host %q", tt.host)
		})
	}
}
