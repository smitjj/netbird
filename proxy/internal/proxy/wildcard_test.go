package proxy

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

// echoedRequest is what an echo backend reports about the request it received.
type echoedRequest struct {
	Backend        string `json:"backend"`
	Host           string `json:"host"`
	Path           string `json:"path"`
	ForwardedHost  string `json:"x_forwarded_host"`
	ForwardedProto string `json:"x_forwarded_proto"`
	ForwardedFor   string `json:"x_forwarded_for"`
	ForwardedPort  string `json:"x_forwarded_port"`
}

// newEchoBackend starts a real HTTP server that answers every request with
// the routing-relevant parts of the request it received.
func newEchoBackend(t *testing.T, name string) *url.URL {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(echoedRequest{
			Backend:        name,
			Host:           r.Host,
			Path:           r.URL.Path,
			ForwardedHost:  r.Header.Get("X-Forwarded-Host"),
			ForwardedProto: r.Header.Get("X-Forwarded-Proto"),
			ForwardedFor:   r.Header.Get("X-Forwarded-For"),
			ForwardedPort:  r.Header.Get("X-Forwarded-Port"),
		})
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return u
}

func addTestMapping(rp *ReverseProxy, id types.ServiceID, host string, target *url.URL, passHost bool) {
	rp.AddMapping(Mapping{
		ID:             id,
		AccountID:      "acct-1",
		Host:           host,
		PassHostHeader: passHost,
		Paths:          map[string]*PathTarget{"/": {URL: target}},
	})
}

// serveThrough sends a request for host through the reverse proxy and decodes
// what the backend saw. A non-200 status is returned with a nil echo.
func serveThrough(t *testing.T, rp *ReverseProxy, host string, withTLS bool) (int, *echoedRequest) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/some/path", nil)
	req.Host = host
	req.RemoteAddr = "203.0.113.7:51234"
	if withTLS {
		req.TLS = &tls.ConnectionState{ServerName: host}
	}
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return rec.Code, nil
	}
	var got echoedRequest
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got), "decode backend echo")
	return rec.Code, &got
}

// TestServeHTTP_WildcardRouting covers the issue #5910 scenario end to end: one
// service on *.prototypes.example.com forwards every single-label subdomain to
// one backend with the original Host intact, so a downstream reverse proxy can
// do the final routing, while an exact service under the same pattern wins.
func TestServeHTTP_WildcardRouting(t *testing.T) {
	wildcardBackend := newEchoBackend(t, "wildcard")
	exactBackend := newEchoBackend(t, "exact")

	rp := NewReverseProxy(http.DefaultTransport, "auto", nil, nil)
	addTestMapping(rp, "svc-wildcard", "*.prototypes.example.com", wildcardBackend, true)
	addTestMapping(rp, "svc-exact", "api.prototypes.example.com", exactBackend, true)

	for _, host := range []string{
		"a.prototypes.example.com",
		"b.prototypes.example.com",
		"foo.prototypes.example.com",
		"test123.prototypes.example.com",
	} {
		t.Run(host, func(t *testing.T) {
			code, got := serveThrough(t, rp, host, true)
			require.Equal(t, http.StatusOK, code, "wildcard host must be routed")
			assert.Equal(t, "wildcard", got.Backend, "request should reach the wildcard backend")
			assert.Equal(t, host, got.Host, "backend must receive the original Host, not the pattern")
			assert.Equal(t, host, got.ForwardedHost, "X-Forwarded-Host should carry the original host")
			assert.Equal(t, "https", got.ForwardedProto, "X-Forwarded-Proto should reflect the TLS frontend")
			assert.Equal(t, "203.0.113.7", got.ForwardedFor, "X-Forwarded-For should carry the client IP")
			assert.Equal(t, "443", got.ForwardedPort, "X-Forwarded-Port should default to 443 for https")
			assert.Equal(t, "/some/path", got.Path, "path should be forwarded unchanged")
		})
	}

	t.Run("exact host overrides wildcard", func(t *testing.T) {
		code, got := serveThrough(t, rp, "api.prototypes.example.com", true)
		require.Equal(t, http.StatusOK, code)
		assert.Equal(t, "exact", got.Backend, "exact service must win over the wildcard")
		assert.Equal(t, "api.prototypes.example.com", got.Host, "exact service keeps its Host")
	})

	t.Run("host with port matches wildcard", func(t *testing.T) {
		code, got := serveThrough(t, rp, "a.prototypes.example.com:8443", true)
		require.Equal(t, http.StatusOK, code)
		assert.Equal(t, "wildcard", got.Backend, "port must be ignored when matching")
		assert.Equal(t, "a.prototypes.example.com:8443", got.Host, "original Host including port is preserved")
	})

	for _, host := range []string{
		"prototypes.example.com",
		"a.b.prototypes.example.com",
		"a.other.example.com",
		"aprototypes.example.com",
		"*.prototypes.example.com",
	} {
		t.Run("no match "+host, func(t *testing.T) {
			code, _ := serveThrough(t, rp, host, true)
			assert.Equal(t, http.StatusNotFound, code, "host %q must not match the wildcard", host)
		})
	}
}

// TestServeHTTP_WildcardWithoutPassHostHeader checks that a wildcard service
// that does not pass the Host header still behaves like an exact one: the Host
// becomes the backend address, never the wildcard pattern, and the original
// name stays available in X-Forwarded-Host.
func TestServeHTTP_WildcardWithoutPassHostHeader(t *testing.T) {
	backend := newEchoBackend(t, "wildcard")
	rp := NewReverseProxy(http.DefaultTransport, "auto", nil, nil)
	addTestMapping(rp, "svc-wildcard", "*.prototypes.example.com", backend, false)

	code, got := serveThrough(t, rp, "a.prototypes.example.com", false)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, backend.Host, got.Host, "Host should be rewritten to the backend address")
	assert.Equal(t, "a.prototypes.example.com", got.ForwardedHost, "X-Forwarded-Host keeps the original name")
	assert.Equal(t, "http", got.ForwardedProto, "X-Forwarded-Proto reflects the plain HTTP frontend")
}

// TestServeHTTP_ExactRoutingUnchanged is a regression check that exact-host
// services behave exactly as before when no wildcard is registered.
func TestServeHTTP_ExactRoutingUnchanged(t *testing.T) {
	backend := newEchoBackend(t, "exact")
	rp := NewReverseProxy(http.DefaultTransport, "auto", nil, nil)
	addTestMapping(rp, "svc-exact", "app.example.com", backend, false)

	code, got := serveThrough(t, rp, "app.example.com", true)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "exact", got.Backend)
	assert.Equal(t, backend.Host, got.Host, "Host is rewritten to the backend when not passed through")
	assert.Equal(t, "app.example.com", got.ForwardedHost, "X-Forwarded-Host carries the public name")

	code, _ = serveThrough(t, rp, "other.app.example.com", true)
	assert.Equal(t, http.StatusNotFound, code, "subdomains of an exact service must not match it")
}

// TestServeHTTP_WildcardMappingRemoval checks that removing the exact service
// lets its name fall back to the wildcard, and removing the wildcard stops
// routing for every host beneath it.
func TestServeHTTP_WildcardMappingRemoval(t *testing.T) {
	wildcardBackend := newEchoBackend(t, "wildcard")
	exactBackend := newEchoBackend(t, "exact")
	rp := NewReverseProxy(http.DefaultTransport, "auto", nil, nil)
	addTestMapping(rp, "svc-wildcard", "*.prototypes.example.com", wildcardBackend, true)
	addTestMapping(rp, "svc-exact", "api.prototypes.example.com", exactBackend, true)

	require.True(t, rp.RemoveMapping(Mapping{Host: "api.prototypes.example.com"}), "exact mapping should exist")
	code, got := serveThrough(t, rp, "api.prototypes.example.com", true)
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "wildcard", got.Backend, "without the exact service the wildcard takes over")

	require.True(t, rp.RemoveMapping(Mapping{Host: "*.prototypes.example.com"}), "wildcard mapping should exist")
	code, _ = serveThrough(t, rp, "a.prototypes.example.com", true)
	assert.Equal(t, http.StatusNotFound, code, "no routing once the wildcard is removed")
}
