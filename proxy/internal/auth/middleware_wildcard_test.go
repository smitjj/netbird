package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

// TestProtect_WildcardAppliesIPRestrictions guards against failing open: a
// request whose Host is covered only by a wildcard must still meet the
// wildcard service's restrictions instead of passing through as unknown.
func TestProtect_WildcardAppliesIPRestrictions(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	require.NoError(t, mw.AddDomain("*.prototypes.example.com", nil, "", 0, "acc1", "svc-wildcard",
		restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"203.0.113.0/24"}}), false, nil))

	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		host       string
		remoteAddr string
		wantCode   int
	}{
		{name: "allowed client on wildcard host", host: "a.prototypes.example.com", remoteAddr: "203.0.113.9:1000", wantCode: http.StatusOK},
		{name: "denied client on wildcard host", host: "a.prototypes.example.com", remoteAddr: "198.51.100.9:1000", wantCode: http.StatusForbidden},
		{name: "denied client on wildcard host with port", host: "b.prototypes.example.com:443", remoteAddr: "198.51.100.9:1000", wantCode: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+tt.host+"/", nil)
			req.Host = tt.host
			req.RemoteAddr = tt.remoteAddr
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			assert.Equal(t, tt.wantCode, rr.Code, "status for %s from %s", tt.host, tt.remoteAddr)
		})
	}
}

// TestProtect_ExactAuthOverridesWildcard checks that an authenticated exact
// service beneath a public wildcard keeps its authentication.
func TestProtect_ExactAuthOverridesWildcard(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	kp := generateTestKeyPair(t)
	require.NoError(t, mw.AddDomain("*.prototypes.example.com", nil, "", 0, "acc1", "svc-wildcard", nil, false, nil))
	require.NoError(t, mw.AddDomain("api.prototypes.example.com",
		[]Scheme{&stubScheme{method: auth.MethodPIN, promptID: "pin"}}, kp.PublicKey, time.Hour, "acc1", "svc-exact", nil, false, nil))

	backendHit := false
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHit = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "http://api.prototypes.example.com/", nil)
	req.Host = "api.prototypes.example.com"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.False(t, backendHit, "unauthenticated request to the exact service must not reach the backend")
	assert.NotEqual(t, http.StatusOK, rr.Code, "exact service must demand authentication")

	backendHit = false
	req = httptest.NewRequest(http.MethodGet, "http://other.prototypes.example.com/", nil)
	req.Host = "other.prototypes.example.com"
	cd := proxy.NewCapturedData("")
	req = req.WithContext(proxy.WithCapturedData(req.Context(), cd))
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.True(t, backendHit, "public wildcard host should pass through")
	assert.Equal(t, types.ServiceID("svc-wildcard"), cd.GetServiceID(), "access log should attribute the wildcard service")
}

func TestAddDomain_WildcardRejectsAuth(t *testing.T) {
	kp := generateTestKeyPair(t)

	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	err := mw.AddDomain("*.example.com", []Scheme{&stubScheme{method: auth.MethodPIN, promptID: "pin"}},
		kp.PublicKey, time.Hour, "acc1", "svc1", nil, false, nil)
	assert.Error(t, err, "wildcard domains must not accept authentication schemes")

	err = mw.AddDomain("*.example.com", nil, "", 0, "acc1", "svc1", nil, true, nil)
	assert.Error(t, err, "wildcard domains must not accept private access")

	_, exists := mw.getDomainConfig("a.example.com")
	assert.False(t, exists, "a rejected wildcard must not be registered")

	require.NoError(t, mw.AddDomain("*.example.com", nil, "", 0, "acc1", "svc1", nil, false, nil))
	_, exists = mw.getDomainConfig("a.example.com")
	assert.True(t, exists, "a public wildcard is registered")
}
