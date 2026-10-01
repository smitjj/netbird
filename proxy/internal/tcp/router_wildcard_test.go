package tcp

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

func TestRouter_LookupRouteWildcard(t *testing.T) {
	router := NewRouter(log.StandardLogger(), nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	router.AddRoute("*.prototypes.example.com", Route{Type: RouteHTTP, ServiceID: "svc-wildcard"})
	router.AddRoute("api.prototypes.example.com", Route{Type: RouteHTTP, ServiceID: "svc-exact"})

	tests := []struct {
		host  SNIHost
		svcID types.ServiceID
		found bool
	}{
		{host: "a.prototypes.example.com", svcID: "svc-wildcard", found: true},
		{host: "b.prototypes.example.com", svcID: "svc-wildcard", found: true},
		{host: "api.prototypes.example.com", svcID: "svc-exact", found: true},
		{host: "prototypes.example.com", found: false},
		{host: "a.b.prototypes.example.com", found: false},
		{host: "a.other.example.com", found: false},
		{host: "*.prototypes.example.com", found: false},
	}
	for _, tt := range tests {
		t.Run(string(tt.host), func(t *testing.T) {
			route, ok := router.lookupRoute(tt.host)
			assert.Equal(t, tt.found, ok, "found for SNI %q", tt.host)
			assert.Equal(t, tt.svcID, route.ServiceID, "service for SNI %q", tt.host)
		})
	}

	router.RemoveRoute("*.prototypes.example.com", "svc-wildcard")
	_, ok := router.lookupRoute("a.prototypes.example.com")
	assert.False(t, ok, "wildcard SNI must stop matching after the route is removed")
}

// TestRouter_WildcardSNIRouting drives real TLS connections through the router:
// a wildcard HTTP route catches every single-label SNI beneath it, while an
// exact TLS-passthrough route under the same pattern keeps its own traffic.
func TestRouter_WildcardSNIRouting(t *testing.T) {
	backendCert := generateSelfSignedCert(t)
	backendLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{backendCert}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backendLn.Close() })
	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(buf[:n])
	}()

	dialResolve := func(types.AccountID) (types.DialContextFunc, error) {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		}, nil
	}
	router := NewRouter(log.StandardLogger(), dialResolve, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	router.AddRoute("*.prototypes.example.com", Route{Type: RouteHTTP, ServiceID: "svc-wildcard"})
	router.AddRoute("db.prototypes.example.com", Route{
		Type:      RouteTCP,
		AccountID: "acct-1",
		ServiceID: "svc-db",
		Target:    backendLn.Addr().String(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = router.Serve(ctx, ln) }()

	for _, sni := range []string{"a.prototypes.example.com", "test123.prototypes.example.com"} {
		t.Run("wildcard "+sni, func(t *testing.T) {
			go func() {
				conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
				if err != nil {
					return
				}
				tlsConn := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true}) //nolint:gosec
				_ = tlsConn.Handshake()
				_ = tlsConn.Close()
			}()

			select {
			case conn := <-router.httpCh:
				assert.NotNil(t, conn, "wildcard SNI should reach the HTTP channel")
				_ = conn.Close()
			case <-time.After(5 * time.Second):
				t.Fatalf("SNI %q was not routed to the HTTP channel", sni)
			}
		})
	}

	t.Run("exact passthrough wins over wildcard", func(t *testing.T) {
		clientConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			ServerName:         "db.prototypes.example.com",
			InsecureSkipVerify: true, //nolint:gosec
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = clientConn.Close() })

		payload := []byte("exact route payload")
		_, err = clientConn.Write(payload)
		require.NoError(t, err)
		buf := make([]byte, 1024)
		n, err := clientConn.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, payload, buf[:n], "exact SNI should be relayed to its own backend, not the wildcard HTTP route")
	})
}
