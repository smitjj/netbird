package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/netbirdio/netbird/proxy/internal/auth"
	"github.com/netbirdio/netbird/proxy/internal/conntrack"
	"github.com/netbirdio/netbird/proxy/internal/crowdsec"
	proxymetrics "github.com/netbirdio/netbird/proxy/internal/metrics"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	nbtcp "github.com/netbirdio/netbird/proxy/internal/tcp"
	"github.com/netbirdio/netbird/proxy/internal/types"
	udprelay "github.com/netbirdio/netbird/proxy/internal/udp"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type wildcardEcho struct {
	Backend        string `json:"backend"`
	Host           string `json:"host"`
	ForwardedHost  string `json:"x_forwarded_host"`
	ForwardedProto string `json:"x_forwarded_proto"`
	ForwardedFor   string `json:"x_forwarded_for"`
}

func newWildcardEchoBackend(t *testing.T, name string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(wildcardEcho{
			Backend:        name,
			Host:           r.Host,
			ForwardedHost:  r.Header.Get("X-Forwarded-Host"),
			ForwardedProto: r.Header.Get("X-Forwarded-Proto"),
			ForwardedFor:   r.Header.Get("X-Forwarded-For"),
		})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// newWildcardTestServer builds a proxy Server with the real SNI router, auth
// middleware and reverse proxy. Upstream requests use the host network so the
// test needs no embedded NetBird client.
func newWildcardTestServer(t *testing.T, ln net.Listener) *Server {
	t.Helper()
	logger := log.New()
	logger.SetOutput(io.Discard)

	meter, err := proxymetrics.New(context.Background(), noop.Meter{})
	require.NoError(t, err)

	return &Server{
		Logger:                logger,
		AllowWildcardServices: true,
		proxy:                 proxy.NewReverseProxy(http.DefaultTransport, "auto", nil, logger),
		auth:                  auth.NewMiddleware(logger, nil, nil),
		mainRouter: nbtcp.NewRouter(logger, func(types.AccountID) (types.DialContextFunc, error) {
			return (&net.Dialer{}).DialContext, nil
		}, ln.Addr()),
		meter:            meter,
		hijackTracker:    conntrack.HijackTracker{},
		crowdsecRegistry: crowdsec.NewRegistry("", "", log.NewEntry(logger)),
		crowdsecServices: make(map[types.ServiceID]bool),
		lastMappings:     make(map[types.ServiceID]*proto.ProxyMapping),
		portRouters:      make(map[uint16]*portRouter),
		svcPorts:         make(map[types.ServiceID][]uint16),
		udpRelays:        make(map[types.ServiceID]*udprelay.Relay),
	}
}

func httpMapping(id, domain, target string) *proto.ProxyMapping {
	return &proto.ProxyMapping{
		Type:           proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
		Id:             id,
		AccountId:      "acct-1",
		Domain:         domain,
		PassHostHeader: true,
		Auth:           &proto.Authentication{},
		Path:           []*proto.PathMapping{{Path: "/", Target: target}},
	}
}

// TestWildcardService_EndToEnd reproduces issue #5910 through the proxy
// runtime: TLS connections are routed by SNI on the shared listener,
// terminated with a static wildcard certificate, and forwarded by the reverse
// proxy to one backend with the original Host, so a downstream proxy such as
// Caddy can route each subdomain. An exact service under the pattern wins.
func TestWildcardService_EndToEnd(t *testing.T) {
	wildcardTarget := newWildcardEchoBackend(t, "wildcard")
	exactTarget := newWildcardEchoBackend(t, "exact")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	s := newWildcardTestServer(t, ln)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	require.NoError(t, s.setupMappingRoutes(ctx, httpMapping("svc-wildcard", "*.prototypes.example.com", wildcardTarget)))
	require.NoError(t, s.setupMappingRoutes(ctx, httpMapping("svc-exact", "api.prototypes.example.com", exactTarget)))

	certPEM, keyPEM := generateCertWithSANs(t, []string{"*.prototypes.example.com"})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(certPEM), "trust the test certificate")

	httpSrv := &http.Server{
		Handler:           s.auth.Protect(s.proxy),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = httpSrv.ServeTLS(s.mainRouter.HTTPListener(), "", "") }()
	t.Cleanup(func() { _ = httpSrv.Close() })
	go func() { _ = s.mainRouter.Serve(ctx, ln) }()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
			},
		},
	}
	t.Cleanup(client.CloseIdleConnections)

	get := func(t *testing.T, host string) (*wildcardEcho, error) {
		t.Helper()
		resp, err := client.Get("https://" + host + "/")
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "status for %s", host)
		var got wildcardEcho
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		return &got, nil
	}

	for _, host := range []string{"a.prototypes.example.com", "b.prototypes.example.com", "foo.prototypes.example.com"} {
		t.Run(host, func(t *testing.T) {
			got, err := get(t, host)
			require.NoError(t, err, "TLS request for %s must succeed with a verified certificate", host)
			assert.Equal(t, "wildcard", got.Backend, "request should reach the wildcard backend")
			assert.Equal(t, host, got.Host, "backend must receive the original Host")
			assert.Equal(t, host, got.ForwardedHost, "X-Forwarded-Host should carry the original host")
			assert.Equal(t, "https", got.ForwardedProto, "X-Forwarded-Proto should be https")
			assert.Equal(t, "127.0.0.1", got.ForwardedFor, "X-Forwarded-For should carry the client IP")
		})
	}

	t.Run("exact service wins", func(t *testing.T) {
		got, err := get(t, "api.prototypes.example.com")
		require.NoError(t, err)
		assert.Equal(t, "exact", got.Backend, "exact service must win over the wildcard")
		assert.Equal(t, "api.prototypes.example.com", got.Host)
	})

	t.Run("deeper name is not covered", func(t *testing.T) {
		_, err := get(t, "a.b.prototypes.example.com")
		assert.Error(t, err, "the wildcard certificate must not validate a two-label-deeper name")
	})

	t.Run("removing the wildcard stops routing", func(t *testing.T) {
		s.cleanupMappingRoutes(httpMapping("svc-wildcard", "*.prototypes.example.com", wildcardTarget))
		client.CloseIdleConnections()

		resp, err := client.Get("https://c.prototypes.example.com/")
		require.NoError(t, err, "TLS still terminates with the static certificate")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "no service should answer once the wildcard is removed")

		got, err := get(t, "api.prototypes.example.com")
		require.NoError(t, err)
		assert.Equal(t, "exact", got.Backend, "the exact service is unaffected")
	})
}

// TestWildcardService_RejectedWithoutOptIn checks that a proxy without
// --allow-wildcard-services registers nothing for a wildcard mapping.
func TestWildcardService_RejectedWithoutOptIn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	s := newWildcardTestServer(t, ln)
	s.AllowWildcardServices = false

	err = s.setupMappingRoutes(context.Background(), httpMapping("svc-wildcard", "*.prototypes.example.com", "http://127.0.0.1:1"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled", "error should name the missing opt-in")

	req := httptest.NewRequest(http.MethodGet, "https://a.prototypes.example.com/", nil)
	rec := httptest.NewRecorder()
	s.auth.Protect(s.proxy).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, "nothing should be routed for the rejected wildcard")
}
