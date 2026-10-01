package acme

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/types"
)

// TestWildcardServicePatternCoveredByStaticCert registers a wildcard service
// domain whose pattern a static certificate carries: it is ready at once, never
// goes to ACME, and the static certificate is served for every matching SNI.
func TestWildcardServicePatternCoveredByStaticCert(t *testing.T) {
	wcDir := t.TempDir()
	generateSelfSignedCert(t, wcDir, "prototypes", "*.prototypes.example.com")
	mgr, err := NewManager(ManagerConfig{CertDir: t.TempDir(), ACMEURL: "https://acme.example.com/directory", WildcardDir: wcDir}, nil, nil, nil)
	require.NoError(t, err)

	hit := mgr.AddDomain("*.prototypes.example.com", types.AccountID("acc1"), types.ServiceID("svc1"))
	assert.True(t, hit, "a pattern carried by a static certificate is certificate-ready")
	assert.Equal(t, 0, mgr.PendingCerts(), "a wildcard pattern must never be prefetched via ACME")
	assert.Equal(t, []string{"*.prototypes.example.com"}, mgr.ReadyDomains())

	for _, sni := range []string{"a.prototypes.example.com", "test123.prototypes.example.com"} {
		cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		require.NoError(t, err, "SNI %s should get the static certificate", sni)
		assert.Contains(t, cert.Leaf.DNSNames, "*.prototypes.example.com", "certificate for %s", sni)
	}

	_, err = mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.b.prototypes.example.com"})
	assert.Error(t, err, "a deeper name is neither covered by the certificate nor issuable on demand")
}

// TestWildcardServicePatternWithoutCert registers a wildcard service domain
// with no matching static certificate. ACME cannot issue wildcards without
// DNS-01, so the pattern is reported failed instead of being sent to ACME, and
// no certificate is issued on demand for hosts beneath it.
func TestWildcardServicePatternWithoutCert(t *testing.T) {
	mgr, err := NewManager(ManagerConfig{CertDir: t.TempDir(), ACMEURL: "https://acme.example.com/directory"}, nil, nil, nil)
	require.NoError(t, err)

	hit := mgr.AddDomain("*.prototypes.example.com", types.AccountID("acc1"), types.ServiceID("svc1"))
	assert.False(t, hit, "an uncovered pattern is not certificate-ready")
	assert.Equal(t, 0, mgr.PendingCerts(), "a wildcard pattern must never be prefetched via ACME")
	assert.Contains(t, mgr.FailedDomains(), "*.prototypes.example.com", "the pattern should be reported as failed with a reason")

	assert.Error(t, mgr.hostPolicy(context.Background(), "*.prototypes.example.com"),
		"a client-sent wildcard SNI must not start an ACME order")
	assert.Error(t, mgr.hostPolicy(context.Background(), "a.prototypes.example.com"),
		"hosts beneath the pattern must not be issued on demand")
}

// TestWildcardServicePatternNotCoveredByParentCert checks that a certificate
// for *.example.com does not cover the service pattern *.prototypes.example.com,
// matching certificate rules where a wildcard spans exactly one label.
func TestWildcardServicePatternNotCoveredByParentCert(t *testing.T) {
	wcDir := t.TempDir()
	generateSelfSignedCert(t, wcDir, "example", "*.example.com")
	mgr, err := NewManager(ManagerConfig{CertDir: t.TempDir(), ACMEURL: "https://acme.example.com/directory", WildcardDir: wcDir}, nil, nil, nil)
	require.NoError(t, err)

	hit := mgr.AddDomain("*.prototypes.example.com", types.AccountID("acc1"), types.ServiceID("svc1"))
	assert.False(t, hit, "*.example.com must not cover *.prototypes.example.com")
	assert.Contains(t, mgr.FailedDomains(), "*.prototypes.example.com")
}
