package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestCheckWildcardMapping(t *testing.T) {
	public := func(d string) *proto.ProxyMapping {
		return &proto.ProxyMapping{Domain: d, Auth: &proto.Authentication{}}
	}

	tests := []struct {
		name    string
		allow   bool
		mapping *proto.ProxyMapping
		wantErr string
	}{
		{name: "exact domain on a proxy without the opt-in", allow: false, mapping: public("app.example.com")},
		{name: "public wildcard with the opt-in", allow: true, mapping: public("*.prototypes.example.com")},
		{name: "explicit http mode", allow: true, mapping: &proto.ProxyMapping{Domain: "*.example.com", Mode: "http"}},
		{name: "wildcard without the opt-in", allow: false, mapping: public("*.prototypes.example.com"), wantErr: "not enabled"},
		{name: "malformed wildcard", allow: true, mapping: public("*.*.example.com"), wantErr: "single leading"},
		{name: "tls passthrough mode", allow: true, mapping: &proto.ProxyMapping{Domain: "*.example.com", Mode: "tls"}, wantErr: "not supported"},
		{name: "password auth", allow: true, mapping: &proto.ProxyMapping{Domain: "*.example.com", Auth: &proto.Authentication{Password: true}}, wantErr: "authentication"},
		{name: "pin auth", allow: true, mapping: &proto.ProxyMapping{Domain: "*.example.com", Auth: &proto.Authentication{Pin: true}}, wantErr: "authentication"},
		{name: "oidc auth", allow: true, mapping: &proto.ProxyMapping{Domain: "*.example.com", Auth: &proto.Authentication{Oidc: true}}, wantErr: "authentication"},
		{name: "header auth", allow: true, mapping: &proto.ProxyMapping{Domain: "*.example.com", Auth: &proto.Authentication{HeaderAuths: []*proto.HeaderAuth{{Header: "X-Key"}}}}, wantErr: "authentication"},
		{name: "private service", allow: true, mapping: &proto.ProxyMapping{Domain: "*.example.com", Private: true}, wantErr: "private"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{AllowWildcardServices: tt.allow}
			err := s.checkWildcardMapping(tt.mapping)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// TestStaticCertCoversWildcardPattern covers static-certificate mode (ACME
// off): a wildcard service is certificate-ready only when the certificate
// carries that exact pattern, not a broader or narrower one.
func TestStaticCertCoversWildcardPattern(t *testing.T) {
	s := &Server{
		Logger:            quietLifecycleLogger(),
		staticCertWatcher: newStaticWatcher(t, []string{"*.prototypes.example.com"}),
	}

	assert.True(t, s.staticCertCovers(domain.Domain("*.prototypes.example.com")), "matching pattern is covered")
	assert.False(t, s.staticCertCovers(domain.Domain("*.example.com")), "broader pattern is not covered")
	assert.False(t, s.staticCertCovers(domain.Domain("*.a.prototypes.example.com")), "narrower pattern is not covered")
}
