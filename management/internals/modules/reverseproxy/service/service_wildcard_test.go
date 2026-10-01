package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate_WildcardDomain(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(s *Service)
		wantErr string
	}{
		{
			name:   "public HTTP wildcard",
			mutate: func(s *Service) { s.Domain = "*.prototypes.proxy.example.com" },
		},
		{
			name:   "public HTTP wildcard with pass host header",
			mutate: func(s *Service) { s.Domain = "*.example.com"; s.PassHostHeader = true },
		},
		{
			name:    "wildcard in an inner label",
			mutate:  func(s *Service) { s.Domain = "foo.*.example.com" },
			wantErr: "must start with",
		},
		{
			name:    "partial label wildcard",
			mutate:  func(s *Service) { s.Domain = "*foo.example.com" },
			wantErr: "invalid domain",
		},
		{
			name:    "double wildcard",
			mutate:  func(s *Service) { s.Domain = "*.*.example.com" },
			wantErr: "single leading",
		},
		{
			name:    "top-level wildcard",
			mutate:  func(s *Service) { s.Domain = "*.com" },
			wantErr: "at least two labels",
		},
		{
			name:    "bare asterisk",
			mutate:  func(s *Service) { s.Domain = "*" },
			wantErr: "invalid domain",
		},
		{
			name:    "TCP mode",
			mutate:  func(s *Service) { s.Domain = "*.example.com"; s.Mode = ModeTCP; s.ListenPort = 5432 },
			wantErr: "only supported for HTTP",
		},
		{
			name:    "TLS mode",
			mutate:  func(s *Service) { s.Domain = "*.example.com"; s.Mode = ModeTLS; s.ListenPort = 8443 },
			wantErr: "only supported for HTTP",
		},
		{
			name: "SSO enabled",
			mutate: func(s *Service) {
				s.Domain = "*.example.com"
				s.Auth.BearerAuth = &BearerAuthConfig{Enabled: true}
			},
			wantErr: "do not support authentication",
		},
		{
			name: "password enabled",
			mutate: func(s *Service) {
				s.Domain = "*.example.com"
				s.Auth.PasswordAuth = &PasswordAuthConfig{Enabled: true, Password: "secret"}
			},
			wantErr: "do not support authentication",
		},
		{
			name: "PIN enabled",
			mutate: func(s *Service) {
				s.Domain = "*.example.com"
				s.Auth.PinAuth = &PINAuthConfig{Enabled: true, Pin: "123456"}
			},
			wantErr: "do not support authentication",
		},
		{
			name: "private service",
			mutate: func(s *Service) {
				s.Domain = "*.example.com"
				s.Private = true
				s.AccessGroups = []string{"grp-admins"}
			},
			wantErr: "do not support private services",
		},
		{
			name: "disabled auth configs are allowed",
			mutate: func(s *Service) {
				s.Domain = "*.example.com"
				s.Auth.BearerAuth = &BearerAuthConfig{Enabled: false}
				s.Auth.PasswordAuth = &PasswordAuthConfig{Enabled: false}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := validProxy()
			tt.mutate(s)
			err := s.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}
