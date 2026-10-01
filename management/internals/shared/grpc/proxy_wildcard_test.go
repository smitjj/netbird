package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// TestSendServiceUpdateToCluster_WildcardRequiresCapability checks that a
// wildcard mapping only reaches proxies that claim supports_wildcard_domains,
// while its removal still reaches every proxy so nothing is left routed.
func TestSendServiceUpdateToCluster_WildcardRequiresCapability(t *testing.T) {
	s := &ProxyServiceServer{tokenStore: NewOneTimeTokenStore(context.Background(), testCacheStore(t))}
	s.SetProxyController(newTestProxyController())

	const cluster = "proxy.example.com"
	chEnabled := registerFakeProxyWithCaps(s, "proxy-enabled", cluster, &proto.ProxyCapabilities{SupportsWildcardDomains: ptr(true)})
	chDisabled := registerFakeProxyWithCaps(s, "proxy-disabled", cluster, &proto.ProxyCapabilities{SupportsWildcardDomains: ptr(false)})
	chLegacy := registerFakeProxy(s, "proxy-legacy", cluster)

	ctx := context.Background()
	wildcard := &proto.ProxyMapping{
		Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
		Id:        "service-wildcard",
		AccountId: "account-1",
		Domain:    "*.prototypes.example.com",
		Path:      []*proto.PathMapping{{Path: "/", Target: "http://10.0.0.1:8080"}},
	}
	s.SendServiceUpdateToCluster(ctx, wildcard, cluster)

	assert.NotNil(t, drainMapping(chEnabled), "proxy allowing wildcards should receive the mapping")
	assert.Nil(t, drainMapping(chDisabled), "proxy not allowing wildcards must not receive the mapping")
	assert.Nil(t, drainMapping(chLegacy), "proxy that never reported capabilities must not receive the mapping")

	exact := &proto.ProxyMapping{
		Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
		Id:        "service-exact",
		AccountId: "account-1",
		Domain:    "api.prototypes.example.com",
		Path:      []*proto.PathMapping{{Path: "/", Target: "http://10.0.0.2:8080"}},
	}
	s.SendServiceUpdateToCluster(ctx, exact, cluster)

	assert.NotNil(t, drainMapping(chEnabled), "exact mappings are unaffected by the wildcard gate")
	assert.NotNil(t, drainMapping(chDisabled), "exact mappings are unaffected by the wildcard gate")
	assert.NotNil(t, drainMapping(chLegacy), "exact mappings are unaffected by the wildcard gate")

	removed := &proto.ProxyMapping{
		Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED,
		Id:        "service-wildcard",
		AccountId: "account-1",
		Domain:    "*.prototypes.example.com",
	}
	s.SendServiceUpdateToCluster(ctx, removed, cluster)

	assert.NotNil(t, drainMapping(chEnabled), "removal must reach every proxy")
	assert.NotNil(t, drainMapping(chDisabled), "removal must reach every proxy")
	assert.NotNil(t, drainMapping(chLegacy), "removal must reach every proxy")
}
