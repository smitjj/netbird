package store

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
)

// TestSqlStore_GetClusterSupportsWildcardDomains checks the capability is
// persisted and aggregated unanimously: one proxy that has not opted in, or
// never reported, keeps wildcard services off for the whole cluster.
func TestSqlStore_GetClusterSupportsWildcardDomains(t *testing.T) {
	if (os.Getenv("CI") == "true" && runtime.GOOS == "darwin") || runtime.GOOS == "windows" {
		t.Skip("skip CI tests on darwin and windows")
	}

	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		yes, no := true, false
		fresh := time.Now().Add(-30 * time.Second)
		stale := time.Now().Add(-30 * time.Minute)

		mustSave := func(id, cluster string, wildcard *bool, lastSeen time.Time) {
			require.NoError(t, store.SaveProxy(ctx, &rpproxy.Proxy{
				ID:             id,
				SessionID:      id + "-sess",
				ClusterAddress: cluster,
				IPAddress:      "10.0.0.1",
				LastSeen:       lastSeen,
				Status:         rpproxy.StatusConnected,
				Capabilities:   rpproxy.Capabilities{SupportsWildcardDomains: wildcard},
			}))
		}

		mustSave("p-all-1", "all.example", &yes, fresh)
		mustSave("p-all-2", "all.example", &yes, fresh)
		// A stale proxy that never opted in is outside the active window.
		mustSave("p-all-stale", "all.example", &no, stale)

		mustSave("p-mixed-1", "mixed.example", &yes, fresh)
		mustSave("p-mixed-2", "mixed.example", &no, fresh)

		mustSave("p-partial-1", "partial.example", &yes, fresh)
		mustSave("p-partial-2", "partial.example", nil, fresh)

		mustSave("p-legacy", "legacy.example", nil, fresh)

		got := store.GetClusterSupportsWildcardDomains(ctx, "all.example")
		require.NotNil(t, got, "all active proxies reported")
		assert.True(t, *got, "every active proxy allows wildcards")

		got = store.GetClusterSupportsWildcardDomains(ctx, "mixed.example")
		require.NotNil(t, got, "all active proxies reported")
		assert.False(t, *got, "one proxy without the opt-in disables wildcards")

		got = store.GetClusterSupportsWildcardDomains(ctx, "partial.example")
		require.NotNil(t, got, "a reporting proxy exists")
		assert.False(t, *got, "an unreported proxy disables wildcards")

		assert.Nil(t, store.GetClusterSupportsWildcardDomains(ctx, "legacy.example"), "no proxy reported the capability")
		assert.Nil(t, store.GetClusterSupportsWildcardDomains(ctx, "unknown.example"), "no active proxy in the cluster")
	})
}
