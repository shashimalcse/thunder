/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package eudi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/thunder-id/thunderid/internal/system/cache"
	"github.com/thunder-id/thunderid/internal/system/config"
)

func TestCacheStateStoreRoundTrip(t *testing.T) {
	config.ResetServerRuntime()
	require.NoError(t, config.InitializeServerRuntime("", &config.Config{
		Cache: config.CacheConfig{Type: "inmemory", Size: 100, TTL: 3600, CleanupInterval: 300},
	}))
	t.Cleanup(config.ResetServerRuntime)

	cm := cache.Initialize()
	t.Cleanup(cm.Close)
	require.True(t, cm.IsEnabled())

	store := NewCacheStateStore(cm)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	st := &RequestState{
		State:        "state-1",
		Nonce:        "nonce-1",
		EphemeralKey: key,
		Status:       StatusPending,
		ExpiresAt:    time.Now().Add(time.Minute),
	}

	require.NoError(t, store.Save(context.Background(), st))

	got, ok := store.Get(context.Background(), "state-1")
	require.True(t, ok)
	assert.Equal(t, "nonce-1", got.Nonce)
	assert.Equal(t, StatusPending, got.Status)
	assert.True(t, key.Equal(got.EphemeralKey))

	require.NoError(t, store.Delete(context.Background(), "state-1"))
	_, ok = store.Get(context.Background(), "state-1")
	assert.False(t, ok)
}
