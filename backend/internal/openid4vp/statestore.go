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

package openid4vp

import (
	"context"
	"crypto/ecdsa"
	"time"

	"github.com/thunder-id/thunderid/internal/system/cache"
)

// stateCacheName is the name of the request-state cache.
const stateCacheName = "OpenID4VPRequestState"

// Status is the lifecycle status of an OpenID4VP request.
type Status string

const (
	// StatusPending indicates the request is awaiting a wallet response.
	StatusPending Status = "PENDING"
	// StatusCompleted indicates a response was received and verified.
	StatusCompleted Status = "COMPLETED"
	// StatusFailed indicates a response was received but failed verification.
	StatusFailed Status = "FAILED"
)

// RequestState is the short-lived per-request state correlated by State. It
// holds the ephemeral response-encryption private key and, once a response
// arrives, the verification outcome.
type RequestState struct {
	State         string
	Nonce         string
	EphemeralKey  *ecdsa.PrivateKey
	ClientID      string
	RequestURI    string
	Status        Status
	Result        *VerifiedPresentation
	FailureReason string
	ExpiresAt     time.Time
}

// StateStore persists short-lived OpenID4VP request state keyed by State.
type StateStore interface {
	Save(ctx context.Context, st *RequestState) error
	Get(ctx context.Context, state string) (*RequestState, bool)
	Delete(ctx context.Context, state string) error
}

// cacheStateStore backs StateStore with the system cache. The cache TTL is
// global, so callers must also honour RequestState.ExpiresAt for the short
// per-request window. Redis-backed deployments require serialising the
// ephemeral key; that is later hardening (the spike assumes in-memory cache).
type cacheStateStore struct {
	cache cache.CacheInterface[*RequestState]
}

// NewCacheStateStore returns a StateStore backed by the system cache manager.
func NewCacheStateStore(cm cache.CacheManagerInterface) StateStore {
	return &cacheStateStore{cache: cache.GetCache[*RequestState](cm, stateCacheName)}
}

// Save stores the request state.
func (c *cacheStateStore) Save(ctx context.Context, st *RequestState) error {
	return c.cache.Set(ctx, cache.CacheKey{Key: st.State}, st)
}

// Get returns the request state for state, if present.
func (c *cacheStateStore) Get(ctx context.Context, state string) (*RequestState, bool) {
	return c.cache.Get(ctx, cache.CacheKey{Key: state})
}

// Delete removes the request state.
func (c *cacheStateStore) Delete(ctx context.Context, state string) error {
	return c.cache.Delete(ctx, cache.CacheKey{Key: state})
}
