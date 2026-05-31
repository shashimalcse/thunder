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
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/thunder-id/thunderid/internal/system/jose/jwe"
)

const defaultStateTTL = 5 * time.Minute

// RequestSigner signs the OpenID4VP request object (JAR) claims into a compact
// JWS using the verifier's registered key and x5c header.
type RequestSigner interface {
	SignRequestObject(ctx context.Context, claims map[string]interface{}) (string, error)
}

// ServiceConfig is the static configuration of the OpenID4VP verifier service.
type ServiceConfig struct {
	// Request is the request-object configuration (client_id, DCQL, etc.). Its
	// ResponseURI is set per-request by the service and may be left empty here.
	Request RequestConfig
	// CredentialID is the DCQL credential id to verify. Defaults to
	// DefaultPIDCredentialID.
	CredentialID string
	// RequestURIBase is the absolute base URL of the request_uri endpoint.
	RequestURIBase string
	// ResponseURIBase is the absolute base URL of the response_uri endpoint.
	ResponseURIBase string
	// EphemeralKeyID is the kid advertised for the ephemeral encryption key.
	EphemeralKeyID string
	// TTL bounds how long a request awaits a response. Defaults to defaultStateTTL.
	TTL time.Duration
	// ResultRedirectURIBase, when set, is the base URL the wallet is told to
	// follow after posting its response (finalising session binding). The state
	// is appended as a query parameter.
	ResultRedirectURIBase string
}

// Service drives the OpenID4VP verifier: it issues signed requests with a fresh
// nonce and ephemeral encryption key, and verifies the encrypted responses.
type Service struct {
	cfg      ServiceConfig
	store    StateStore
	signer   RequestSigner
	verifier *PIDVerifier

	now      func() time.Time
	newState func() (string, error)
	newNonce func() (string, error)
	newKey   func() (*ecdsa.PrivateKey, error)
}

// Initiation is what the client needs to render the QR / deep link.
type Initiation struct {
	State      string
	ClientID   string
	RequestURI string
}

// NewService creates an OpenID4VP verifier service.
func NewService(cfg ServiceConfig, store StateStore, signer RequestSigner, verifier *PIDVerifier) (*Service, error) {
	if store == nil || signer == nil || verifier == nil {
		return nil, fmt.Errorf("%w: store, signer and verifier are required", ErrPolicy)
	}
	if cfg.RequestURIBase == "" || cfg.ResponseURIBase == "" {
		return nil, fmt.Errorf("%w: request_uri and response_uri base URLs are required", ErrPolicy)
	}
	if cfg.Request.ClientID == "" {
		return nil, fmt.Errorf("%w: client_id is required", ErrPolicy)
	}
	if cfg.CredentialID == "" {
		cfg.CredentialID = DefaultPIDCredentialID
	}
	if cfg.TTL == 0 {
		cfg.TTL = defaultStateTTL
	}
	return &Service{
		cfg:      cfg,
		store:    store,
		signer:   signer,
		verifier: verifier,
		now:      time.Now,
		newState: randomToken,
		newNonce: randomToken,
		newKey:   func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) },
	}, nil
}

// Initiate creates a fresh request: a random state and nonce and an ephemeral
// encryption keypair, stored pending under a short TTL.
func (s *Service) Initiate(ctx context.Context) (*Initiation, error) {
	state, err := s.newState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}
	nonce, err := s.newNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	key, err := s.newKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	rs := &RequestState{
		State:        state,
		Nonce:        nonce,
		EphemeralKey: key,
		Status:       StatusPending,
		ExpiresAt:    s.now().Add(s.cfg.TTL),
	}
	if err := s.store.Save(ctx, rs); err != nil {
		return nil, fmt.Errorf("failed to store request state: %w", err)
	}

	return &Initiation{
		State:      state,
		ClientID:   s.cfg.Request.ClientID,
		RequestURI: s.requestURI(state),
	}, nil
}

// RequestObject builds and signs the request object (JAR) for state.
func (s *Service) RequestObject(ctx context.Context, state string) (string, error) {
	rs, err := s.load(ctx, state)
	if err != nil {
		return "", err
	}

	reqCfg := s.cfg.Request
	reqCfg.ResponseURI = s.responseURI(state)

	claims, err := BuildRequestObject(reqCfg, RequestParams{
		Nonce:          rs.Nonce,
		State:          state,
		EphemeralKey:   &rs.EphemeralKey.PublicKey,
		EphemeralKeyID: s.cfg.EphemeralKeyID,
		IssuedAt:       s.now(),
	})
	if err != nil {
		return "", err
	}
	return s.signer.SignRequestObject(ctx, claims)
}

// SubmitResponse decrypts and verifies an encrypted wallet response for state,
// recording the outcome. It returns the verified PID on success.
func (s *Service) SubmitResponse(ctx context.Context, state, encryptedResponse string) (*VerifiedPID, error) {
	rs, err := s.load(ctx, state)
	if err != nil {
		return nil, err
	}

	plaintext, err := jwe.DecryptWithKey(encryptedResponse, rs.EphemeralKey)
	if err != nil {
		return nil, s.fail(ctx, rs, fmt.Errorf("%w: decryption failed: %w", ErrInvalidResponse, err))
	}

	resp, err := ParseAuthorizationResponse(plaintext)
	if err != nil {
		return nil, s.fail(ctx, rs, err)
	}
	if resp.State != "" && resp.State != state {
		return nil, s.fail(ctx, rs, ErrStateMismatch)
	}

	pid, err := s.verifier.VerifyResponse(ctx, plaintext, s.cfg.CredentialID, rs.Nonce)
	if err != nil {
		return nil, s.fail(ctx, rs, err)
	}

	rs.Status = StatusCompleted
	rs.Result = pid
	if err := s.store.Save(ctx, rs); err != nil {
		return nil, fmt.Errorf("failed to persist verification result: %w", err)
	}
	return pid, nil
}

// Result returns the current state record for polling. It returns
// ErrUnknownState when the state is unknown or expired.
func (s *Service) Result(ctx context.Context, state string) (*RequestState, error) {
	return s.load(ctx, state)
}

// load fetches non-expired state, deleting and rejecting expired entries.
func (s *Service) load(ctx context.Context, state string) (*RequestState, error) {
	rs, ok := s.store.Get(ctx, state)
	if !ok || rs == nil {
		return nil, ErrUnknownState
	}
	if s.now().After(rs.ExpiresAt) {
		_ = s.store.Delete(ctx, state)
		return nil, ErrUnknownState
	}
	return rs, nil
}

// fail records a verification failure and returns the wrapped reason.
func (s *Service) fail(ctx context.Context, rs *RequestState, reason error) error {
	rs.Status = StatusFailed
	rs.FailureReason = reason.Error()
	_ = s.store.Save(ctx, rs)
	return reason
}

// ResultRedirectURI returns the URL the wallet should follow after posting its
// response, or an empty string when none is configured.
func (s *Service) ResultRedirectURI(state string) string {
	if s.cfg.ResultRedirectURIBase == "" {
		return ""
	}
	return withState(s.cfg.ResultRedirectURIBase, state)
}

func (s *Service) requestURI(state string) string {
	return withState(s.cfg.RequestURIBase, state)
}

func (s *Service) responseURI(state string) string {
	return withState(s.cfg.ResponseURIBase, state)
}

// withState appends the state query parameter to a base URL.
func withState(base, state string) string {
	sep := "?"
	if u, err := url.Parse(base); err == nil && u.RawQuery != "" {
		sep = "&"
	}
	return base + sep + "state=" + url.QueryEscape(state)
}

// randomToken returns 32 cryptographically random bytes, base64url-encoded.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// WalletAuthorizationURI builds the openid4vp:// deep link the wallet scans,
// carrying the client_id and request_uri.
func WalletAuthorizationURI(clientID, requestURI string) string {
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("request_uri", requestURI)
	return "openid4vp://?" + v.Encode()
}
