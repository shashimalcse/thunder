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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/thunder-id/thunderid/internal/system/cryptolib"
)

// fakeStore is an in-memory StateStore for tests.
type fakeStore struct {
	m map[string]*RequestState
}

func newFakeStore() *fakeStore { return &fakeStore{m: map[string]*RequestState{}} }

func (f *fakeStore) Save(_ context.Context, st *RequestState) error {
	f.m[st.State] = st
	return nil
}

func (f *fakeStore) Get(_ context.Context, state string) (*RequestState, bool) {
	st, ok := f.m[state]
	return st, ok
}

func (f *fakeStore) Delete(_ context.Context, state string) error {
	delete(f.m, state)
	return nil
}

// fakeSigner signs request-object claims with an ECDSA key.
type fakeSigner struct {
	key *ecdsa.PrivateKey
}

func (s *fakeSigner) SignRequestObject(_ context.Context, claims map[string]interface{}) (string, error) {
	headerJSON, err := json.Marshal(map[string]interface{}{"alg": "ES256", "typ": "oauth-authz-req+jwt"})
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig, err := cryptolib.Generate([]byte(signingInput), cryptolib.ECDSASHA256, s.key)
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// fabricateResponseJWE encrypts plaintext to recipientPub as an ECDH-ES/A128GCM
// JWE, mirroring what an OpenID4VP wallet posts to response_uri.
func fabricateResponseJWE(t *testing.T, recipientPub *ecdsa.PublicKey, plaintext []byte) string {
	t.Helper()
	params := cryptolib.AlgorithmParams{
		Algorithm: cryptolib.AlgorithmECDHES,
		ECDHES:    cryptolib.ECDHESParams{ContentEncryptionAlgorithm: cryptolib.Algorithm("A128GCM")},
	}
	encryptedKey, details, err := cryptolib.Encrypt(recipientPub, &params, nil)
	require.NoError(t, err)

	epk := details.EPK.(*ecdh.PublicKey)
	raw := epk.Bytes()
	require.Len(t, raw, 65)
	header := map[string]interface{}{
		"typ": "JWE", "alg": "ECDH-ES", "enc": "A128GCM",
		"epk": map[string]interface{}{
			"kty": "EC", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(raw[1:33]),
			"y": base64.RawURLEncoding.EncodeToString(raw[33:]),
		},
	}
	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	block, err := aes.NewCipher(details.CEK)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	iv := make([]byte, gcm.NonceSize())
	_, err = rand.Read(iv)
	require.NoError(t, err)
	sealed := gcm.Seal(nil, iv, plaintext, []byte(headerB64))
	ciphertext := sealed[:len(sealed)-gcm.Overhead()]
	tag := sealed[len(sealed)-gcm.Overhead():]

	return strings.Join([]string{
		headerB64,
		base64.RawURLEncoding.EncodeToString(encryptedKey),
		base64.RawURLEncoding.EncodeToString(iv),
		base64.RawURLEncoding.EncodeToString(ciphertext),
		base64.RawURLEncoding.EncodeToString(tag),
	}, ".")
}

func newTestService(t *testing.T, b *pidBuilder) (*Service, *fakeStore) {
	t.Helper()
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	store := newFakeStore()
	verifier := newVerifier(t, b, defaultPolicy())
	cfg := ServiceConfig{
		Request: RequestConfig{
			ClientID: testAudience,
			DCQL:     DCQLConfig{CredentialID: credentialID, VCT: testVCT, Claims: []string{"given_name", "family_name"}},
		},
		CredentialID:    credentialID,
		RequestURIBase:  "https://verifier.example/openid4vp/request",
		ResponseURIBase: "https://verifier.example/openid4vp/response",
		EphemeralKeyID:  "enc-key-1",
	}
	svc, err := NewService(cfg, store, &fakeSigner{key: signerKey}, verifier)
	require.NoError(t, err)
	return svc, store
}

func TestNewServiceValidation(t *testing.T) {
	b := newPIDBuilder(t)
	verifier := newVerifier(t, b, defaultPolicy())
	signer := &fakeSigner{}
	store := newFakeStore()
	valid := ServiceConfig{
		Request:         RequestConfig{ClientID: "x509_hash:x"},
		CredentialID:    credentialID,
		RequestURIBase:  "https://x/req",
		ResponseURIBase: "https://x/resp",
	}

	_, err := NewService(valid, nil, signer, verifier)
	assert.ErrorIs(t, err, ErrPolicy)

	_, err = NewService(ServiceConfig{Request: RequestConfig{ClientID: "x"}}, store, signer, verifier)
	assert.ErrorIs(t, err, ErrPolicy)

	_, err = NewService(ServiceConfig{RequestURIBase: "a", ResponseURIBase: "b"}, store, signer, verifier)
	assert.ErrorIs(t, err, ErrPolicy)

	// Missing credential_id is rejected.
	_, err = NewService(ServiceConfig{
		Request: RequestConfig{ClientID: "x"}, RequestURIBase: "a", ResponseURIBase: "b",
	}, store, signer, verifier)
	assert.ErrorIs(t, err, ErrPolicy)

	svc, err := NewService(valid, store, signer, verifier)
	require.NoError(t, err)
	assert.Equal(t, credentialID, svc.cfg.CredentialID)
	assert.Equal(t, defaultStateTTL, svc.cfg.TTL)
}

func TestInitiateStoresPendingState(t *testing.T) {
	b := newPIDBuilder(t)
	svc, store := newTestService(t, b)

	init, err := svc.Initiate(context.Background())
	require.NoError(t, err)

	assert.NotEmpty(t, init.State)
	assert.Equal(t, testAudience, init.ClientID)
	assert.Contains(t, init.RequestURI, "state=")

	rs := store.m[init.State]
	require.NotNil(t, rs)
	assert.Equal(t, StatusPending, rs.Status)
	assert.NotEmpty(t, rs.Nonce)
	assert.NotNil(t, rs.EphemeralKey)
}

func TestRequestObjectBuildsSignedJAR(t *testing.T) {
	b := newPIDBuilder(t)
	svc, store := newTestService(t, b)

	init, err := svc.Initiate(context.Background())
	require.NoError(t, err)

	jar, err := svc.RequestObject(context.Background(), init.State)
	require.NoError(t, err)

	parts := strings.Split(jar, ".")
	require.Len(t, parts, 3)
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadJSON, &claims))

	assert.Equal(t, ResponseModeDirectPostJWT, claims["response_mode"])
	assert.Equal(t, testAudience, claims["client_id"])
	assert.Equal(t, init.State, claims["state"])
	assert.Equal(t, store.m[init.State].Nonce, claims["nonce"])
	assert.Contains(t, claims["response_uri"], "state=")
	assert.Contains(t, claims, "dcql_query")
	assert.Contains(t, claims, "client_metadata")
}

func TestRequestObjectUnknownState(t *testing.T) {
	b := newPIDBuilder(t)
	svc, _ := newTestService(t, b)
	_, err := svc.RequestObject(context.Background(), "nope")
	assert.ErrorIs(t, err, ErrUnknownState)
}

func TestSubmitResponseHappyPath(t *testing.T) {
	b := newPIDBuilder(t)
	svc, store := newTestService(t, b)

	init, err := svc.Initiate(context.Background())
	require.NoError(t, err)
	rs := store.m[init.State]

	presentation := b.build(rs.Nonce, map[string]interface{}{
		"given_name": "Erika", "family_name": "Mustermann", "birthdate": "1984-01-26",
	})
	body, err := json.Marshal(map[string]interface{}{
		"state":    init.State,
		"vp_token": map[string]interface{}{credentialID: []string{presentation}},
	})
	require.NoError(t, err)
	jweToken := fabricateResponseJWE(t, &rs.EphemeralKey.PublicKey, body)

	pid, err := svc.SubmitResponse(context.Background(), init.State, jweToken)
	require.NoError(t, err)
	assert.Equal(t, "Erika", pid.Claims["given_name"])

	stored := store.m[init.State]
	assert.Equal(t, StatusCompleted, stored.Status)
	assert.NotNil(t, stored.Result)

	// Result polling reflects completion.
	res, err := svc.Result(context.Background(), init.State)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, res.Status)
}

func TestSubmitResponseWrongNonceMarksFailed(t *testing.T) {
	b := newPIDBuilder(t)
	svc, store := newTestService(t, b)

	init, err := svc.Initiate(context.Background())
	require.NoError(t, err)
	rs := store.m[init.State]

	// Presentation bound to a different nonce than the one issued.
	presentation := b.build("attacker-nonce", map[string]interface{}{"given_name": "Erika", "family_name": "M"})
	body, err := json.Marshal(map[string]interface{}{
		"state":    init.State,
		"vp_token": map[string]interface{}{credentialID: []string{presentation}},
	})
	require.NoError(t, err)
	jweToken := fabricateResponseJWE(t, &rs.EphemeralKey.PublicKey, body)

	_, err = svc.SubmitResponse(context.Background(), init.State, jweToken)
	assert.ErrorIs(t, err, ErrInvalidPresentation)
	assert.Equal(t, StatusFailed, store.m[init.State].Status)
	assert.NotEmpty(t, store.m[init.State].FailureReason)
}

func TestSubmitResponseStateMismatch(t *testing.T) {
	b := newPIDBuilder(t)
	svc, store := newTestService(t, b)

	init, err := svc.Initiate(context.Background())
	require.NoError(t, err)
	rs := store.m[init.State]

	presentation := b.build(rs.Nonce, map[string]interface{}{"given_name": "Erika", "family_name": "M"})
	body, err := json.Marshal(map[string]interface{}{
		"state":    "a-different-state",
		"vp_token": map[string]interface{}{credentialID: []string{presentation}},
	})
	require.NoError(t, err)
	jweToken := fabricateResponseJWE(t, &rs.EphemeralKey.PublicKey, body)

	_, err = svc.SubmitResponse(context.Background(), init.State, jweToken)
	assert.ErrorIs(t, err, ErrStateMismatch)
}

func TestSubmitResponseUndecryptable(t *testing.T) {
	b := newPIDBuilder(t)
	svc, _ := newTestService(t, b)

	init, err := svc.Initiate(context.Background())
	require.NoError(t, err)

	// JWE encrypted to an unrelated key cannot be decrypted by the stored key.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jweToken := fabricateResponseJWE(t, &other.PublicKey, []byte(`{"state":"x"}`))

	_, err = svc.SubmitResponse(context.Background(), init.State, jweToken)
	assert.ErrorIs(t, err, ErrInvalidResponse)
}

func TestSubmitResponseUnknownState(t *testing.T) {
	b := newPIDBuilder(t)
	svc, _ := newTestService(t, b)
	_, err := svc.SubmitResponse(context.Background(), "nope", "x.y.z.a.b")
	assert.ErrorIs(t, err, ErrUnknownState)
}

func TestExpiredStateRejected(t *testing.T) {
	b := newPIDBuilder(t)
	svc, store := newTestService(t, b)

	init, err := svc.Initiate(context.Background())
	require.NoError(t, err)

	// Force expiry.
	store.m[init.State].ExpiresAt = time.Now().Add(-time.Minute)

	_, err = svc.Result(context.Background(), init.State)
	assert.ErrorIs(t, err, ErrUnknownState)
	// Expired entry is evicted.
	_, ok := store.m[init.State]
	assert.False(t, ok)
}

func TestWalletAuthorizationURI(t *testing.T) {
	uri := WalletAuthorizationURI("x509_hash:abc", "https://v/req?state=s")
	assert.Contains(t, uri, "openid4vp://?")
	assert.Contains(t, uri, "client_id=x509_hash%3Aabc")
	assert.Contains(t, uri, "request_uri=https")
}
