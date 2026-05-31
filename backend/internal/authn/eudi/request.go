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
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"time"
)

// OpenID4VP request object constants (German sandbox HAIP profile).
const (
	// ResponseTypeVPToken is the OpenID4VP response_type.
	ResponseTypeVPToken = "vp_token"
	// ResponseModeDirectPostJWT mandates an encrypted (JWE) response.
	ResponseModeDirectPostJWT = "direct_post.jwt"
	// DefaultRequestAudience is the request object audience.
	DefaultRequestAudience = "https://self-issued.me/v2"
	// DefaultResponseEncValue is the mandated content encryption algorithm.
	DefaultResponseEncValue = "A128GCM"
	// defaultRequestValidity bounds the request object lifetime.
	defaultRequestValidity = 5 * time.Minute
)

// RequestConfig is the static (config-driven) part of the OpenID4VP request.
type RequestConfig struct {
	// ClientID is the verifier identifier, e.g. "x509_hash:<hash>".
	ClientID string
	// ResponseURI is where the wallet posts the encrypted response.
	ResponseURI string
	// Audience overrides DefaultRequestAudience when set.
	Audience string
	// Validity overrides defaultRequestValidity when set.
	Validity time.Duration
	// DCQL describes the requested PID claims.
	DCQL DCQLConfig
	// ResponseEncValues lists supported content encryption algorithms.
	// Defaults to [DefaultResponseEncValue].
	ResponseEncValues []string
	// VerifierInfo carries the registration certificate(s) the wallet requires.
	// It is passed through opaquely; obtaining it is part of RP onboarding.
	VerifierInfo []interface{}
}

// RequestParams is the per-request dynamic input.
type RequestParams struct {
	// Nonce is the fresh request nonce.
	Nonce string
	// State correlates the eventual response.
	State string
	// EphemeralKey is the per-request response-encryption public key.
	EphemeralKey *ecdsa.PublicKey
	// EphemeralKeyID identifies the ephemeral key in client_metadata.jwks.
	EphemeralKeyID string
	// IssuedAt is the request issuance time (iat); defaults to now-bound exp.
	IssuedAt time.Time
}

// BuildRequestObject assembles the OpenID4VP signed-request (JAR) claims. The
// caller signs the result into a JWT with the registered key (x5c header); this
// function does not sign. The returned map matches the decoded request shape in
// the sandbox guide §3.2.
func BuildRequestObject(cfg RequestConfig, params RequestParams) (map[string]interface{}, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("%w: client_id is required", ErrPolicy)
	}
	if cfg.ResponseURI == "" {
		return nil, fmt.Errorf("%w: response_uri is required", ErrPolicy)
	}
	if params.Nonce == "" || params.State == "" {
		return nil, fmt.Errorf("%w: nonce and state are required", ErrPolicy)
	}
	if params.EphemeralKey == nil {
		return nil, fmt.Errorf("%w: ephemeral encryption key is required", ErrPolicy)
	}

	dcql, err := BuildPIDQuery(cfg.DCQL)
	if err != nil {
		return nil, err
	}

	clientMetadata, err := buildClientMetadata(cfg, params)
	if err != nil {
		return nil, err
	}

	audience := cfg.Audience
	if audience == "" {
		audience = DefaultRequestAudience
	}
	validity := cfg.Validity
	if validity == 0 {
		validity = defaultRequestValidity
	}
	iat := params.IssuedAt
	if iat.IsZero() {
		iat = time.Now()
	}

	request := map[string]interface{}{
		"response_type":   ResponseTypeVPToken,
		"response_mode":   ResponseModeDirectPostJWT,
		"client_id":       cfg.ClientID,
		"response_uri":    cfg.ResponseURI,
		"nonce":           params.Nonce,
		"state":           params.State,
		"aud":             audience,
		"iat":             iat.Unix(),
		"exp":             iat.Add(validity).Unix(),
		"dcql_query":      dcql,
		"client_metadata": clientMetadata,
	}
	if len(cfg.VerifierInfo) > 0 {
		request["verifier_info"] = cfg.VerifierInfo
	}

	return request, nil
}

// buildClientMetadata builds the client_metadata advertising the ephemeral
// encryption key and the supported response encryption algorithms.
func buildClientMetadata(cfg RequestConfig, params RequestParams) (map[string]interface{}, error) {
	jwk, err := ecdsaPublicKeyToEncJWK(params.EphemeralKey, params.EphemeralKeyID)
	if err != nil {
		return nil, err
	}

	encValues := cfg.ResponseEncValues
	if len(encValues) == 0 {
		encValues = []string{DefaultResponseEncValue}
	}

	return map[string]interface{}{
		"jwks": map[string]interface{}{
			"keys": []interface{}{jwk},
		},
		"vp_formats_supported": map[string]interface{}{
			FormatSDJWTVC: map[string]interface{}{},
		},
		"encrypted_response_enc_values_supported": encValues,
	}, nil
}

// ecdsaPublicKeyToEncJWK encodes an EC public key as an encryption-use JWK.
func ecdsaPublicKeyToEncJWK(pub *ecdsa.PublicKey, kid string) (map[string]interface{}, error) {
	raw, err := pub.Bytes()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPolicy, err)
	}

	var crv string
	var coordLen int
	switch len(raw) {
	case 65:
		crv, coordLen = "P-256", 32
	case 97:
		crv, coordLen = "P-384", 48
	case 133:
		crv, coordLen = "P-521", 66
	default:
		return nil, fmt.Errorf("%w: unsupported EC public key length %d", ErrPolicy, len(raw))
	}

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(raw[1 : 1+coordLen]),
		"y":   base64.RawURLEncoding.EncodeToString(raw[1+coordLen:]),
		"use": "enc",
		"alg": "ECDH-ES",
	}
	if kid != "" {
		jwk["kid"] = kid
	}
	return jwk, nil
}
