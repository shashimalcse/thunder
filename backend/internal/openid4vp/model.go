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

// Package openid4vp implements an OpenID4VP verifier: it builds signed
// presentation requests, decrypts and verifies wallet responses (SD-JWT VC via
// the generic verifier in system/jose/sdjwt), and exposes the wallet-facing
// endpoints. It is credential-agnostic; credential-specific policy (e.g. the
// EUDI PID) is supplied by callers as configuration.
package openid4vp

import (
	"context"
	"crypto"
	"errors"
	"time"
)

// Errors returned by the verifier. They wrap the failing layer so callers and
// tests can assert exactly where a presentation was rejected.
var (
	// ErrUntrustedIssuer indicates the credential issuer is not in the trust
	// store (credential layer).
	ErrUntrustedIssuer = errors.New("openid4vp: untrusted credential issuer")
	// ErrUnexpectedVCT indicates the credential type did not match policy
	// (credential layer).
	ErrUnexpectedVCT = errors.New("openid4vp: unexpected credential type (vct)")
	// ErrUnrequestedClaim indicates a disclosed claim was not requested
	// (selective-disclosure layer).
	ErrUnrequestedClaim = errors.New("openid4vp: disclosed claim was not requested")
	// ErrMissingMandatoryClaim indicates a required claim was not disclosed
	// (selective-disclosure layer).
	ErrMissingMandatoryClaim = errors.New("openid4vp: mandatory claim missing")
	// ErrInvalidPresentation indicates the presentation failed structural or
	// cryptographic verification (wraps sdjwt errors).
	ErrInvalidPresentation = errors.New("openid4vp: invalid presentation")
	// ErrInvalidResponse indicates the OpenID4VP authorization response could
	// not be parsed or lacked the expected presentation (transport layer).
	ErrInvalidResponse = errors.New("openid4vp: invalid authorization response")
	// ErrPolicy indicates the verification policy itself was misconfigured.
	ErrPolicy = errors.New("openid4vp: invalid verification policy")
	// ErrUnknownState indicates no request state matched the given state value
	// (it never existed, already completed, or expired).
	ErrUnknownState = errors.New("openid4vp: unknown or expired request state")
	// ErrStateMismatch indicates the response state did not match the request.
	ErrStateMismatch = errors.New("openid4vp: response state mismatch")
)

// Policy is the verification policy. The claim sets use dotted paths (e.g.
// "given_name", "address.locality") matching the SD-JWT disclosure paths, so
// tightening what is requested is purely a configuration change.
type Policy struct {
	// ExpectedVCT is the required credential type (vct).
	ExpectedVCT string
	// Audience is this verifier's client_id; the Key Binding JWT aud must match.
	Audience string
	// RequestedClaims are the dotted paths the DCQL query asked for. A disclosed
	// claim outside this set is rejected (data minimisation). Empty disables the
	// check.
	RequestedClaims []string
	// MandatoryClaims are dotted paths that must be present after resolution.
	MandatoryClaims []string
	// Leeway tolerates clock skew on the Key Binding JWT iat.
	Leeway time.Duration
}

// TrustStore resolves a credential issuer identifier to its trusted signing key.
type TrustStore interface {
	// IssuerKey returns the trusted public key for issuer, or ErrUntrustedIssuer
	// when the issuer is unknown.
	IssuerKey(ctx context.Context, issuer string) (crypto.PublicKey, error)
}

// VerifiedPresentation is the result of a successful PID presentation verification.
type VerifiedPresentation struct {
	// Subject is a stable, privacy-respecting identifier for the verified person.
	Subject string
	// Issuer is the verified credential issuer.
	Issuer string
	// VCT is the verified credential type.
	VCT string
	// Claims is the disclosed PID attribute set (dotted-path keyed, flattened).
	Claims map[string]interface{}
	// DisclosedPaths lists the dotted paths revealed by the holder.
	DisclosedPaths []string
}
