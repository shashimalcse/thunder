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

// Package eudi verifies OpenID4VP presentations of the German EUDI Wallet PID
// (SD-JWT VC) and maps the disclosed claims into a verified-person result. It
// layers PID-specific policy (credential type, issuer trust, requested-claim
// enforcement) over the generic SD-JWT verifier in system/jose/sdjwt.
package eudi

import (
	"context"
	"crypto"
	"errors"
	"time"
)

// Confirmed EUDI PID SD-JWT VC identifiers (German sandbox HAIP profile).
const (
	// PIDVCTSDJWT is the SD-JWT VC type of the German PID.
	PIDVCTSDJWT = "urn:eudi:pid:de:1"
)

// Errors returned by the PID verifier. They wrap the failing layer so callers
// and tests can assert exactly where a presentation was rejected.
var (
	// ErrUntrustedIssuer indicates the credential issuer is not in the trust
	// store (credential layer).
	ErrUntrustedIssuer = errors.New("eudi: untrusted credential issuer")
	// ErrUnexpectedVCT indicates the credential type did not match policy
	// (credential layer).
	ErrUnexpectedVCT = errors.New("eudi: unexpected credential type (vct)")
	// ErrUnrequestedClaim indicates a disclosed claim was not requested
	// (selective-disclosure layer).
	ErrUnrequestedClaim = errors.New("eudi: disclosed claim was not requested")
	// ErrMissingMandatoryClaim indicates a required claim was not disclosed
	// (selective-disclosure layer).
	ErrMissingMandatoryClaim = errors.New("eudi: mandatory claim missing")
	// ErrInvalidPresentation indicates the presentation failed structural or
	// cryptographic verification (wraps sdjwt errors).
	ErrInvalidPresentation = errors.New("eudi: invalid presentation")
	// ErrInvalidResponse indicates the OpenID4VP authorization response could
	// not be parsed or lacked the expected presentation (transport layer).
	ErrInvalidResponse = errors.New("eudi: invalid authorization response")
	// ErrPolicy indicates the verification policy itself was misconfigured.
	ErrPolicy = errors.New("eudi: invalid verification policy")
)

// Policy is the config-driven PID verification policy. The claim sets use dotted
// paths (e.g. "given_name", "address.locality") matching the SD-JWT disclosure
// paths, so tightening what is requested is purely a configuration change.
type Policy struct {
	// ExpectedVCT is the required credential type. Defaults to PIDVCTSDJWT.
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

// VerifiedPID is the result of a successful PID presentation verification.
type VerifiedPID struct {
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
