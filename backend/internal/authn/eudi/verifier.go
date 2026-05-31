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
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/thunder-id/thunderid/internal/system/cryptolib"
	"github.com/thunder-id/thunderid/internal/system/jose/sdjwt"
)

// PIDVerifier verifies EUDI PID SD-JWT VC presentations against a policy and a
// trust store.
type PIDVerifier struct {
	trust  TrustStore
	policy Policy
}

// NewPIDVerifier creates a PID verifier. ExpectedVCT defaults to PIDVCTSDJWT.
func NewPIDVerifier(trust TrustStore, policy Policy) (*PIDVerifier, error) {
	if trust == nil {
		return nil, fmt.Errorf("%w: trust store is required", ErrPolicy)
	}
	if policy.ExpectedVCT == "" {
		policy.ExpectedVCT = PIDVCTSDJWT
	}
	if policy.Audience == "" {
		return nil, fmt.Errorf("%w: audience is required", ErrPolicy)
	}
	return &PIDVerifier{trust: trust, policy: policy}, nil
}

// Verify validates a combined-format PID presentation against the expected
// nonce, then enforces PID policy and returns the verified person and claims.
// The layers run fail-fast: parse, issuer trust, full SD-JWT verification
// (signature, selective disclosure, holder binding), then credential and
// selective-disclosure policy.
func (v *PIDVerifier) Verify(ctx context.Context, presentation, nonce string) (*VerifiedPID, error) {
	p, err := sdjwt.Parse(presentation)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPresentation, err)
	}

	issuerClaims, err := p.IssuerClaims()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPresentation, err)
	}
	issuer, _ := issuerClaims["iss"].(string)
	if issuer == "" {
		return nil, fmt.Errorf("%w: credential missing iss", ErrInvalidPresentation)
	}

	issuerKey, err := v.trust.IssuerKey(ctx, issuer)
	if err != nil {
		return nil, err
	}

	cred, err := sdjwt.Verify(p, sdjwt.VerifyOptions{
		IssuerKey:         issuerKey,
		RequireKeyBinding: true,
		ExpectedAudience:  v.policy.Audience,
		ExpectedNonce:     nonce,
		Leeway:            v.policy.Leeway,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPresentation, err)
	}

	vct, _ := cred.Claims["vct"].(string)
	if vct != v.policy.ExpectedVCT {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrUnexpectedVCT, vct, v.policy.ExpectedVCT)
	}

	if err := v.enforceClaimPolicy(cred.DisclosedPaths, cred.Claims); err != nil {
		return nil, err
	}

	return &VerifiedPID{
		Subject:        deriveSubject(issuer, cred.Claims),
		Issuer:         issuer,
		VCT:            vct,
		Claims:         flattenClaims(cred.Claims),
		DisclosedPaths: cred.DisclosedPaths,
	}, nil
}

// enforceClaimPolicy applies data minimisation: every disclosed claim must have
// been requested, and every mandatory claim must be present.
func (v *PIDVerifier) enforceClaimPolicy(disclosed []string, claims map[string]interface{}) error {
	if len(v.policy.RequestedClaims) > 0 {
		requested := make(map[string]bool, len(v.policy.RequestedClaims))
		for _, c := range v.policy.RequestedClaims {
			requested[c] = true
		}
		for _, path := range disclosed {
			if !requested[path] {
				return fmt.Errorf("%w: %s", ErrUnrequestedClaim, path)
			}
		}
	}

	for _, mandatory := range v.policy.MandatoryClaims {
		if _, ok := lookupClaim(claims, mandatory); !ok {
			return fmt.Errorf("%w: %s", ErrMissingMandatoryClaim, mandatory)
		}
	}
	return nil
}

// lookupClaim resolves a dotted path against a nested claims map.
func lookupClaim(claims map[string]interface{}, path string) (interface{}, bool) {
	segments := strings.Split(path, ".")
	var current interface{} = claims
	for _, seg := range segments {
		obj, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current, ok = obj[seg]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// flattenClaims returns the PID attributes as a dotted-path-keyed map, omitting
// SD-JWT and credential-metadata claims that are not user attributes.
func flattenClaims(claims map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{})
	flattenInto(out, "", claims)
	for _, meta := range []string{"iss", "vct", "cnf", "iat", "exp", "nbf", "status", "_sd_alg"} {
		delete(out, meta)
	}
	return out
}

// flattenInto walks nested objects into dotted-path keys. Arrays and scalars are
// stored as-is at their path.
func flattenInto(out map[string]interface{}, prefix string, node map[string]interface{}) {
	for k, val := range node {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if nested, ok := val.(map[string]interface{}); ok {
			flattenInto(out, key, nested)
			continue
		}
		out[key] = val
	}
}

// deriveSubject produces a stable, privacy-respecting identifier for the verified
// person. A credential-provided "sub" is preferred; otherwise a deterministic
// pseudonym is derived from the issuer and the core identity attributes. This is
// a spike-only scheme; linking strategy is a later decision.
func deriveSubject(issuer string, claims map[string]interface{}) string {
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		return sub
	}
	parts := []string{issuer}
	for _, field := range []string{"family_name", "given_name", "birthdate"} {
		if val, ok := lookupClaim(claims, field); ok {
			parts = append(parts, fmt.Sprintf("%s=%v", field, val))
		}
	}
	sort.Strings(parts[1:])
	sum, err := cryptolib.Hash([]byte(strings.Join(parts, "|")), cryptolib.GenericSHA256)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(sum)
}
