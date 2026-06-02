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
	"fmt"
	"strings"

	"github.com/thunder-id/thunderid/internal/system/jose/sdjwt"
)

// Verifier verifies OpenID4VP SD-JWT VC presentations against a policy and a
// trust store.
type Verifier struct {
	trust  TrustStore
	policy Policy
}

// NewVerifier creates a verifier. The policy must set ExpectedVCT and Audience.
func NewVerifier(trust TrustStore, policy Policy) (*Verifier, error) {
	if trust == nil {
		return nil, fmt.Errorf("%w: trust store is required", ErrPolicy)
	}
	if policy.ExpectedVCT == "" {
		return nil, fmt.Errorf("%w: expected vct is required", ErrPolicy)
	}
	if policy.Audience == "" {
		return nil, fmt.Errorf("%w: audience is required", ErrPolicy)
	}
	return &Verifier{trust: trust, policy: policy}, nil
}

// Verify validates a combined-format presentation against the expected nonce,
// then enforces policy and returns the verified presentation and claims.
// The layers run fail-fast: parse, issuer trust, full SD-JWT verification
// (signature, selective disclosure, holder binding), then credential and
// selective-disclosure policy.
func (v *Verifier) Verify(ctx context.Context, presentation, nonce string) (*VerifiedPresentation, error) {
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

	subject, _ := cred.Claims["sub"].(string)
	return &VerifiedPresentation{
		Subject:        subject,
		Issuer:         issuer,
		VCT:            vct,
		Claims:         flattenClaims(cred.Claims),
		DisclosedPaths: cred.DisclosedPaths,
	}, nil
}

// enforceClaimPolicy applies data minimisation: every disclosed claim must have
// been requested, and every mandatory claim must be present.
func (v *Verifier) enforceClaimPolicy(disclosed []string, claims map[string]interface{}) error {
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
