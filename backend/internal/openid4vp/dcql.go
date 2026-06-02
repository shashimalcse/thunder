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
	"fmt"
	"strings"
)

const (
	// FormatSDJWTVC is the OpenID4VP credential format identifier for SD-JWT VC.
	FormatSDJWTVC = "dc+sd-jwt"
)

// DCQLConfig describes the credential query to build. Keeping the claim set in
// configuration means "ask for less" is a configuration change.
type DCQLConfig struct {
	// CredentialID is the DCQL query id. Required.
	CredentialID string
	// VCT is the required credential type (vct_values). Required.
	VCT string
	// Claims are the requested claim paths in dotted notation (e.g.
	// "given_name", "address.locality"). Required (at least one).
	Claims []string
}

// DCQLQuery is the OpenID4VP Digital Credentials Query Language query object.
type DCQLQuery struct {
	Credentials    []DCQLCredential    `json:"credentials"`
	CredentialSets []DCQLCredentialSet `json:"credential_sets,omitempty"`
}

// DCQLCredential is a single credential query.
type DCQLCredential struct {
	ID     string      `json:"id"`
	Format string      `json:"format"`
	Meta   *DCQLMeta   `json:"meta,omitempty"`
	Claims []DCQLClaim `json:"claims,omitempty"`
}

// DCQLMeta carries format-specific matching metadata.
type DCQLMeta struct {
	VCTValues []string `json:"vct_values,omitempty"`
}

// DCQLClaim selects a single claim by its path. Path elements are object keys
// (strings); array indexing is not used for the PID claim set.
type DCQLClaim struct {
	Path []interface{} `json:"path"`
}

// DCQLCredentialSet groups credential options that together satisfy the request.
type DCQLCredentialSet struct {
	Options [][]string `json:"options"`
}

// BuildQuery builds the DCQL query requesting the configured claims as an
// SD-JWT VC. It produces the sandbox guide's single-format request; an mdoc
// option can be added later without changing callers.
func BuildQuery(cfg DCQLConfig) (*DCQLQuery, error) {
	credentialID := cfg.CredentialID
	vct := cfg.VCT
	claims := cfg.Claims
	if credentialID == "" || vct == "" || len(claims) == 0 {
		return nil, fmt.Errorf("%w: credential_id, vct and at least one claim are required", ErrPolicy)
	}

	dcqlClaims := make([]DCQLClaim, 0, len(claims))
	for _, path := range claims {
		segments, err := claimPathToSegments(path)
		if err != nil {
			return nil, err
		}
		dcqlClaims = append(dcqlClaims, DCQLClaim{Path: segments})
	}

	return &DCQLQuery{
		Credentials: []DCQLCredential{
			{
				ID:     credentialID,
				Format: FormatSDJWTVC,
				Meta:   &DCQLMeta{VCTValues: []string{vct}},
				Claims: dcqlClaims,
			},
		},
		CredentialSets: []DCQLCredentialSet{
			{Options: [][]string{{credentialID}}},
		},
	}, nil
}

// claimPathToSegments converts a dotted claim path into DCQL path segments.
func claimPathToSegments(path string) ([]interface{}, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty claim path", ErrPolicy)
	}
	parts := strings.Split(path, ".")
	segments := make([]interface{}, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("%w: malformed claim path %q", ErrPolicy, path)
		}
		segments = append(segments, part)
	}
	return segments, nil
}
