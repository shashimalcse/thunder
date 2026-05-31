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
	"fmt"
	"strings"
)

const (
	// FormatSDJWTVC is the OpenID4VP credential format identifier for SD-JWT VC.
	FormatSDJWTVC = "dc+sd-jwt"
	// DefaultPIDCredentialID is the DCQL credential query id used for the PID.
	DefaultPIDCredentialID = "pid-sd-jwt"
)

// DefaultPIDClaims is the minimal PID claim set (data minimisation default).
var DefaultPIDClaims = []string{"given_name", "family_name", "birthdate"}

// DCQLConfig describes the PID credential query to build. Keeping the claim set
// here means "ask for less" is a configuration change.
type DCQLConfig struct {
	// CredentialID is the DCQL query id. Defaults to DefaultPIDCredentialID.
	CredentialID string
	// VCT is the required credential type. Defaults to PIDVCTSDJWT.
	VCT string
	// Claims are the requested claim paths in dotted notation (e.g.
	// "given_name", "address.locality"). Defaults to DefaultPIDClaims.
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

// BuildPIDQuery builds the DCQL query requesting the configured PID claims as an
// SD-JWT VC. It mirrors the sandbox guide's single-format request; an mdoc
// option can be added later without changing callers.
func BuildPIDQuery(cfg DCQLConfig) (*DCQLQuery, error) {
	credentialID := cfg.CredentialID
	if credentialID == "" {
		credentialID = DefaultPIDCredentialID
	}
	vct := cfg.VCT
	if vct == "" {
		vct = PIDVCTSDJWT
	}
	claims := cfg.Claims
	if len(claims) == 0 {
		claims = DefaultPIDClaims
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
