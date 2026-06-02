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

// Package eudi is the EUDI Wallet PID authenticator. It is a thin consumer of
// the generic OpenID4VP verifier (internal/openid4vp): it supplies the PID
// (urn:eudi:pid:de:1) defaults and derives a verified-person subject.
package eudi

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/thunder-id/thunderid/internal/openid4vp"
	"github.com/thunder-id/thunderid/internal/system/config"
	"github.com/thunder-id/thunderid/internal/system/cryptolib"
)

// Confirmed EUDI PID SD-JWT VC identifiers (German sandbox HAIP profile).
const (
	// PIDVCTSDJWT is the SD-JWT VC type of the German PID.
	PIDVCTSDJWT = "urn:eudi:pid:de:1"
	// DefaultPIDCredentialID is the DCQL credential query id used for the PID.
	DefaultPIDCredentialID = "pid-sd-jwt"
)

// DefaultPIDClaims is the minimal PID claim set (data minimisation default).
var DefaultPIDClaims = []string{"given_name", "family_name", "birthdate"}

// DeriveSubject produces a stable, privacy-respecting identifier for the verified
// person. A credential-provided "sub" is preferred; otherwise a deterministic
// pseudonym is derived from the issuer and the core PID identity attributes.
// This is a spike-only scheme; the linking strategy is a later decision.
func DeriveSubject(vp *openid4vp.VerifiedPresentation) string {
	if vp.Subject != "" {
		return vp.Subject
	}
	parts := []string{vp.Issuer}
	for _, field := range []string{"family_name", "given_name", "birthdate"} {
		if val, ok := vp.Claims[field]; ok {
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

// buildConfig maps the deployment OpenID4VP config to an openid4vp.Config,
// applying PID defaults and resolving trusted-issuer cert paths against serverHome.
func buildConfig(cfg config.OpenID4VPConfig, serverHome string) openid4vp.Config {
	credentialID := cfg.CredentialID
	if credentialID == "" {
		credentialID = DefaultPIDCredentialID
	}
	vct := cfg.VCT
	if vct == "" {
		vct = PIDVCTSDJWT
	}
	claims := cfg.RequestedClaims
	if len(claims) == 0 {
		claims = DefaultPIDClaims
	}

	issuers := make([]openid4vp.TrustedIssuer, 0, len(cfg.TrustedIssuers))
	for _, ti := range cfg.TrustedIssuers {
		issuers = append(issuers, openid4vp.TrustedIssuer{
			Issuer:   ti.Issuer,
			CertFile: resolvePath(serverHome, ti.CertFile),
		})
	}

	return openid4vp.Config{
		ClientID:          cfg.ClientID,
		SigningKeyID:      cfg.SigningKeyID,
		BaseURL:           cfg.BaseURL,
		ResultRedirectURI: cfg.ResultRedirectURI,
		RequestAudience:   cfg.RequestAudience,
		CredentialID:      credentialID,
		VCT:               vct,
		EphemeralKeyID:    cfg.EphemeralKeyID,
		RequestedClaims:   claims,
		MandatoryClaims:   cfg.MandatoryClaims,
		ResponseEncValues: cfg.ResponseEncValues,
		RequestValidity:   time.Duration(cfg.RequestValiditySeconds) * time.Second,
		StateTTL:          time.Duration(cfg.StateTTLSeconds) * time.Second,
		Leeway:            time.Duration(cfg.LeewaySeconds) * time.Second,
		TrustedIssuers:    issuers,
	}
}

// resolvePath joins a relative path with the server home directory.
func resolvePath(serverHome, path string) string {
	if path == "" || filepath.IsAbs(path) || serverHome == "" {
		return path
	}
	return filepath.Join(serverHome, path)
}
