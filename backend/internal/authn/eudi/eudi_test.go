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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/thunder-id/thunderid/internal/openid4vp"
	"github.com/thunder-id/thunderid/internal/system/config"
)

func TestDeriveSubjectPrefersSubClaim(t *testing.T) {
	got := DeriveSubject(&openid4vp.VerifiedPresentation{Subject: "stable-sub", Issuer: "iss"})
	assert.Equal(t, "stable-sub", got)
}

func TestDeriveSubjectPseudonymIsStableAndPerPerson(t *testing.T) {
	erika := func() *openid4vp.VerifiedPresentation {
		return &openid4vp.VerifiedPresentation{
			Issuer: "https://issuer.example",
			Claims: map[string]interface{}{"given_name": "Erika", "family_name": "Mustermann", "birthdate": "1984-01-26"},
		}
	}
	a := DeriveSubject(erika())
	b := DeriveSubject(erika())
	assert.NotEmpty(t, a)
	assert.Equal(t, a, b, "same person + issuer -> stable subject")

	max := DeriveSubject(&openid4vp.VerifiedPresentation{
		Issuer: "https://issuer.example",
		Claims: map[string]interface{}{"given_name": "Max", "family_name": "Mustermann", "birthdate": "1990-05-05"},
	})
	assert.NotEqual(t, a, max, "different person -> different subject")
}

func TestBuildConfigAppliesPIDDefaults(t *testing.T) {
	cfg := buildConfig(config.OpenID4VPConfig{ClientID: "x509_hash:x", SigningKeyID: "k", BaseURL: "https://x"}, "")
	assert.Equal(t, DefaultPIDCredentialID, cfg.CredentialID)
	assert.Equal(t, PIDVCTSDJWT, cfg.VCT)
	assert.Equal(t, DefaultPIDClaims, cfg.RequestedClaims)
}

func TestBuildConfigHonoursOverridesAndDurations(t *testing.T) {
	cfg := buildConfig(config.OpenID4VPConfig{
		CredentialID:           "custom-id",
		VCT:                    "urn:custom",
		RequestedClaims:        []string{"given_name"},
		RequestValiditySeconds: 300,
		StateTTLSeconds:        120,
		LeewaySeconds:          30,
	}, "")
	assert.Equal(t, "custom-id", cfg.CredentialID)
	assert.Equal(t, "urn:custom", cfg.VCT)
	assert.Equal(t, []string{"given_name"}, cfg.RequestedClaims)
	assert.Equal(t, 300*time.Second, cfg.RequestValidity)
	assert.Equal(t, 120*time.Second, cfg.StateTTL)
	assert.Equal(t, 30*time.Second, cfg.Leeway)
}

func TestBuildConfigResolvesTrustedIssuerPaths(t *testing.T) {
	cfg := buildConfig(config.OpenID4VPConfig{
		TrustedIssuers: []config.PIDIssuerConfig{
			{Issuer: "https://issuer.example", CertFile: "repository/resources/security/pid.cert"},
			{Issuer: "https://abs.example", CertFile: "/etc/abs.cert"},
		},
	}, "/home/thunder")
	require.Len(t, cfg.TrustedIssuers, 2)
	assert.Equal(t, "https://issuer.example", cfg.TrustedIssuers[0].Issuer)
	assert.Equal(t, filepath.Join("/home/thunder", "repository/resources/security/pid.cert"), cfg.TrustedIssuers[0].CertFile)
	// Absolute paths are left untouched.
	assert.Equal(t, "/etc/abs.cert", cfg.TrustedIssuers[1].CertFile)
}
