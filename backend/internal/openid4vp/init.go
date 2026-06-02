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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/thunder-id/thunderid/internal/system/cache"
	kmprovider "github.com/thunder-id/thunderid/internal/system/kmprovider/common"
	"github.com/thunder-id/thunderid/internal/system/log"
	"github.com/thunder-id/thunderid/internal/system/middleware"
)

// Route paths for the wallet-facing OpenID4VP endpoints.
const (
	requestURIPath  = "/openid4vp/request"
	responseURIPath = "/openid4vp/response"
)

// TrustedIssuer pins a trusted credential issuer's signing certificate.
type TrustedIssuer struct {
	Issuer string
	// CertFile is a path to a PEM CERTIFICATE or PUBLIC KEY. It must be resolved
	// (absolute, or relative to the caller's working directory) before passing.
	CertFile string
}

// Config is the full configuration of the OpenID4VP verifier service. Callers
// (e.g. the EUDI authenticator) build it from their own configuration source.
type Config struct {
	ClientID          string
	SigningKeyID      string
	BaseURL           string
	ResultRedirectURI string
	RequestAudience   string
	CredentialID      string
	VCT               string
	EphemeralKeyID    string
	RequestedClaims   []string
	MandatoryClaims   []string
	ResponseEncValues []string
	RequestValidity   time.Duration
	StateTTL          time.Duration
	Leeway            time.Duration
	TrustedIssuers    []TrustedIssuer
}

// Initialize wires the OpenID4VP verifier service and registers its wallet-facing
// endpoints, returning the Service for in-process consumers (e.g. a flow executor).
func Initialize(
	mux *http.ServeMux, cryptoProvider kmprovider.RuntimeCryptoProvider,
	cacheManager cache.CacheManagerInterface, cfg Config,
) (*Service, error) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "OpenID4VPService"))

	trust, err := buildTrustStore(cfg.TrustedIssuers)
	if err != nil {
		return nil, err
	}

	verifier, err := NewVerifier(trust, Policy{
		ExpectedVCT:     cfg.VCT,
		Audience:        cfg.ClientID,
		RequestedClaims: cfg.RequestedClaims,
		MandatoryClaims: cfg.MandatoryClaims,
		Leeway:          cfg.Leeway,
	})
	if err != nil {
		return nil, err
	}

	signer, err := NewRequestSigner(context.Background(), cryptoProvider, cfg.SigningKeyID)
	if err != nil {
		return nil, err
	}

	base := strings.TrimRight(cfg.BaseURL, "/")
	svc, err := NewService(ServiceConfig{
		Request: RequestConfig{
			ClientID:          cfg.ClientID,
			Audience:          cfg.RequestAudience,
			Validity:          cfg.RequestValidity,
			DCQL:              DCQLConfig{CredentialID: cfg.CredentialID, VCT: cfg.VCT, Claims: cfg.RequestedClaims},
			ResponseEncValues: cfg.ResponseEncValues,
		},
		CredentialID:          cfg.CredentialID,
		RequestURIBase:        base + requestURIPath,
		ResponseURIBase:       base + responseURIPath,
		EphemeralKeyID:        cfg.EphemeralKeyID,
		TTL:                   cfg.StateTTL,
		ResultRedirectURIBase: cfg.ResultRedirectURI,
	}, NewCacheStateStore(cacheManager), signer, verifier)
	if err != nil {
		return nil, err
	}

	registerRoutes(mux, newHandler(svc))
	logger.Info("OpenID4VP verifier initialized", log.String("clientID", cfg.ClientID))
	return svc, nil
}

// registerRoutes registers the wallet-facing endpoints on the mux.
func registerRoutes(mux *http.ServeMux, h *handler) {
	opts := middleware.CORSOptions{
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   middleware.DefaultAllowedHeaders,
		AllowCredentials: true,
		MaxAge:           600,
	}

	mux.HandleFunc(middleware.WithCORS("GET "+requestURIPath,
		middleware.CorrelationIDMiddleware(http.HandlerFunc(h.HandleRequestObject)).ServeHTTP, opts))
	mux.HandleFunc(middleware.WithCORS("POST "+responseURIPath,
		middleware.CorrelationIDMiddleware(http.HandlerFunc(h.HandleResponse)).ServeHTTP, opts))

	for _, path := range []string{requestURIPath, responseURIPath} {
		mux.HandleFunc(middleware.WithCORS("OPTIONS "+path,
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }, opts))
	}
}

// buildTrustStore loads the configured trusted issuer certificates.
func buildTrustStore(issuers []TrustedIssuer) (TrustStore, error) {
	if len(issuers) == 0 {
		return nil, fmt.Errorf("%w: at least one trusted issuer is required", ErrPolicy)
	}
	keys := make(map[string]crypto.PublicKey, len(issuers))
	for _, issuer := range issuers {
		if issuer.Issuer == "" || issuer.CertFile == "" {
			return nil, fmt.Errorf("%w: trusted issuer requires issuer and cert_file", ErrPolicy)
		}
		key, err := loadIssuerKey(issuer.CertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load trusted issuer %q: %w", issuer.Issuer, err)
		}
		keys[issuer.Issuer] = key
	}
	return NewStaticTrustStore(keys), nil
}

// loadIssuerKey reads an issuer signing key from a PEM file containing either an
// X.509 certificate or a PKIX public key.
func loadIssuerKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-configured
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q in %s", block.Type, path)
	}
}
