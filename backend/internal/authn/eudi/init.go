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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thunder-id/thunderid/internal/system/cache"
	"github.com/thunder-id/thunderid/internal/system/config"
	kmprovider "github.com/thunder-id/thunderid/internal/system/kmprovider/common"
	"github.com/thunder-id/thunderid/internal/system/log"
	"github.com/thunder-id/thunderid/internal/system/middleware"
)

// Route paths for the wallet-facing OpenID4VP endpoints.
const (
	requestURIPath  = "/openid4vp/request"
	responseURIPath = "/openid4vp/response"
)

// Initialize wires the OpenID4VP verifier service and registers its endpoints.
// It returns (nil, nil) when the verifier is disabled in configuration.
func Initialize(
	mux *http.ServeMux, cryptoProvider kmprovider.RuntimeCryptoProvider, cacheManager cache.CacheManagerInterface,
) (*Service, error) {
	runtime := config.GetServerRuntime()
	cfg := runtime.Config.OpenID4VP
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "OpenID4VPService"))

	if !cfg.Enabled {
		logger.Debug("OpenID4VP verifier is disabled; skipping initialization")
		return nil, nil
	}

	trust, err := buildTrustStore(runtime.ServerHome, cfg.TrustedIssuers)
	if err != nil {
		return nil, err
	}

	verifier, err := NewPIDVerifier(trust, Policy{
		ExpectedVCT:     cfg.VCT,
		Audience:        cfg.ClientID,
		RequestedClaims: cfg.RequestedClaims,
		MandatoryClaims: cfg.MandatoryClaims,
		Leeway:          time.Duration(cfg.LeewaySeconds) * time.Second,
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
			Validity:          time.Duration(cfg.RequestValiditySeconds) * time.Second,
			DCQL:              DCQLConfig{CredentialID: cfg.CredentialID, VCT: cfg.VCT, Claims: cfg.RequestedClaims},
			ResponseEncValues: cfg.ResponseEncValues,
		},
		CredentialID:          cfg.CredentialID,
		RequestURIBase:        base + requestURIPath,
		ResponseURIBase:       base + responseURIPath,
		EphemeralKeyID:        cfg.EphemeralKeyID,
		TTL:                   time.Duration(cfg.StateTTLSeconds) * time.Second,
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

// buildTrustStore loads the configured trusted PID issuer certificates.
func buildTrustStore(serverHome string, issuers []config.PIDIssuerConfig) (TrustStore, error) {
	if len(issuers) == 0 {
		return nil, fmt.Errorf("%w: at least one trusted issuer is required", ErrPolicy)
	}
	keys := make(map[string]crypto.PublicKey, len(issuers))
	for _, issuer := range issuers {
		if issuer.Issuer == "" || issuer.CertFile == "" {
			return nil, fmt.Errorf("%w: trusted issuer requires issuer and cert_file", ErrPolicy)
		}
		key, err := loadIssuerKey(resolvePath(serverHome, issuer.CertFile))
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

// resolvePath joins a relative path with the server home directory.
func resolvePath(serverHome, path string) string {
	if filepath.IsAbs(path) || serverHome == "" {
		return path
	}
	return filepath.Join(serverHome, path)
}
