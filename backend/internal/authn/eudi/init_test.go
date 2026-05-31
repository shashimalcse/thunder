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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/thunder-id/thunderid/internal/system/config"
)

// writeSelfSignedCertPEM writes a self-signed cert for key to a temp file and
// returns its path.
func writeSelfSignedCertPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-pid-issuer"},
		NotBefore:    time.Unix(1_700_000_000, 0),
		NotAfter:     time.Unix(1_900_000_000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "issuer.cert")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

func TestBuildTrustStoreLoadsCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	certPath := writeSelfSignedCertPEM(t, key)

	store, err := buildTrustStore("", []config.PIDIssuerConfig{
		{Issuer: "https://issuer.example", CertFile: certPath},
	})
	require.NoError(t, err)

	got, err := store.IssuerKey(context.Background(), "https://issuer.example")
	require.NoError(t, err)
	pub, ok := got.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, key.PublicKey.Equal(pub))

	_, err = store.IssuerKey(context.Background(), "https://unknown.example")
	assert.ErrorIs(t, err, ErrUntrustedIssuer)
}

func TestBuildTrustStoreErrors(t *testing.T) {
	t.Run("no issuers", func(t *testing.T) {
		_, err := buildTrustStore("", nil)
		assert.ErrorIs(t, err, ErrPolicy)
	})

	t.Run("missing fields", func(t *testing.T) {
		_, err := buildTrustStore("", []config.PIDIssuerConfig{{Issuer: "x"}})
		assert.ErrorIs(t, err, ErrPolicy)
	})

	t.Run("unreadable cert", func(t *testing.T) {
		_, err := buildTrustStore("", []config.PIDIssuerConfig{
			{Issuer: "x", CertFile: filepath.Join(t.TempDir(), "missing.cert")},
		})
		assert.Error(t, err)
	})
}

func TestLoadIssuerKeyRejectsNonPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.cert")
	require.NoError(t, os.WriteFile(path, []byte("not pem"), 0o600))
	_, err := loadIssuerKey(path)
	assert.Error(t, err)
}

func TestResolvePath(t *testing.T) {
	assert.Equal(t, "/abs/path", resolvePath("/home", "/abs/path"))
	assert.Equal(t, "rel/path", resolvePath("", "rel/path"))
	assert.Equal(t, filepath.Join("/home", "rel"), resolvePath("/home", "rel"))
}

func TestInitializeDisabledReturnsNil(t *testing.T) {
	config.ResetServerRuntime()
	require.NoError(t, config.InitializeServerRuntime("", &config.Config{
		OpenID4VP: config.OpenID4VPConfig{Enabled: false},
	}))
	t.Cleanup(config.ResetServerRuntime)

	svc, err := Initialize(http.NewServeMux(), nil, nil)
	require.NoError(t, err)
	assert.Nil(t, svc)
}
