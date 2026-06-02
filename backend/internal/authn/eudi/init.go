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
	"net/http"

	"github.com/thunder-id/thunderid/internal/openid4vp"
	"github.com/thunder-id/thunderid/internal/system/cache"
	"github.com/thunder-id/thunderid/internal/system/config"
	kmprovider "github.com/thunder-id/thunderid/internal/system/kmprovider/common"
	"github.com/thunder-id/thunderid/internal/system/log"
)

// Initialize wires the EUDI Wallet PID verifier on top of the OpenID4VP verifier
// when enabled in configuration, returning the shared Service (nil when disabled).
func Initialize(
	mux *http.ServeMux, cryptoProvider kmprovider.RuntimeCryptoProvider, cacheManager cache.CacheManagerInterface,
) (*openid4vp.Service, error) {
	runtime := config.GetServerRuntime()
	cfg := runtime.Config.OpenID4VP
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "EUDIAuthenticator"))

	if !cfg.Enabled {
		logger.Debug("EUDI PID verifier is disabled; skipping initialization")
		return nil, nil
	}

	return openid4vp.Initialize(mux, cryptoProvider, cacheManager, buildConfig(cfg, runtime.ServerHome))
}
