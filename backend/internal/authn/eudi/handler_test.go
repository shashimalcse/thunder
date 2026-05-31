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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleRequestObject(t *testing.T) {
	b := newPIDBuilder(t)
	svc, _ := newTestService(t, b)
	h := newHandler(svc)

	init, err := svc.Initiate(context.Background())
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/openid4vp/request?state="+url.QueryEscape(init.State), nil)
		rec := httptest.NewRecorder()
		h.HandleRequestObject(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, requestObjectContentType, rec.Header().Get("Content-Type"))
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		assert.Len(t, strings.Split(rec.Body.String(), "."), 3)
	})

	t.Run("missing state", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/openid4vp/request", nil)
		rec := httptest.NewRecorder()
		h.HandleRequestObject(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, ErrorInvalidRequest.Code, decodeErrorCode(t, rec))
	})

	t.Run("unknown state", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/openid4vp/request?state=nope", nil)
		rec := httptest.NewRecorder()
		h.HandleRequestObject(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Equal(t, ErrorUnknownState.Code, decodeErrorCode(t, rec))
	})
}

func TestHandleResponse(t *testing.T) {
	b := newPIDBuilder(t)
	svc, store := newTestService(t, b)
	svc.cfg.ResultRedirectURIBase = "https://verifier.example/result"
	h := newHandler(svc)

	init, err := svc.Initiate(context.Background())
	require.NoError(t, err)
	rs := store.m[init.State]

	presentation := b.build(rs.Nonce, map[string]interface{}{
		"given_name": "Erika", "family_name": "Mustermann",
	})
	body, err := json.Marshal(map[string]interface{}{
		"state":    init.State,
		"vp_token": map[string]interface{}{DefaultPIDCredentialID: []string{presentation}},
	})
	require.NoError(t, err)
	jweToken := fabricateResponseJWE(t, &rs.EphemeralKey.PublicKey, body)

	t.Run("success returns redirect_uri", func(t *testing.T) {
		form := url.Values{"state": {init.State}, "response": {jweToken}}
		rec := postForm(h, form)
		assert.Equal(t, http.StatusOK, rec.Code)

		var resp map[string]string
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Contains(t, resp["redirect_uri"], "state=")
	})

	t.Run("missing fields", func(t *testing.T) {
		rec := postForm(h, url.Values{"state": {init.State}})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, ErrorInvalidRequest.Code, decodeErrorCode(t, rec))
	})
}

func TestHandleResponseVerificationFailure(t *testing.T) {
	b := newPIDBuilder(t)
	svc, store := newTestService(t, b)
	h := newHandler(svc)

	init, err := svc.Initiate(context.Background())
	require.NoError(t, err)
	rs := store.m[init.State]

	// Presentation bound to the wrong nonce -> verification fails.
	presentation := b.build("wrong-nonce", map[string]interface{}{"given_name": "Erika", "family_name": "M"})
	body, err := json.Marshal(map[string]interface{}{
		"state":    init.State,
		"vp_token": map[string]interface{}{DefaultPIDCredentialID: []string{presentation}},
	})
	require.NoError(t, err)
	jweToken := fabricateResponseJWE(t, &rs.EphemeralKey.PublicKey, body)

	rec := postForm(h, url.Values{"state": {init.State}, "response": {jweToken}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, ErrorVerificationFailed.Code, decodeErrorCode(t, rec))
}

func postForm(h *handler, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/openid4vp/response", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.HandleResponse(rec, req)
	return rec
}

func decodeErrorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Code string `json:"code"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Code
}
