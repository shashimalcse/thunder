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

	"github.com/thunder-id/thunderid/internal/system/error/apierror"
	"github.com/thunder-id/thunderid/internal/system/error/serviceerror"
	"github.com/thunder-id/thunderid/internal/system/log"
	sysutils "github.com/thunder-id/thunderid/internal/system/utils"
)

// requestObjectContentType is the media type of a signed OpenID4VP request object.
const requestObjectContentType = "application/oauth-authz-req+jwt"

// handler serves the wallet-facing OpenID4VP endpoints.
type handler struct {
	service *Service
}

func newHandler(service *Service) *handler {
	return &handler{service: service}
}

// HandleRequestObject serves GET request_uri: it returns the signed request
// object (JAR) for the state in the query string.
func (h *handler) HandleRequestObject(w http.ResponseWriter, r *http.Request) {
	state := sysutils.SanitizeString(r.URL.Query().Get("state"))
	if state == "" {
		writeServiceErrorResponse(w, &ErrorInvalidRequest)
		return
	}

	jar, err := h.service.RequestObject(r.Context(), state)
	if err != nil {
		writeServiceErrorResponse(w, toServiceError(err))
		return
	}

	w.Header().Set("Content-Type", requestObjectContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, werr := w.Write([]byte(jar)); werr != nil {
		log.GetLogger().Error("Failed to write request object response", log.Error(werr))
	}
}

// HandleResponse serves POST response_uri: it accepts the wallet's encrypted
// response (direct_post.jwt) and, on success, returns a redirect_uri to follow.
func (h *handler) HandleResponse(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeServiceErrorResponse(w, &ErrorInvalidRequest)
		return
	}

	// The per-request response_uri carries the state in its query string;
	// FormValue also accepts it from the form body.
	state := sysutils.SanitizeString(r.FormValue("state"))
	response := r.FormValue("response")
	if state == "" || response == "" {
		writeServiceErrorResponse(w, &ErrorInvalidRequest)
		return
	}

	if _, err := h.service.SubmitResponse(r.Context(), state, response); err != nil {
		writeServiceErrorResponse(w, toServiceError(err))
		return
	}

	body := map[string]string{}
	if redirect := h.service.ResultRedirectURI(state); redirect != "" {
		body["redirect_uri"] = redirect
	}
	sysutils.WriteSuccessResponse(w, http.StatusOK, body)
}

// writeServiceErrorResponse maps a service error to an HTTP error response.
func writeServiceErrorResponse(w http.ResponseWriter, svcErr *serviceerror.ServiceError) {
	statusCode := http.StatusInternalServerError
	if svcErr.Type == serviceerror.ClientErrorType {
		statusCode = clientErrorStatusCode(svcErr.Code)
	}
	sysutils.WriteErrorResponse(w, statusCode, apierror.ErrorResponse{
		Code:        svcErr.Code,
		Message:     svcErr.Error,
		Description: svcErr.ErrorDescription,
	})
}

// clientErrorStatusCode maps a client error code to an HTTP status code.
func clientErrorStatusCode(code string) int {
	if code == ErrorUnknownState.Code {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}
