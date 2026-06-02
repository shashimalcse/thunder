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

package executor

import (
	"context"

	authncm "github.com/thunder-id/thunderid/internal/authn/common"
	"github.com/thunder-id/thunderid/internal/authn/eudi"
	"github.com/thunder-id/thunderid/internal/flow/common"
	"github.com/thunder-id/thunderid/internal/flow/core"
	"github.com/thunder-id/thunderid/internal/openid4vp"
	"github.com/thunder-id/thunderid/internal/system/log"
)

const (
	// eudiRuntimeKeyState holds the OpenID4VP request state across poll steps.
	eudiRuntimeKeyState = "eudiVerificationState"
	// AdditionalData keys carrying the QR / deep-link payload to the client.
	eudiDataClientID   = "eudiClientId"
	eudiDataRequestURI = "eudiRequestUri"
	eudiDataWalletURI  = "eudiWalletUri"

	failureReasonEUDINotConfigured = "OpenID4VP verifier is not configured"
	failureReasonEUDIInitiate      = "Failed to initiate the EUDI Wallet request"
	failureReasonEUDIExpired       = "The EUDI Wallet request expired before a response was received"
)

// eudiVerifierService is the subset of the OpenID4VP verifier service the
// executor depends on. *openid4vp.Service satisfies it.
type eudiVerifierService interface {
	Initiate(ctx context.Context) (*openid4vp.Initiation, error)
	Result(ctx context.Context, state string) (*openid4vp.RequestState, error)
}

// eudiVerifyExecutor drives an EUDI Wallet PID presentation as a flow step: it
// initiates a request (returning QR / deep-link data) and then polls until the
// wallet's response is verified, surfacing the verified person as the
// authenticated user.
type eudiVerifyExecutor struct {
	core.ExecutorInterface
	service eudiVerifierService
	logger  *log.Logger
}

var _ core.ExecutorInterface = (*eudiVerifyExecutor)(nil)

// newEUDIVerifyExecutor creates the EUDI verifier executor. service may be nil
// when the verifier is disabled; the executor then fails cleanly when reached.
func newEUDIVerifyExecutor(flowFactory core.FlowFactoryInterface, service eudiVerifierService) core.ExecutorInterface {
	base := flowFactory.CreateExecutor(
		ExecutorNameEUDIVerify, common.ExecutorTypeAuthentication, []common.Input{}, []common.Input{})
	return &eudiVerifyExecutor{
		ExecutorInterface: base,
		service:           service,
		logger:            log.GetLogger().With(log.String(log.LoggerKeyExecutorName, ExecutorNameEUDIVerify)),
	}
}

// Execute initiates the request on first entry and polls for the result on
// subsequent entries.
func (e *eudiVerifyExecutor) Execute(ctx *core.NodeContext) (*common.ExecutorResponse, error) {
	logger := e.logger.With(log.String(log.LoggerKeyExecutionID, ctx.ExecutionID))
	execResp := &common.ExecutorResponse{
		AdditionalData: make(map[string]string),
		RuntimeData:    make(map[string]string),
	}

	if e.service == nil {
		logger.Error("EUDI verifier service is not configured")
		execResp.Status = common.ExecFailure
		execResp.FailureReason = failureReasonEUDINotConfigured
		return execResp, nil
	}

	state := ctx.RuntimeData[eudiRuntimeKeyState]
	if state == "" {
		return e.initiate(ctx, execResp, logger)
	}
	return e.poll(ctx, state, execResp, logger)
}

// initiate starts a new request and returns the QR / deep-link data as a view.
func (e *eudiVerifyExecutor) initiate(
	ctx *core.NodeContext, execResp *common.ExecutorResponse, logger *log.Logger,
) (*common.ExecutorResponse, error) {
	init, err := e.service.Initiate(ctx.Context)
	if err != nil {
		logger.Error("Failed to initiate EUDI request", log.Error(err))
		execResp.Status = common.ExecFailure
		execResp.FailureReason = failureReasonEUDIInitiate
		return execResp, nil
	}

	execResp.RuntimeData[eudiRuntimeKeyState] = init.State
	setQRData(execResp, init.ClientID, init.RequestURI)
	execResp.Status = common.ExecUserInputRequired
	return execResp, nil
}

// setQRData populates the QR / deep-link payload for the client.
func setQRData(execResp *common.ExecutorResponse, clientID, requestURI string) {
	execResp.AdditionalData[eudiDataClientID] = clientID
	execResp.AdditionalData[eudiDataRequestURI] = requestURI
	execResp.AdditionalData[eudiDataWalletURI] = openid4vp.WalletAuthorizationURI(clientID, requestURI)
}

// poll checks the request result, completing, failing, or continuing to wait.
func (e *eudiVerifyExecutor) poll(
	ctx *core.NodeContext, state string, execResp *common.ExecutorResponse, logger *log.Logger,
) (*common.ExecutorResponse, error) {
	rs, err := e.service.Result(ctx.Context, state)
	if err != nil {
		logger.Debug("EUDI request state not found or expired", log.Error(err))
		execResp.Status = common.ExecFailure
		execResp.FailureReason = failureReasonEUDIExpired
		return execResp, nil
	}

	switch rs.Status {
	case openid4vp.StatusCompleted:
		e.setAuthenticatedUser(execResp, rs.Result)
		execResp.Status = common.ExecComplete
	case openid4vp.StatusFailed:
		logger.Debug("EUDI presentation verification failed", log.String("reason", rs.FailureReason))
		execResp.Status = common.ExecFailure
		execResp.FailureReason = rs.FailureReason
	default:
		// Still pending: keep the state, re-emit the QR data so the wait view
		// keeps rendering it across polls, and keep the client polling.
		execResp.RuntimeData[eudiRuntimeKeyState] = state
		setQRData(execResp, rs.ClientID, rs.RequestURI)
		execResp.Status = common.ExecUserInputRequired
	}
	return execResp, nil
}

// setAuthenticatedUser maps the verified presentation into the authenticated user.
func (e *eudiVerifyExecutor) setAuthenticatedUser(execResp *common.ExecutorResponse, vp *openid4vp.VerifiedPresentation) {
	if vp == nil {
		execResp.Status = common.ExecFailure
		execResp.FailureReason = failureReasonEUDIExpired
		return
	}
	attributes := make(map[string]interface{}, len(vp.Claims)+2)
	for k, v := range vp.Claims {
		attributes[k] = v
	}
	attributes["eudi_issuer"] = vp.Issuer
	attributes["eudi_vct"] = vp.VCT

	execResp.AuthenticatedUser = authncm.AuthenticatedUser{
		IsAuthenticated: true,
		UserID:          eudi.DeriveSubject(vp),
		Attributes:      attributes,
	}
}
