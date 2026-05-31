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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/thunder-id/thunderid/internal/authn/eudi"
	"github.com/thunder-id/thunderid/internal/flow/common"
	"github.com/thunder-id/thunderid/internal/flow/core"
	"github.com/thunder-id/thunderid/tests/mocks/flow/coremock"
)

type fakeEUDIService struct {
	initiate func(ctx context.Context) (*eudi.Initiation, error)
	result   func(ctx context.Context, state string) (*eudi.RequestState, error)
}

func (f *fakeEUDIService) Initiate(ctx context.Context) (*eudi.Initiation, error) {
	return f.initiate(ctx)
}

func (f *fakeEUDIService) Result(ctx context.Context, state string) (*eudi.RequestState, error) {
	return f.result(ctx, state)
}

func newTestEUDIExecutor(t *testing.T, service eudiVerifierService) core.ExecutorInterface {
	t.Helper()
	factory := coremock.NewFlowFactoryInterfaceMock(t)
	base := coremock.NewExecutorInterfaceMock(t)
	factory.On("CreateExecutor", ExecutorNameEUDIVerify, common.ExecutorTypeAuthentication,
		[]common.Input{}, []common.Input{}).Return(base).Maybe()
	return newEUDIVerifyExecutor(factory, service)
}

func eudiNodeContext(runtime map[string]string) *core.NodeContext {
	if runtime == nil {
		runtime = map[string]string{}
	}
	return &core.NodeContext{Context: context.Background(), ExecutionID: "exec-1", RuntimeData: runtime}
}

func TestEUDIExecutorInitiates(t *testing.T) {
	svc := &fakeEUDIService{
		initiate: func(_ context.Context) (*eudi.Initiation, error) {
			return &eudi.Initiation{
				State:      "state-123",
				ClientID:   "x509_hash:abc",
				RequestURI: "https://verifier.example/openid4vp/request?state=state-123",
			}, nil
		},
	}
	exec := newTestEUDIExecutor(t, svc)

	resp, err := exec.Execute(eudiNodeContext(nil))
	require.NoError(t, err)
	assert.Equal(t, common.ExecUserInputRequired, resp.Status)
	assert.Equal(t, "state-123", resp.RuntimeData[eudiRuntimeKeyState])
	assert.Equal(t, "x509_hash:abc", resp.AdditionalData[eudiDataClientID])
	assert.Contains(t, resp.AdditionalData[eudiDataRequestURI], "state-123")
	assert.Contains(t, resp.AdditionalData[eudiDataWalletURI], "openid4vp://")
}

func TestEUDIExecutorInitiateFailure(t *testing.T) {
	svc := &fakeEUDIService{
		initiate: func(_ context.Context) (*eudi.Initiation, error) {
			return nil, errors.New("boom")
		},
	}
	exec := newTestEUDIExecutor(t, svc)

	resp, err := exec.Execute(eudiNodeContext(nil))
	require.NoError(t, err)
	assert.Equal(t, common.ExecFailure, resp.Status)
	assert.Equal(t, failureReasonEUDIInitiate, resp.FailureReason)
}

func TestEUDIExecutorPollPending(t *testing.T) {
	svc := &fakeEUDIService{
		result: func(_ context.Context, state string) (*eudi.RequestState, error) {
			return &eudi.RequestState{State: state, Status: eudi.StatusPending}, nil
		},
	}
	exec := newTestEUDIExecutor(t, svc)

	resp, err := exec.Execute(eudiNodeContext(map[string]string{eudiRuntimeKeyState: "state-123"}))
	require.NoError(t, err)
	assert.Equal(t, common.ExecUserInputRequired, resp.Status)
	assert.Equal(t, "state-123", resp.RuntimeData[eudiRuntimeKeyState])
}

func TestEUDIExecutorPollCompleted(t *testing.T) {
	svc := &fakeEUDIService{
		result: func(_ context.Context, state string) (*eudi.RequestState, error) {
			return &eudi.RequestState{
				State:  state,
				Status: eudi.StatusCompleted,
				Result: &eudi.VerifiedPID{
					Subject: "sub-1",
					Issuer:  "https://issuer.example",
					VCT:     eudi.PIDVCTSDJWT,
					Claims:  map[string]interface{}{"given_name": "Erika", "family_name": "Mustermann"},
				},
			}, nil
		},
	}
	exec := newTestEUDIExecutor(t, svc)

	resp, err := exec.Execute(eudiNodeContext(map[string]string{eudiRuntimeKeyState: "state-123"}))
	require.NoError(t, err)
	assert.Equal(t, common.ExecComplete, resp.Status)
	assert.True(t, resp.AuthenticatedUser.IsAuthenticated)
	assert.Equal(t, "sub-1", resp.AuthenticatedUser.UserID)
	assert.Equal(t, "Erika", resp.AuthenticatedUser.Attributes["given_name"])
	assert.Equal(t, "https://issuer.example", resp.AuthenticatedUser.Attributes["eudi_issuer"])
	assert.Equal(t, eudi.PIDVCTSDJWT, resp.AuthenticatedUser.Attributes["eudi_vct"])
}

func TestEUDIExecutorPollFailed(t *testing.T) {
	svc := &fakeEUDIService{
		result: func(_ context.Context, state string) (*eudi.RequestState, error) {
			return &eudi.RequestState{State: state, Status: eudi.StatusFailed, FailureReason: "nonce mismatch"}, nil
		},
	}
	exec := newTestEUDIExecutor(t, svc)

	resp, err := exec.Execute(eudiNodeContext(map[string]string{eudiRuntimeKeyState: "state-123"}))
	require.NoError(t, err)
	assert.Equal(t, common.ExecFailure, resp.Status)
	assert.Equal(t, "nonce mismatch", resp.FailureReason)
}

func TestEUDIExecutorPollExpired(t *testing.T) {
	svc := &fakeEUDIService{
		result: func(_ context.Context, _ string) (*eudi.RequestState, error) {
			return nil, eudi.ErrUnknownState
		},
	}
	exec := newTestEUDIExecutor(t, svc)

	resp, err := exec.Execute(eudiNodeContext(map[string]string{eudiRuntimeKeyState: "gone"}))
	require.NoError(t, err)
	assert.Equal(t, common.ExecFailure, resp.Status)
	assert.Equal(t, failureReasonEUDIExpired, resp.FailureReason)
}

func TestEUDIExecutorNotConfigured(t *testing.T) {
	exec := newTestEUDIExecutor(t, nil)
	resp, err := exec.Execute(eudiNodeContext(nil))
	require.NoError(t, err)
	assert.Equal(t, common.ExecFailure, resp.Status)
	assert.Equal(t, failureReasonEUDINotConfigured, resp.FailureReason)
}
