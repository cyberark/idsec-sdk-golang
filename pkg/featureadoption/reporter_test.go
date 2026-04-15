// Copyright (c) CyberArk.
// SPDX-License-Identifier: Apache-2.0

package featureadoption

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "github.com/cyberark/idsec-sdk-golang/pkg"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
)

// setTestBaseURL sets FAS_BASE_URL for the duration of the test. Restore with the returned cleanup func.
func setTestBaseURL(t *testing.T, url string) func() {
	t.Helper()
	orig := os.Getenv(fasBaseURLEnvVar)
	_ = os.Setenv(fasBaseURLEnvVar, url)
	return func() {
		if orig != "" {
			_ = os.Setenv(fasBaseURLEnvVar, orig)
		} else {
			_ = os.Unsetenv(fasBaseURLEnvVar)
		}
	}
}

func TestReport_Success(t *testing.T) {
	var receivedBody featureAdoptionRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/feature-adoption", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "Bearer my-token", r.Header.Get("Authorization"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		err = json.Unmarshal(body, &receivedBody)
		require.NoError(t, err)

		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	defer setTestBaseURL(t, server.URL)()

	ctx := context.Background()
	tags := map[string]string{"idsec_tool": "test", "os_name": "linux"}
	msg, err := report(ctx, "my-token", "IDSGO.test.usage", tags, nil)

	require.NoError(t, err)
	assert.Equal(t, "FAS report sent successfully", msg)
	assert.Equal(t, "IDSGO.test.usage", receivedBody.MetricKey)
	for k, v := range tags {
		assert.Equal(t, v, receivedBody.Tags[k], "tag %q", k)
	}
	assert.Equal(t, 1, receivedBody.NumberOfEvents)
	assert.Equal(t, TriggeredByBE, receivedBody.TriggeredBy)
	assert.Equal(t, int64(0), receivedBody.EventTime)
}

func TestReport_WithOpts(t *testing.T) {
	var receivedBody featureAdoptionRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	defer setTestBaseURL(t, server.URL)()

	ctx := context.Background()
	opts := &ReportOpts{
		CustomData: map[string]interface{}{"correlation_id": "abc-123"},
	}
	msg, err := report(ctx, "token", "metric.key", map[string]string{"k": "v"}, opts)

	require.NoError(t, err)
	assert.Equal(t, "FAS report sent successfully", msg)
	assert.Equal(t, map[string]interface{}{"correlation_id": "abc-123"}, receivedBody.CustomData)
}

func TestReport_BaseURLTrailingSlash(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/feature-adoption", r.URL.Path)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	defer setTestBaseURL(t, server.URL)()

	_, err := report(context.Background(), "t", "m", nil, nil)
	require.NoError(t, err)
}

func TestReport_ValidationErrors(t *testing.T) {
	t.Run("empty metricKey", func(t *testing.T) {
		msg, err := report(context.Background(), "token", "", nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "metricKey is required")
		assert.Equal(t, msg, "")
	})
}

func TestReport_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	defer setTestBaseURL(t, server.URL)()

	msg, err := report(context.Background(), "token", "m", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
	assert.Contains(t, msg, "")
}

func TestAuthISPOrPVWA(t *testing.T) {
	t.Run("nil_api_returns_nil", func(t *testing.T) {
		result := authISPOrPVWA(nil)
		assert.Nil(t, result)
	})

	t.Run("api_with_isp_auth_returns_isp", func(t *testing.T) {
		ispAuth := auth.NewIdsecISPAuth(false)
		apiInstance, err := api.NewIdsecAPI([]auth.IdsecAuth{ispAuth}, nil)
		require.NoError(t, err)
		result := authISPOrPVWA(apiInstance)
		require.NotNil(t, result)
		assert.Equal(t, "isp", result.AuthenticatorName())
	})

	t.Run("api_with_pvwa_auth_returns_pvwa", func(t *testing.T) {
		pvwaAuth := auth.NewIdsecPVWAAuth(false)
		apiInstance, err := api.NewIdsecAPI([]auth.IdsecAuth{pvwaAuth}, nil)
		require.NoError(t, err)
		result := authISPOrPVWA(apiInstance)
		require.NotNil(t, result)
		assert.Equal(t, "pvwa", result.AuthenticatorName())
	})

	t.Run("api_with_both_returns_isp_first", func(t *testing.T) {
		ispAuth := auth.NewIdsecISPAuth(false)
		pvwaAuth := auth.NewIdsecPVWAAuth(false)
		apiInstance, err := api.NewIdsecAPI([]auth.IdsecAuth{ispAuth, pvwaAuth}, nil)
		require.NoError(t, err)
		result := authISPOrPVWA(apiInstance)
		require.NotNil(t, result)
		assert.Equal(t, "isp", result.AuthenticatorName())
	})

	t.Run("api_with_neither_returns_nil", func(t *testing.T) {
		apiInstance, err := api.NewIdsecAPI(nil, nil)
		require.NoError(t, err)
		result := authISPOrPVWA(apiInstance)
		assert.Nil(t, result)
	})
}

func TestReport_NoToken(t *testing.T) {
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	defer setTestBaseURL(t, server.URL)()

	msg, err := report(context.Background(), "", "m", nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "FAS report sent successfully", msg)
	assert.Empty(t, authHeader)
}
