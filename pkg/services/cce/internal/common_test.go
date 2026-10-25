package internal

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

func TestHandleNon2xxResponse_ReadableMessage(t *testing.T) {
	tests := []struct {
		name             string
		statusCode       int
		body             string
		expectedError    string
		expectedAppCode  string
		expectedMessage  string
		unexpectedSubstr string
	}{
		{
			name:       "uses description with status and app error code",
			statusCode: http.StatusNotFound,
			body: `{"app_error_code":"NOT_FOUND","attributes":null,"code":"404",` +
				`"description":"Workspace with onboarding_id abc not found.","message":"Not Found"}`,
			expectedError:    "failed to get Entra tenant details: Workspace with onboarding_id abc not found. (HTTP 404 Not Found, NOT_FOUND)",
			expectedAppCode:  "NOT_FOUND",
			expectedMessage:  "Workspace with onboarding_id abc not found.",
			unexpectedSubstr: "attributes",
		},
		{
			name:            "omits app error code when absent",
			statusCode:      http.StatusBadRequest,
			body:            `{"code":"400","description":"Cannot add the service while another service is being deployed or removed.","message":"Bad Request"}`,
			expectedError:   "failed to get Entra tenant details: Cannot add the service while another service is being deployed or removed. (HTTP 400 Bad Request)",
			expectedMessage: "Cannot add the service while another service is being deployed or removed.",
		},
		{
			name:            "falls back to message when description is missing",
			statusCode:      http.StatusNotImplemented,
			body:            `{"app_error_code":"NOT_IMPLEMENTED","description":null,"message":"This feature is currently not available."}`,
			expectedError:   "failed to get Entra tenant details: This feature is currently not available. (HTTP 501 Not Implemented, NOT_IMPLEMENTED)",
			expectedAppCode: "NOT_IMPLEMENTED",
			expectedMessage: "This feature is currently not available.",
		},
		{
			name:            "falls back to raw body when it is not JSON",
			statusCode:      http.StatusBadGateway,
			body:            "upstream connect error\n",
			expectedError:   "failed to get Entra tenant details: upstream connect error (HTTP 502 Bad Gateway)",
			expectedMessage: "upstream connect error",
		},
		{
			name:            "falls back to raw body when JSON has no message fields",
			statusCode:      http.StatusConflict,
			body:            `{"code":"409"}`,
			expectedError:   `failed to get Entra tenant details: {"code":"409"} (HTTP 409 Conflict)`,
			expectedMessage: `{"code":"409"}`,
		},
		{
			name:            "renders non-string description as JSON",
			statusCode:      http.StatusUnprocessableEntity,
			body:            `{"description":["field required"],"message":"Unprocessable Entity"}`,
			expectedError:   `failed to get Entra tenant details: ["field required"] (HTTP 422 Unprocessable Entity)`,
			expectedMessage: `["field required"]`,
		},
		{
			name:          "handles empty body",
			statusCode:    http.StatusInternalServerError,
			body:          "",
			expectedError: "failed to get Entra tenant details (HTTP 500 Internal Server Error)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := io.NopCloser(strings.NewReader(tt.body))

			err := HandleNon2xxResponse(common.GlobalLogger, tt.statusCode, body, "failed to get Entra tenant details")

			require.EqualError(t, err, tt.expectedError)
			apiErr, ok := AsAPIError(err)
			require.True(t, ok)
			require.Equal(t, tt.statusCode, apiErr.StatusCode)
			require.Equal(t, tt.expectedAppCode, apiErr.AppErrorCode)
			require.Equal(t, tt.expectedMessage, apiErr.Message)
			require.Equal(t, tt.body, apiErr.Body)
			if tt.unexpectedSubstr != "" {
				require.NotContains(t, err.Error(), tt.unexpectedSubstr)
			}
		})
	}
}

func TestAsAPIError_Wrapped(t *testing.T) {
	apiErr := NewAPIError(http.StatusBadRequest, []byte(`{"app_error_code":"SCAN_IN_PROGRESS","description":"scan is in progress"}`), "failed to add account")
	wrapped := fmt.Errorf("failed to retrieve account: %w", apiErr)

	got, ok := AsAPIError(wrapped)

	require.True(t, ok)
	require.Same(t, apiErr, got)
	require.Equal(t, "SCAN_IN_PROGRESS", got.AppErrorCode)
}

func TestAsAPIError_NonAPIError(t *testing.T) {
	got, ok := AsAPIError(fmt.Errorf("connection reset by peer"))

	require.False(t, ok)
	require.Nil(t, got)
}
