package internal

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

// MockEndpointConfig defines configuration for a single endpoint matcher.
// Used by SetupMockSCAService to handle single or multiple endpoints with different behaviors.
type MockEndpointConfig struct {
	Matcher      func(*http.Request) bool // Returns true if this config should handle the request
	StatusCode   int
	ResponseBody string
	OnRequest    func(*http.Request) // optional callback to verify/capture requests
}

// SetupMockSCAService creates a mock ISP service client with endpoint matchers.
// This helper provides maximum flexibility for testing scenarios requiring multiple
// endpoints with different behaviors.
//
// Matchers are evaluated in order, and the first matching config is used.
// If no matcher returns true, the request will receive a 404 Not Found response.
//
// Parameters:
//   - t: The testing context
//   - configs: Slice of endpoint configurations with matchers. First match wins.
//
// Returns:
//   - *isp.IdsecISPServiceClient: A mock ISP client pointing to the test server
//   - func(): Cleanup function to close the test server
func SetupMockSCAService(t *testing.T, configs []MockEndpointConfig) (*isp.IdsecISPServiceClient, func()) {
	t.Helper()
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		for _, config := range configs {
			if config.Matcher(r) {
				if config.OnRequest != nil {
					config.OnRequest(r)
				}
				w.WriteHeader(config.StatusCode)
				_, _ = w.Write([]byte(config.ResponseBody))
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error": "endpoint not found in mock configuration"}`))
	}))

	client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
	client.BaseURL = testServer.URL

	ispClient := &isp.IdsecISPServiceClient{
		IdsecClient: client,
	}

	return ispClient, testServer.Close
}

// InjectISPClient injects a mock ISP client into an IdsecISPBaseService using reflection.
// This is necessary because the client field is unexported.
func InjectISPClient(ispBase *services.IdsecISPBaseService, client *isp.IdsecISPServiceClient) {
	v := reflect.ValueOf(ispBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(client))
}

// getCallerFunctionName extracts a descriptive name from the calling test function.
func getCallerFunctionName() string {
	pc, _, _, ok := runtime.Caller(2)
	if !ok {
		return "Unknown"
	}
	funcName := runtime.FuncForPC(pc).Name()
	parts := strings.Split(funcName, ".")
	if len(parts) == 0 {
		return "Unknown"
	}
	testFuncName := parts[len(parts)-1]
	testFuncName = strings.TrimPrefix(testFuncName, "Test")
	testFuncName = strings.TrimSuffix(testFuncName, "_ErrorPropagation")
	if testFuncName == "" {
		return "Unknown"
	}
	return testFuncName
}

// TestServiceErrorPropagation tests that a service function properly propagates HTTP errors.
// It automatically tests common error codes: 400 Bad Request, 404 Not Found,
// 500 Internal Server Error.
//
// The callFunc parameter should call the service method and return any error.
// Sub-test names are auto-generated from the calling test function name.
// For example, calling from "TestListTargets_ErrorPropagation" produces sub-tests like:
// "ListTargets_BadRequest", "ListTargets_NotFound", "ListTargets_InternalServerError".
//
// Parameters:
//   - t: The testing context
//   - callFunc: A function that takes a mock ISP client, constructs the service,
//     calls the method, and returns the error
func TestServiceErrorPropagation(t *testing.T, callFunc func(*isp.IdsecISPServiceClient) error) {
	t.Helper()
	functionName := getCallerFunctionName()
	errorCases := []struct {
		name       string
		statusCode int
	}{
		{"BadRequest", http.StatusBadRequest},
		{"NotFound", http.StatusNotFound},
		{"InternalServerError", http.StatusInternalServerError},
	}

	for _, tc := range errorCases {
		testName := functionName + "_" + tc.name
		t.Run(testName, func(t *testing.T) {
			client, cleanup := SetupMockSCAService(t, []MockEndpointConfig{
				{
					Matcher:      func(r *http.Request) bool { return true },
					StatusCode:   tc.statusCode,
					ResponseBody: `{"error": "test error"}`,
				},
			})
			defer cleanup()
			err := callFunc(client)
			require.Error(t, err)
		})
	}
}
