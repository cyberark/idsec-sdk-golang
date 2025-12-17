package internal

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
)

// MockEndpointConfig defines configuration for a single endpoint matcher.
// Used by SetupMockCCEService to handle single or multiple endpoints with different behaviors.
type MockEndpointConfig struct {
	Matcher      func(*http.Request) bool // Returns true if this config should handle the request
	StatusCode   int
	ResponseBody string
	OnRequest    func(*http.Request) // optional callback to verify/capture requests
}

// SetupMockCCEService creates a mock ISP service client with endpoint matchers.
// This helper provides maximum flexibility for testing scenarios requiring multiple endpoints with different behaviors.
//
// The matcher-based approach allows you to:
//   - Handle multiple HTTP endpoints with different responses
//   - Capture request bodies for assertions
//   - Match requests based on method, path, headers, or any other criteria
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
//
// Example:
//
//	var capturedBody map[string]interface{}
//	client, cleanup := SetupMockCCEService(t, []MockEndpointConfig{
//	    {
//	        Matcher: func(r *http.Request) bool {
//	            return r.Method == "POST" && r.URL.Path == "/api/resource"
//	        },
//	        StatusCode: http.StatusCreated,
//	        ResponseBody: `{"id": "new-123"}`,
//	        OnRequest: func(r *http.Request) {
//	            json.NewDecoder(r.Body).Decode(&capturedBody)
//	        },
//	    },
//	    {
//	        Matcher: func(r *http.Request) bool {
//	            return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/resource/")
//	        },
//	        StatusCode: http.StatusOK,
//	        ResponseBody: `{"id": "new-123", "status": "active"}`,
//	    },
//	})
//	defer cleanup()
func SetupMockCCEService(t *testing.T, configs []MockEndpointConfig) (*isp.IdsecISPServiceClient, func()) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Find the first matching config
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

		// No matcher found - return 404
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error": "endpoint not found in mock configuration"}`))
	}))

	// Create IdsecClient with test server URL
	client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
	client.BaseURL = testServer.URL

	// Wrap in ISP service client
	ispClient := &isp.IdsecISPServiceClient{
		IdsecClient: client,
	}

	cleanup := func() {
		testServer.Close()
	}

	return ispClient, cleanup
}

// getCallerFunctionName extracts a descriptive name from the calling test function.
// It uses runtime.Caller to get the test function name and parses it to extract
// the meaningful part (e.g., "TestOrganization_ErrorPropagation" -> "Organization").
func getCallerFunctionName() string {
	// Get the caller's function name (skip 2 frames: this function and TestServiceErrorPropagation)
	pc, _, _, ok := runtime.Caller(2)
	if !ok {
		return "Unknown"
	}

	// Get the full function name
	funcName := runtime.FuncForPC(pc).Name()

	// Extract just the function name from the full path
	// e.g., "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/aws.TestOrganization_ErrorPropagation"
	parts := strings.Split(funcName, ".")
	if len(parts) == 0 {
		return "Unknown"
	}

	// Get the last part (e.g., "TestOrganization_ErrorPropagation")
	testFuncName := parts[len(parts)-1]

	// Remove "Test" prefix if present
	testFuncName = strings.TrimPrefix(testFuncName, "Test")

	// Remove "_ErrorPropagation" suffix if present
	testFuncName = strings.TrimSuffix(testFuncName, "_ErrorPropagation")

	if testFuncName == "" {
		return "Unknown"
	}

	return testFuncName
}

// TestServiceErrorPropagation tests that a service function properly propagates HTTP errors.
// It automatically tests common error codes: 400 Bad Request, 404 Not Found, 500 Internal Server Error.
// The callFunc parameter should call the service method and return any error.
//
// This helper ensures consistent error handling across all CCE service methods.
// Sub-test names are automatically generated based on the calling test function name.
// For example, calling from "TestOrganization_ErrorPropagation" creates sub-tests like:
// "Organization_BadRequest", "Organization_NotFound", "Organization_InternalServerError".
//
// Parameters:
//   - t: The testing context
//   - callFunc: A function that takes a mock ISP client, constructs the service, calls the method, and returns the error
//
// Example:
//
//	TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
//	    service := &IdsecCCEAWSService{client: client}
//	    _, err := service.Organization(&awsmodels.IdsecCCEAWSGetOrganization{ID: "org-123"})
//	    return err
//	})
func TestServiceErrorPropagation(t *testing.T, callFunc func(*isp.IdsecISPServiceClient) error) {
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
			client, cleanup := SetupMockCCEService(t, []MockEndpointConfig{
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
