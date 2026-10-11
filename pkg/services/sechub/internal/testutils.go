package internal

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"unsafe"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

// MockEndpointConfig defines configuration for a single endpoint matcher.
// Used by SetupMockSecHubService to handle single or multiple endpoints with different behaviors.
type MockEndpointConfig struct {
	Matcher      func(*http.Request) bool // Returns true if this config should handle the request
	StatusCode   int
	ResponseBody string
	OnRequest    func(*http.Request) // optional callback to verify/capture requests
}

// SetupMockSecHubService creates a mock ISP service client with endpoint matchers.
// Matchers are evaluated in order; the first matching config is used.
// If no matcher returns true, the request receives a 404 Not Found response.
//
// Returns:
//   - *isp.IdsecISPServiceClient: A mock ISP client pointing to the test server
//   - func(): Cleanup function to close the test server
func SetupMockSecHubService(t *testing.T, configs []MockEndpointConfig) (*isp.IdsecISPServiceClient, func()) {
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
