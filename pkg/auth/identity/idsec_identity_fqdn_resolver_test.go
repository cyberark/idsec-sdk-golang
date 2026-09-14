package identity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common/identity"
)

// discoveryClient returns an IdsecClient pre-configured to talk to the given test server.
// NewSimpleIdsecClient preserves http:// prefixes, so the test server's plain-HTTP address
// is used directly without TLS.
func discoveryClient(srv *httptest.Server) *common.IdsecClient {
	client := common.NewSimpleIdsecClient(srv.URL)
	client.SetHeaders(map[string]string{"Content-Type": "application/json"})
	return client
}

// writeEndpointJSON writes a 200 TenantEndpointResponse body.
func writeEndpointJSON(w http.ResponseWriter, endpoint string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(identity.TenantEndpointResponse{Endpoint: endpoint})
}

func TestResolveFqdnWithClient(t *testing.T) {
	t.Parallel()

	const wantFqdn = "https://mytenant.example.com"

	tests := []struct {
		name          string
		handler       http.HandlerFunc
		expectedFqdn  string
		expectedError bool
	}{
		{
			name: "success_on_first_attempt",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeEndpointJSON(w, wantFqdn)
			},
			expectedFqdn:  wantFqdn,
			expectedError: false,
		},
		{
			name: "success_after_one_transient_503",
			handler: func() http.HandlerFunc {
				var calls atomic.Int32
				return func(w http.ResponseWriter, r *http.Request) {
					if calls.Add(1) < 2 {
						http.Error(w, "service unavailable", http.StatusServiceUnavailable)
						return
					}
					writeEndpointJSON(w, wantFqdn)
				}
			}(),
			expectedFqdn:  wantFqdn,
			expectedError: false,
		},
		{
			name: "success_after_two_transient_503s",
			handler: func() http.HandlerFunc {
				var calls atomic.Int32
				return func(w http.ResponseWriter, r *http.Request) {
					if calls.Add(1) < 3 {
						http.Error(w, "service unavailable", http.StatusServiceUnavailable)
						return
					}
					writeEndpointJSON(w, wantFqdn)
				}
			}(),
			expectedFqdn:  wantFqdn,
			expectedError: false,
		},
		{
			name: "error_all_attempts_fail_with_504",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
			},
			expectedFqdn:  "",
			expectedError: true,
		},
		{
			name: "error_invalid_json_in_200_response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("not-json{{{"))
			},
			expectedFqdn:  "",
			expectedError: true,
		},
		{
			name: "error_404_not_found",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.NotFound(w, r)
			},
			expectedFqdn:  "",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			fqdn, err := resolveFqdnWithClient("mytenant", discoveryClient(srv))

			if tt.expectedError {
				if err == nil {
					t.Errorf("expected error, got nil (fqdn=%q)", fqdn)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if fqdn != tt.expectedFqdn {
				t.Errorf("expected fqdn %q, got %q", tt.expectedFqdn, fqdn)
			}
		})
	}
}
