package access

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	accessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/access/models"
)

func httpResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func newServiceWithGet(
	fn func(ctx context.Context, path string, params map[string]string) (*http.Response, error),
) *IdsecSIAAccessService {
	return &IdsecSIAAccessService{
		IdsecBaseService: &services.IdsecBaseService{
			Logger: common.GlobalLogger,
		},
		doGet: fn,
	}
}

func TestListConnectors_Success(t *testing.T) {
	okJSON := `{
	  "connectors": [
	    {"id":"c-1","name":"alpha"},
	    {"id":"c-2","name":"beta"}
	  ],
	  "total": 2
	}`

	var gotPath string
	svc := newServiceWithGet(func(ctx context.Context, path string, params map[string]string) (*http.Response, error) {
		gotPath = path
		require.Nil(t, params)
		return httpResp(http.StatusOK, okJSON), nil
	})

	got, err := svc.ListConnectors()
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, connectorsURL, gotPath)
}

func TestListConnectors_TransportError(t *testing.T) {
	svc := newServiceWithGet(func(ctx context.Context, path string, params map[string]string) (*http.Response, error) {
		return nil, fmt.Errorf("network down")
	})

	got, err := svc.ListConnectors()
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "network down")
}

func TestListConnectors_Non200Status(t *testing.T) {
	svc := newServiceWithGet(func(ctx context.Context, path string, params map[string]string) (*http.Response, error) {
		return httpResp(http.StatusInternalServerError, `{"error":"boom"}`), nil
	})

	got, err := svc.ListConnectors()
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "failed to list connectors")
}

func TestListConnectors_BadJSON(t *testing.T) {
	svc := newServiceWithGet(func(ctx context.Context, path string, params map[string]string) (*http.Response, error) {
		return httpResp(http.StatusOK, `not-json`), nil
	})

	got, err := svc.ListConnectors()
	require.Error(t, err)
	require.Nil(t, got)
}

func TestListConnectors_DecodeMismatch(t *testing.T) {
	svc := newServiceWithGet(func(ctx context.Context, path string, params map[string]string) (*http.Response, error) {
		return httpResp(http.StatusOK, `{"connectors":"not-a-list"}`), nil
	})

	got, err := svc.ListConnectors()
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Zero(t, got.Count)
	require.Len(t, got.Items, 0)
}

// newServiceWithHTTPTest creates an IdsecSIAAccessService wired to the given httptest server URL.
// It uses reflection to inject the ISP client because the client field is unexported.
func newServiceWithHTTPTest(t *testing.T, serverURL string) *IdsecSIAAccessService {
	t.Helper()
	client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
	client.BaseURL = serverURL
	ispClient := &isp.IdsecISPServiceClient{IdsecClient: client}
	ispBase := &services.IdsecISPBaseService{}
	v := reflect.ValueOf(ispBase).Elem()
	f := v.FieldByName("client")
	f = reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
	f.Set(reflect.ValueOf(ispClient))
	return &IdsecSIAAccessService{
		IdsecBaseService:    &services.IdsecBaseService{Logger: common.GlobalLogger},
		IdsecISPBaseService: ispBase,
	}
}

func TestRotateRelay(t *testing.T) {
	relayID := "relay-test-123"

	tests := []struct {
		name             string
		relayID          string
		serverStatus     int
		serverBody       string
		closeServer      bool
		expectedError    bool
		expectedErrorMsg string
		expectedPath     string
	}{
		{
			name:          "success",
			relayID:       relayID,
			serverStatus:  http.StatusOK,
			serverBody:    `{}`,
			expectedError: false,
			expectedPath:  fmt.Sprintf(httpsRelayRotateURL, relayID),
		},
		{
			name:             "empty_id",
			relayID:          "",
			expectedError:    true,
			expectedErrorMsg: "HTTPS relay ID is required",
		},
		{
			name:             "non_200_status",
			relayID:          relayID,
			serverStatus:     http.StatusInternalServerError,
			serverBody:       `{"error":"internal error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to rotate HTTPS relay certificate",
		},
		{
			name:             "transport_error",
			relayID:          relayID,
			closeServer:      true,
			expectedError:    true,
			expectedErrorMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.relayID == "" {
				svc := newServiceWithHTTPTest(t, "http://unused")
				err := svc.RotateRelay(&accessmodels.IdsecSIARotateHTTPSRelay{HTTPSRelayID: tt.relayID})
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErrorMsg)
				return
			}

			var gotPath string
			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)
				_, _ = w.Write([]byte(tt.serverBody))
			}))

			if tt.closeServer {
				testServer.Close()
			} else {
				defer testServer.Close()
			}

			svc := newServiceWithHTTPTest(t, testServer.URL)
			err := svc.RotateRelay(&accessmodels.IdsecSIARotateHTTPSRelay{HTTPSRelayID: tt.relayID})

			if tt.expectedError {
				require.Error(t, err)
				if tt.expectedErrorMsg != "" {
					require.Contains(t, err.Error(), tt.expectedErrorMsg)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedPath, gotPath)
		})
	}
}

// ---------------------------------------------------------------------------
// ListRelays
// ---------------------------------------------------------------------------

func TestListRelays_Success(t *testing.T) {
	body := `{
		"items": [
			{"id":"relay-1","host_name":"host1","status":"ACTIVE","status_code":1},
			{"id":"relay-2","host_name":"host2","status":"INACTIVE","status_code":0}
		],
		"continuationToken": ""
	}`
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	svc := newServiceWithHTTPTest(t, srv.URL)
	pages, err := svc.ListRelays()
	require.NoError(t, err)

	var all []*accessmodels.IdsecSIAHTTPSRelay
	for page := range pages {
		all = append(all, page.Items...)
	}
	require.Len(t, all, 2)
	require.Equal(t, "relay-1", all[0].HTTPSRelayID)
	require.Equal(t, "relay-2", all[1].HTTPSRelayID)
	require.Equal(t, httpsRelaysURL, gotPath)
}

func TestListRelays_IDRenaming(t *testing.T) {
	// The API returns "id" at the item level; the SDK must map it to "https_relay_id".
	body := `{"items":[{"id":"relay-abc","status":"ACTIVE","status_code":1}],"continuationToken":""}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	svc := newServiceWithHTTPTest(t, srv.URL)
	pages, err := svc.ListRelays()
	require.NoError(t, err)

	var all []*accessmodels.IdsecSIAHTTPSRelay
	for page := range pages {
		all = append(all, page.Items...)
	}
	require.Len(t, all, 1)
	require.Equal(t, "relay-abc", all[0].HTTPSRelayID)
}

func TestListRelays_Pagination(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Query().Get("continuationToken") == "" {
			_, _ = w.Write([]byte(`{"items":[{"id":"relay-1"}],"continuationToken":"tok-2"}`))
		} else {
			_, _ = w.Write([]byte(`{"items":[{"id":"relay-2"}],"continuationToken":""}`))
		}
	}))
	defer srv.Close()

	svc := newServiceWithHTTPTest(t, srv.URL)
	pages, err := svc.ListRelays()
	require.NoError(t, err)

	var all []*accessmodels.IdsecSIAHTTPSRelay
	for page := range pages {
		all = append(all, page.Items...)
	}
	require.Len(t, all, 2)
	require.Equal(t, 2, callCount, "expected two pages to be fetched")
	require.Equal(t, "relay-1", all[0].HTTPSRelayID)
	require.Equal(t, "relay-2", all[1].HTTPSRelayID)
}

func TestListRelays_Non200Status(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer srv.Close()

	svc := newServiceWithHTTPTest(t, srv.URL)
	pages, err := svc.ListRelays()
	require.NoError(t, err)

	// The channel should be closed without delivering any items.
	var all []*accessmodels.IdsecSIAHTTPSRelay
	for page := range pages {
		all = append(all, page.Items...)
	}
	require.Empty(t, all)
}

func TestListRelays_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":[],"continuationToken":""}`))
	}))
	defer srv.Close()

	svc := newServiceWithHTTPTest(t, srv.URL)
	pages, err := svc.ListRelays()
	require.NoError(t, err)

	var all []*accessmodels.IdsecSIAHTTPSRelay
	for page := range pages {
		all = append(all, page.Items...)
	}
	require.Empty(t, all)
}

// ---------------------------------------------------------------------------
// GetRelay
// ---------------------------------------------------------------------------

func TestGetRelay_EmptyID(t *testing.T) {
	svc := newServiceWithHTTPTest(t, "http://unused")
	got, err := svc.GetRelay(&accessmodels.IdsecSIAGetHTTPSRelay{})
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "HTTPS relay ID is required")
}

func TestGetRelay_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":[{"id":"relay-xyz","status":"ACTIVE","status_code":1}],"continuationToken":""}`))
	}))
	defer srv.Close()

	svc := newServiceWithHTTPTest(t, srv.URL)
	got, err := svc.GetRelay(&accessmodels.IdsecSIAGetHTTPSRelay{HTTPSRelayID: "relay-xyz"})
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "relay-xyz", got.HTTPSRelayID)
}

func TestGetRelay_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":[{"id":"relay-other","status":"ACTIVE","status_code":1}],"continuationToken":""}`))
	}))
	defer srv.Close()

	svc := newServiceWithHTTPTest(t, srv.URL)
	got, err := svc.GetRelay(&accessmodels.IdsecSIAGetHTTPSRelay{HTTPSRelayID: "relay-xyz"})
	require.Error(t, err)
	require.Nil(t, got)
	require.Contains(t, err.Error(), "relay-xyz")
	require.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// DeleteRelay
// ---------------------------------------------------------------------------

func TestDeleteRelay(t *testing.T) {
	relayID := "relay-del-1"

	tests := []struct {
		name             string
		relayID          string
		serverStatus     int
		serverBody       string
		closeServer      bool
		expectedError    bool
		expectedErrorMsg string
		expectedPath     string
	}{
		{
			name:          "success",
			relayID:       relayID,
			serverStatus:  http.StatusNoContent,
			serverBody:    "",
			expectedError: false,
			expectedPath:  fmt.Sprintf(httpsRelayURL, relayID),
		},
		{
			name:             "empty_id",
			relayID:          "",
			expectedError:    true,
			expectedErrorMsg: "HTTPS relay ID is required",
		},
		{
			name:             "non_204_status",
			relayID:          relayID,
			serverStatus:     http.StatusConflict,
			serverBody:       `{"error":"conflict"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to delete HTTPS relay",
		},
		{
			name:             "transport_error",
			relayID:          relayID,
			closeServer:      true,
			expectedError:    true,
			expectedErrorMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.relayID == "" {
				svc := newServiceWithHTTPTest(t, "http://unused")
				err := svc.DeleteRelay(&accessmodels.IdsecSIADeleteHTTPSRelay{HTTPSRelayID: tt.relayID})
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErrorMsg)
				return
			}

			var gotPath string
			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.WriteHeader(tt.serverStatus)
				_, _ = w.Write([]byte(tt.serverBody))
			}))

			if tt.closeServer {
				testServer.Close()
			} else {
				defer testServer.Close()
			}

			svc := newServiceWithHTTPTest(t, testServer.URL)
			err := svc.DeleteRelay(&accessmodels.IdsecSIADeleteHTTPSRelay{HTTPSRelayID: tt.relayID})

			if tt.expectedError {
				require.Error(t, err)
				if tt.expectedErrorMsg != "" {
					require.Contains(t, err.Error(), tt.expectedErrorMsg)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedPath, gotPath)
		})
	}
}

// ---------------------------------------------------------------------------
// UpgradeRelay
// ---------------------------------------------------------------------------

func TestUpgradeRelay(t *testing.T) {
	relayID := "relay-upg-1"

	tests := []struct {
		name             string
		relayID          string
		serverStatus     int
		serverBody       string
		closeServer      bool
		expectedError    bool
		expectedErrorMsg string
		expectedPath     string
	}{
		{
			name:          "success",
			relayID:       relayID,
			serverStatus:  http.StatusOK,
			serverBody:    `{}`,
			expectedError: false,
			expectedPath:  fmt.Sprintf(httpsRelayUpgradeURL, relayID),
		},
		{
			name:             "empty_id",
			relayID:          "",
			expectedError:    true,
			expectedErrorMsg: "HTTPS relay ID is required",
		},
		{
			name:             "non_200_status",
			relayID:          relayID,
			serverStatus:     http.StatusBadRequest,
			serverBody:       `{"error":"bad request"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to upgrade HTTPS relay",
		},
		{
			name:             "transport_error",
			relayID:          relayID,
			closeServer:      true,
			expectedError:    true,
			expectedErrorMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.relayID == "" {
				svc := newServiceWithHTTPTest(t, "http://unused")
				err := svc.UpgradeRelay(&accessmodels.IdsecSIAUpgradeHTTPSRelay{HTTPSRelayID: tt.relayID})
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErrorMsg)
				return
			}

			var gotPath string
			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.WriteHeader(tt.serverStatus)
				_, _ = w.Write([]byte(tt.serverBody))
			}))

			if tt.closeServer {
				testServer.Close()
			} else {
				defer testServer.Close()
			}

			svc := newServiceWithHTTPTest(t, testServer.URL)
			err := svc.UpgradeRelay(&accessmodels.IdsecSIAUpgradeHTTPSRelay{HTTPSRelayID: tt.relayID})

			if tt.expectedError {
				require.Error(t, err)
				if tt.expectedErrorMsg != "" {
					require.Contains(t, err.Error(), tt.expectedErrorMsg)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedPath, gotPath)
		})
	}
}

func TestRotateConnector(t *testing.T) {
	connectorID := "connector-test-456"

	tests := []struct {
		name             string
		connectorID      string
		serverStatus     int
		serverBody       string
		closeServer      bool
		expectedError    bool
		expectedErrorMsg string
		expectedPath     string
	}{
		{
			name:          "success",
			connectorID:   connectorID,
			serverStatus:  http.StatusCreated,
			serverBody:    `{}`,
			expectedError: false,
			expectedPath:  fmt.Sprintf(connectorRotateURL, connectorID),
		},
		{
			name:             "empty_id",
			connectorID:      "",
			expectedError:    true,
			expectedErrorMsg: "connector ID is required",
		},
		{
			name:             "non_201_status",
			connectorID:      connectorID,
			serverStatus:     http.StatusForbidden,
			serverBody:       `{"error":"forbidden"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to rotate connector certificate",
		},
		{
			name:             "transport_error",
			connectorID:      connectorID,
			closeServer:      true,
			expectedError:    true,
			expectedErrorMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.connectorID == "" {
				svc := newServiceWithHTTPTest(t, "http://unused")
				err := svc.RotateConnector(&accessmodels.IdsecSIARotateConnector{ConnectorID: tt.connectorID})
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErrorMsg)
				return
			}

			var gotPath string
			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)
				_, _ = w.Write([]byte(tt.serverBody))
			}))

			if tt.closeServer {
				testServer.Close()
			} else {
				defer testServer.Close()
			}

			svc := newServiceWithHTTPTest(t, testServer.URL)
			err := svc.RotateConnector(&accessmodels.IdsecSIARotateConnector{ConnectorID: tt.connectorID})

			if tt.expectedError {
				require.Error(t, err)
				if tt.expectedErrorMsg != "" {
					require.Contains(t, err.Error(), tt.expectedErrorMsg)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedPath, gotPath)
		})
	}
}

// ---------------------------------------------------------------------------
// DeleteConnector
// ---------------------------------------------------------------------------

func TestDeleteConnector(t *testing.T) {
	connectorID := "conn-del-1"

	tests := []struct {
		name             string
		connectorID      string
		forceDelete      bool
		serverStatus     int
		serverBody       string
		closeServer      bool
		expectedError    bool
		expectedErrorMsg string
		expectedPath     string
		expectedQuery    string
	}{
		{
			name:          "success",
			connectorID:   connectorID,
			serverStatus:  http.StatusOK,
			serverBody:    `{}`,
			expectedError: false,
			expectedPath:  fmt.Sprintf(connectorURL, connectorID),
		},
		{
			name:          "success_force_delete",
			connectorID:   connectorID,
			forceDelete:   true,
			serverStatus:  http.StatusOK,
			serverBody:    `{}`,
			expectedError: false,
			expectedPath:  fmt.Sprintf(connectorURL, connectorID),
			expectedQuery: "force_delete=true",
		},
		{
			name:             "non_200_status",
			connectorID:      connectorID,
			serverStatus:     http.StatusConflict,
			serverBody:       `{"error":"conflict"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to delete connector",
		},
		{
			name:             "transport_error",
			connectorID:      connectorID,
			closeServer:      true,
			expectedError:    true,
			expectedErrorMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var gotPath, gotQuery string
			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotQuery = r.URL.RawQuery
				w.WriteHeader(tt.serverStatus)
				_, _ = w.Write([]byte(tt.serverBody))
			}))

			if tt.closeServer {
				testServer.Close()
			} else {
				defer testServer.Close()
			}

			svc := newServiceWithHTTPTest(t, testServer.URL)
			err := svc.DeleteConnector(&accessmodels.IdsecSIADeleteConnector{
				ConnectorID: tt.connectorID,
				ForceDelete: tt.forceDelete,
			})

			if tt.expectedError {
				require.Error(t, err)
				if tt.expectedErrorMsg != "" {
					require.Contains(t, err.Error(), tt.expectedErrorMsg)
				}
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedPath, gotPath)
			if tt.expectedQuery != "" {
				require.Contains(t, gotQuery, tt.expectedQuery)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// UpdateConnectorMaintenanceMode
// ---------------------------------------------------------------------------

func TestUpdateConnectorMaintenanceMode(t *testing.T) {
	connectorID := "conn-maint-1"

	tests := []struct {
		name             string
		connectorID      string
		maintenance      bool
		serverStatus     int
		serverBody       string
		closeServer      bool
		expectedError    bool
		expectedErrorMsg string
		expectedPath     string
	}{
		{
			name:          "enable_success",
			connectorID:   connectorID,
			maintenance:   true,
			serverStatus:  http.StatusOK,
			serverBody:    `{"connector_id":"conn-maint-1","maintenance":true}`,
			expectedError: false,
			expectedPath:  fmt.Sprintf(connectorMaintenanceURL, connectorID),
		},
		{
			name:          "disable_success",
			connectorID:   connectorID,
			maintenance:   false,
			serverStatus:  http.StatusOK,
			serverBody:    `{"connector_id":"conn-maint-1","maintenance":false}`,
			expectedError: false,
			expectedPath:  fmt.Sprintf(connectorMaintenanceURL, connectorID),
		},
		{
			name:             "non_200_status",
			connectorID:      connectorID,
			serverStatus:     http.StatusForbidden,
			serverBody:       `{"error":"forbidden"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to update connector maintenance mode",
		},
		{
			name:             "transport_error",
			connectorID:      connectorID,
			closeServer:      true,
			expectedError:    true,
			expectedErrorMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var gotPath string
			testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverStatus)
				_, _ = w.Write([]byte(tt.serverBody))
			}))

			if tt.closeServer {
				testServer.Close()
			} else {
				defer testServer.Close()
			}

			svc := newServiceWithHTTPTest(t, testServer.URL)
			status, err := svc.UpdateConnectorMaintenanceMode(&accessmodels.IdsecSIAMaintenanceConnector{
				ConnectorID: tt.connectorID,
				Maintenance: tt.maintenance,
			})

			if tt.expectedError {
				require.Error(t, err)
				if tt.expectedErrorMsg != "" {
					require.Contains(t, err.Error(), tt.expectedErrorMsg)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, status)
			require.Equal(t, tt.expectedPath, gotPath)
		})
	}
}
