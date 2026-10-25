package securezones

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	securezonesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/securezones/models"
)

// ── test helpers ──────────────────────────────────────────────────────────────

func MockISPAuth() *auth.IdsecISPAuth {
	return &auth.IdsecISPAuth{
		IdsecAuthBase: &auth.IdsecAuthBase{
			Token: &authmodels.IdsecToken{
				Token:      "",
				TokenType:  authmodels.JWT,
				Username:   "mock-username@mock-domain.cyberark.cloud",
				Endpoint:   "https://mock-endpoint",
				AuthMethod: authmodels.Identity,
				Metadata:   map[string]interface{}{"env": "dev"},
			},
		},
	}
}

func MockHTTPResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

func MockPostFunc(resp *http.Response, err error) func(context.Context, string, interface{}) (*http.Response, error) {
	return func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
		return resp, err
	}
}

// ── sample JSON responses ─────────────────────────────────────────────────────

const (
	// ListZonesJSON returns two zones: zone-1 active, zone-2 inactive.
	ListZonesJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{"Row": {"ID": "zone-1", "Label": "Zone One", "Range": "10.0.0.0/24", "Status": "active"}},
				{"Row": {"ID": "zone-2", "Label": "Zone Two", "Range": "10.0.1.0/24", "Status": "inactive"}}
			]
		}
	}`

	// ListZonesEmptyJSON returns an empty result set.
	ListZonesEmptyJSON = `{
		"success": true,
		"Result": {
			"Results": []
		}
	}`

	// ListZonesMissingStatusJSON returns a zone with no Status field — server defaults it to "active".
	ListZonesMissingStatusJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{"Row": {"ID": "zone-3", "Label": "Zone Three", "Range": "10.0.3.0/24"}}
			]
		}
	}`

	// ListSingleZoneActiveJSON is used as the read-back response after create/update.
	ListSingleZoneActiveJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{"Row": {"ID": "zone-new", "Label": "New Zone", "Range": "10.0.2.0/24", "Status": "active"}}
			]
		}
	}`

	// ListSingleZoneInactiveJSON is used as the read-back response after a create with status=inactive.
	ListSingleZoneInactiveJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{"Row": {"ID": "zone-new", "Label": "New Zone", "Range": "10.0.2.0/24", "Status": "inactive"}}
			]
		}
	}`

	CreateZoneSuccessJSON  = `{"success": true, "Result": "zone-new"}`
	UpdateZoneSuccessJSON  = `{"success": true, "Result": {}}`
	DisableZoneSuccessJSON = `{"success": true, "Result": {}}`
	EnableZoneSuccessJSON  = `{"success": true, "Result": {}}`
	DeleteZoneSuccessJSON  = `{"success": true}`
	APIErrorJSON           = `{"success": false, "Message": "permission denied"}`
	ServerErrorBody        = `{"success": false, "error": "internal error"}`
)

// ── TestList ──────────────────────────────────────────────────────────────────

func TestList(t *testing.T) {
	tests := []struct {
		name             string
		mockPostResponse *http.Response
		mockPostError    error
		expectedLen      int
		expectedError    bool
	}{
		{
			name:             "success_list_two_zones",
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListZonesJSON),
			expectedLen:      2,
		},
		{
			name:             "success_list_empty",
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListZonesEmptyJSON),
			expectedLen:      0,
		},
		{
			name:             "success_missing_status_defaults_to_active",
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListZonesMissingStatusJSON),
			expectedLen:      1,
		},
		{
			name:          "error_network_failure",
			mockPostError: errors.New("connection refused"),
			expectedError: true,
		},
		{
			name:             "error_non_200_status",
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ServerErrorBody),
			expectedError:    true,
		},
		{
			name:             "error_success_false",
			mockPostResponse: MockHTTPResponse(http.StatusOK, APIErrorJSON),
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc, err := NewIdsecIdentitySecureZonesService(MockISPAuth())
			if err != nil {
				t.Fatalf("failed to create service: %v", err)
			}
			svc.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)

			result, err := svc.List()

			if tt.expectedError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != tt.expectedLen {
				t.Errorf("expected %d zones, got %d", tt.expectedLen, len(result))
			}
		})
	}
}

// TestList_FieldDecoding verifies that PascalCase wire keys decode correctly into the model.
func TestList_FieldDecoding(t *testing.T) {
	svc, err := NewIdsecIdentitySecureZonesService(MockISPAuth())
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}
	svc.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListZonesJSON), nil)

	result, err := svc.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(result))
	}

	z := result[0]
	if z.ID != "zone-1" {
		t.Errorf("expected ID %q, got %q", "zone-1", z.ID)
	}
	if z.Label != "Zone One" {
		t.Errorf("expected Label %q, got %q", "Zone One", z.Label)
	}
	if z.Range != "10.0.0.0/24" {
		t.Errorf("expected Range %q, got %q", "10.0.0.0/24", z.Range)
	}
	if z.Status != "active" {
		t.Errorf("expected Status %q, got %q", "active", z.Status)
	}
}

// TestList_MissingStatusDefaultsToActive verifies the server default-to-active behaviour
// (PremDetect.GetRangesQuery line 100: range.Get(RangeFields.Status, SECURE_ZONE_ACTIVE)).
func TestList_MissingStatusDefaultsToActive(t *testing.T) {
	svc, err := NewIdsecIdentitySecureZonesService(MockISPAuth())
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}
	svc.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListZonesMissingStatusJSON), nil)

	result, err := svc.List()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("expected 1 zone, got 0")
	}
	if result[0].Status != "active" {
		t.Errorf("expected Status %q when absent from wire, got %q", "active", result[0].Status)
	}
}

// ── TestListBy ────────────────────────────────────────────────────────────────

func TestListBy(t *testing.T) {
	tests := []struct {
		name             string
		filters          *securezonesmodels.IdsecIdentitySecureZoneFilters
		mockPostResponse *http.Response
		mockPostError    error
		expectedLen      int
		expectedError    bool
	}{
		{
			name:             "success_filter_by_label_match",
			filters:          &securezonesmodels.IdsecIdentitySecureZoneFilters{Label: "Zone One"},
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListZonesJSON),
			expectedLen:      1,
		},
		{
			name:             "success_filter_by_label_no_match",
			filters:          &securezonesmodels.IdsecIdentitySecureZoneFilters{Label: "Nonexistent"},
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListZonesJSON),
			expectedLen:      0,
		},
		{
			name:             "success_filter_by_range",
			filters:          &securezonesmodels.IdsecIdentitySecureZoneFilters{Range: "10.0.0.0/24"},
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListZonesJSON),
			expectedLen:      1,
		},
		{
			name:             "success_filter_by_status_inactive",
			filters:          &securezonesmodels.IdsecIdentitySecureZoneFilters{Status: "inactive"},
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListZonesJSON),
			expectedLen:      1,
		},
		{
			name:             "success_filter_by_status_active",
			filters:          &securezonesmodels.IdsecIdentitySecureZoneFilters{Status: "active"},
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListZonesJSON),
			expectedLen:      1,
		},
		{
			name:             "success_nil_filters_returns_all",
			filters:          nil,
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListZonesJSON),
			expectedLen:      2,
		},
		{
			name:          "error_list_failure",
			filters:       &securezonesmodels.IdsecIdentitySecureZoneFilters{Label: "Zone One"},
			mockPostError: errors.New("network error"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc, err := NewIdsecIdentitySecureZonesService(MockISPAuth())
			if err != nil {
				t.Fatalf("failed to create service: %v", err)
			}
			svc.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)

			result, err := svc.ListBy(tt.filters)

			if tt.expectedError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != tt.expectedLen {
				t.Errorf("expected %d zones, got %d", tt.expectedLen, len(result))
			}
		})
	}
}

// ── TestGet ───────────────────────────────────────────────────────────────────

func TestGet(t *testing.T) {
	tests := []struct {
		name             string
		req              *securezonesmodels.IdsecIdentityGetSecureZone
		mockPostResponse *http.Response
		mockPostError    error
		expectedID       string
		expectedError    bool
		expectNotFound   bool
	}{
		{
			name:             "success_get_by_id",
			req:              &securezonesmodels.IdsecIdentityGetSecureZone{ID: "zone-1"},
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListZonesJSON),
			expectedID:       "zone-1",
		},
		{
			// Not-found must wrap common.ErrNotFound so the provider's Read handler
			// can remove the resource from state on out-of-band deletions.
			name:             "error_not_found_wraps_ErrNotFound",
			req:              &securezonesmodels.IdsecIdentityGetSecureZone{ID: "nonexistent"},
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListZonesJSON),
			expectedError:    true,
			expectNotFound:   true,
		},
		{
			name:             "error_not_found_in_empty_list",
			req:              &securezonesmodels.IdsecIdentityGetSecureZone{ID: "zone-1"},
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListZonesEmptyJSON),
			expectedError:    true,
			expectNotFound:   true,
		},
		{
			name:          "error_network_failure",
			req:           &securezonesmodels.IdsecIdentityGetSecureZone{ID: "zone-1"},
			mockPostError: errors.New("connection refused"),
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc, err := NewIdsecIdentitySecureZonesService(MockISPAuth())
			if err != nil {
				t.Fatalf("failed to create service: %v", err)
			}
			svc.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)

			result, err := svc.Get(tt.req)

			if tt.expectedError {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if tt.expectNotFound && !errors.Is(err, common.ErrNotFound) {
					t.Errorf("expected errors.Is(err, common.ErrNotFound); got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.ID != tt.expectedID {
				t.Errorf("expected ID %q, got %q", tt.expectedID, result.ID)
			}
		})
	}
}

// ── TestCreate ────────────────────────────────────────────────────────────────

func TestCreate(t *testing.T) {
	tests := []struct {
		name          string
		req           *securezonesmodels.IdsecIdentityCreateSecureZone
		setupMock     func(svc *IdsecIdentitySecureZonesService)
		expectedID    string
		expectedError bool
	}{
		{
			// Happy path: active zone — create → read-back (List).
			name: "success_create_active_zone",
			req: &securezonesmodels.IdsecIdentityCreateSecureZone{
				Label:  "New Zone",
				Range:  "10.0.2.0/24",
				Status: "active",
			},
			setupMock: func(svc *IdsecIdentitySecureZonesService) {
				callCount := 0
				svc.DoPost = func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
					callCount++
					switch callCount {
					case 1: // Create endpoint → bare UUID string in Result
						return MockHTTPResponse(http.StatusOK, CreateZoneSuccessJSON), nil
					default: // Get read-back (List)
						return MockHTTPResponse(http.StatusOK, ListSingleZoneActiveJSON), nil
					}
				}
			},
			expectedID: "zone-new",
		},
		{
			// Inactive zone: create → Disable → read-back (List).
			name: "success_create_inactive_zone_calls_disable",
			req: &securezonesmodels.IdsecIdentityCreateSecureZone{
				Label:  "New Zone",
				Range:  "10.0.2.0/24",
				Status: "inactive",
			},
			setupMock: func(svc *IdsecIdentitySecureZonesService) {
				callCount := 0
				svc.DoPost = func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
					callCount++
					switch callCount {
					case 1: // Create endpoint
						return MockHTTPResponse(http.StatusOK, CreateZoneSuccessJSON), nil
					case 2: // Disable endpoint
						return MockHTTPResponse(http.StatusOK, DisableZoneSuccessJSON), nil
					default: // Get read-back (List)
						return MockHTTPResponse(http.StatusOK, ListSingleZoneInactiveJSON), nil
					}
				}
			},
			expectedID: "zone-new",
		},
		{
			// Create returns a non-string Result — unexpected shape must error.
			name: "error_result_not_uuid_string",
			req:  &securezonesmodels.IdsecIdentityCreateSecureZone{Label: "New Zone", Range: "10.0.2.0/24"},
			setupMock: func(svc *IdsecIdentitySecureZonesService) {
				svc.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, `{"success": true, "Result": {}}`), nil)
			},
			expectedError: true,
		},
		{
			name: "error_success_false",
			req:  &securezonesmodels.IdsecIdentityCreateSecureZone{Label: "New Zone", Range: "10.0.2.0/24"},
			setupMock: func(svc *IdsecIdentitySecureZonesService) {
				svc.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, APIErrorJSON), nil)
			},
			expectedError: true,
		},
		{
			name: "error_non_200_status",
			req:  &securezonesmodels.IdsecIdentityCreateSecureZone{Label: "New Zone", Range: "10.0.2.0/24"},
			setupMock: func(svc *IdsecIdentitySecureZonesService) {
				svc.DoPost = MockPostFunc(MockHTTPResponse(http.StatusInternalServerError, ServerErrorBody), nil)
			},
			expectedError: true,
		},
		{
			name: "error_network_failure",
			req:  &securezonesmodels.IdsecIdentityCreateSecureZone{Label: "New Zone", Range: "10.0.2.0/24"},
			setupMock: func(svc *IdsecIdentitySecureZonesService) {
				svc.DoPost = MockPostFunc(nil, errors.New("connection refused"))
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc, err := NewIdsecIdentitySecureZonesService(MockISPAuth())
			if err != nil {
				t.Fatalf("failed to create service: %v", err)
			}
			tt.setupMock(svc)

			result, err := svc.Create(tt.req)

			if tt.expectedError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.ID != tt.expectedID {
				t.Errorf("expected ID %q, got %q", tt.expectedID, result.ID)
			}
		})
	}
}

// ── TestUpdate ────────────────────────────────────────────────────────────────

func TestUpdate(t *testing.T) {
	tests := []struct {
		name          string
		req           *securezonesmodels.IdsecIdentityUpdateSecureZone
		setupMock     func(svc *IdsecIdentitySecureZonesService)
		expectedError bool
	}{
		{
			// No status change: Get(List) → Update → Get(List).
			name: "success_update_label_no_status_change",
			req: &securezonesmodels.IdsecIdentityUpdateSecureZone{
				ID:    "zone-1",
				Label: "Zone One Updated",
				Range: "10.0.0.0/24",
			},
			setupMock: func(svc *IdsecIdentitySecureZonesService) {
				callCount := 0
				svc.DoPost = func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
					callCount++
					switch callCount {
					case 1: // Get existing state (List)
						return MockHTTPResponse(http.StatusOK, ListZonesJSON), nil
					case 2: // Update endpoint
						return MockHTTPResponse(http.StatusOK, UpdateZoneSuccessJSON), nil
					default: // Get read-back (List)
						return MockHTTPResponse(http.StatusOK, ListZonesJSON), nil
					}
				}
			},
		},
		{
			// Status active → inactive: Get(List) → Update → Disable → Get(List).
			name: "success_update_status_to_inactive",
			req: &securezonesmodels.IdsecIdentityUpdateSecureZone{
				ID:     "zone-1",
				Label:  "Zone One",
				Range:  "10.0.0.0/24",
				Status: "inactive",
			},
			setupMock: func(svc *IdsecIdentitySecureZonesService) {
				callCount := 0
				svc.DoPost = func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
					callCount++
					switch callCount {
					case 1: // Get existing state (List) — zone-1 is active
						return MockHTTPResponse(http.StatusOK, ListZonesJSON), nil
					case 2: // Update endpoint
						return MockHTTPResponse(http.StatusOK, UpdateZoneSuccessJSON), nil
					case 3: // Disable endpoint (status active → inactive)
						return MockHTTPResponse(http.StatusOK, DisableZoneSuccessJSON), nil
					default: // Get read-back (List)
						return MockHTTPResponse(http.StatusOK, ListZonesJSON), nil
					}
				}
			},
		},
		{
			// Status inactive → active: Get(List) → Update → Enable → Get(List).
			name: "success_update_status_to_active",
			req: &securezonesmodels.IdsecIdentityUpdateSecureZone{
				ID:     "zone-2",
				Label:  "Zone Two",
				Range:  "10.0.1.0/24",
				Status: "active",
			},
			setupMock: func(svc *IdsecIdentitySecureZonesService) {
				callCount := 0
				svc.DoPost = func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
					callCount++
					switch callCount {
					case 1: // Get existing state (List) — zone-2 is inactive
						return MockHTTPResponse(http.StatusOK, ListZonesJSON), nil
					case 2: // Update endpoint
						return MockHTTPResponse(http.StatusOK, UpdateZoneSuccessJSON), nil
					case 3: // Enable endpoint (status inactive → active)
						return MockHTTPResponse(http.StatusOK, EnableZoneSuccessJSON), nil
					default: // Get read-back (List)
						return MockHTTPResponse(http.StatusOK, ListZonesJSON), nil
					}
				}
			},
		},
		{
			name: "error_network_failure_on_get_existing",
			req:  &securezonesmodels.IdsecIdentityUpdateSecureZone{ID: "zone-1", Label: "Zone One", Range: "10.0.0.0/24"},
			setupMock: func(svc *IdsecIdentitySecureZonesService) {
				svc.DoPost = MockPostFunc(nil, errors.New("connection refused"))
			},
			expectedError: true,
		},
		{
			name: "error_update_request_fails",
			req:  &securezonesmodels.IdsecIdentityUpdateSecureZone{ID: "zone-1", Label: "Zone One", Range: "10.0.0.0/24"},
			setupMock: func(svc *IdsecIdentitySecureZonesService) {
				callCount := 0
				svc.DoPost = func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, ListZonesJSON), nil
					}
					return nil, errors.New("network error on update")
				}
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc, err := NewIdsecIdentitySecureZonesService(MockISPAuth())
			if err != nil {
				t.Fatalf("failed to create service: %v", err)
			}
			tt.setupMock(svc)

			result, err := svc.Update(tt.req)

			if tt.expectedError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Error("expected non-nil result")
			}
		})
	}
}

// ── TestDelete ────────────────────────────────────────────────────────────────

func TestDelete(t *testing.T) {
	t.Run("success_delete_zone", func(t *testing.T) {
		t.Parallel()
		svc, err := NewIdsecIdentitySecureZonesService(MockISPAuth())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}
		// Delete now does a preflight Get (→ List) before the delete request.
		// Call 1: List (preflight Get) — returns zone-1 so Get succeeds.
		// Call 2: Delete request — returns success.
		callCount := 0
		svc.DoPost = func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
			callCount++
			switch callCount {
			case 1:
				return MockHTTPResponse(http.StatusOK, ListZonesJSON), nil
			default:
				return MockHTTPResponse(http.StatusOK, DeleteZoneSuccessJSON), nil
			}
		}
		if err := svc.Delete(&securezonesmodels.IdsecIdentityDeleteSecureZone{ID: "zone-1"}); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("error_not_found", func(t *testing.T) {
		t.Parallel()
		svc, err := NewIdsecIdentitySecureZonesService(MockISPAuth())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}
		// Preflight Get returns an empty list → Get wraps ErrNotFound → Delete returns it.
		svc.DoPost = MockPostFunc(MockHTTPResponse(http.StatusOK, ListZonesEmptyJSON), nil)
		err = svc.Delete(&securezonesmodels.IdsecIdentityDeleteSecureZone{ID: "zone-1"})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, common.ErrNotFound) {
			t.Errorf("expected errors.Is(err, common.ErrNotFound); got: %v", err)
		}
	})

	t.Run("error_network_failure", func(t *testing.T) {
		t.Parallel()
		svc, err := NewIdsecIdentitySecureZonesService(MockISPAuth())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}
		svc.DoPost = MockPostFunc(nil, errors.New("connection refused"))
		if err := svc.Delete(&securezonesmodels.IdsecIdentityDeleteSecureZone{ID: "zone-1"}); err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("error_non_200_status", func(t *testing.T) {
		t.Parallel()
		svc, err := NewIdsecIdentitySecureZonesService(MockISPAuth())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}
		// Preflight List returns 500 — delete never reached.
		svc.DoPost = MockPostFunc(MockHTTPResponse(http.StatusInternalServerError, ServerErrorBody), nil)
		if err := svc.Delete(&securezonesmodels.IdsecIdentityDeleteSecureZone{ID: "zone-1"}); err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("error_success_false_on_delete", func(t *testing.T) {
		t.Parallel()
		svc, err := NewIdsecIdentitySecureZonesService(MockISPAuth())
		if err != nil {
			t.Fatalf("failed to create service: %v", err)
		}
		// Preflight List succeeds (zone found), actual delete returns success:false.
		callCount := 0
		svc.DoPost = func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
			callCount++
			switch callCount {
			case 1:
				return MockHTTPResponse(http.StatusOK, ListZonesJSON), nil
			default:
				return MockHTTPResponse(http.StatusOK, APIErrorJSON), nil
			}
		}
		if err := svc.Delete(&securezonesmodels.IdsecIdentityDeleteSecureZone{ID: "zone-1"}); err == nil {
			t.Error("expected error, got nil")
		}
	})
}
