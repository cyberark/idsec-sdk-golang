package authprofiles

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	authprofilesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/authprofiles/models"
)

// MockHTTPResponse creates a mock HTTP response with the given status code and body.
func MockHTTPResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

// MockPostFunc creates a mock function for POST operations that returns the provided response.
func MockPostFunc(response *http.Response, err error) func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	return func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
		return response, err
	}
}

func MockISPAuth() *auth.IdsecISPAuth {
	return &auth.IdsecISPAuth{
		IdsecAuthBase: &auth.IdsecAuthBase{
			Token: &authmodels.IdsecToken{
				Token:      "",
				TokenType:  authmodels.JWT,
				Username:   "mock-username@mock-domain.cyberark.cloud",
				Endpoint:   "https://mock-endpoint",
				AuthMethod: authmodels.Identity,
				Metadata: map[string]interface{}{
					"env": "dev",
				},
			},
		},
	}
}

// Sample JSON responses for testing
const (
	CreateAuthProfileResponseJSON = `{
		"success": true,
		"Result": {
			"Uuid": "profile-123",
			"Name": "TestProfile",
			"DurationInMinutes": 30,
			"Challenges": ["UP", "SMS,EMAIL"],
			"AdditionalData": {"key": "value"}
		}
	}`

	CreateAuthProfileFailureResponseJSON = `{
		"success": false
	}`

	GetAuthProfileResponseJSON = `{
		"success": true,
		"Result": {
			"Uuid": "profile-123",
			"Name": "TestProfile",
			"DurationInMinutes": 30,
			"Challenges": ["UP", "SMS,EMAIL"],
			"AdditionalData": {"key": "value"}
		}
	}`

	UpdateAuthProfileResponseJSON = `{
		"success": true,
		"Result": {
			"Uuid": "profile-123",
			"Name": "UpdatedProfile",
			"DurationInMinutes": 45,
			"Challenges": ["SMS", "EMAIL"],
			"AdditionalData": {"updated": "data"}
		}
	}`

	DeleteAuthProfileResponseJSON = `{
		"success": true
	}`

	ListAuthProfilesResponseJSON = `{
		"success": true,
		"Result": {
			"Results": [
				{
					"Row": {
						"Uuid": "profile-1",
						"Name": "Profile1",
						"DurationInMinutes": 30,
						"Challenges": ["UP", "SMS"],
						"AdditionalData": {}
					}
				},
				{
					"Row": {
						"Uuid": "profile-2",
						"Name": "Profile2",
						"DurationInMinutes": 60,
						"Challenges": ["EMAIL", "OTP"],
						"AdditionalData": {}
					}
				}
			]
		}
	}`

	ListAuthProfilesEmptyResponseJSON = `{
		"success": true,
		"Result": {
			"Results": []
		}
	}`

	ErrorResponseJSON = `{
		"success": false,
		"error": "operation failed"
	}`
)

func TestCreateAuthProfile(t *testing.T) {
	tests := []struct {
		name              string
		createAuthProfile *authprofilesmodels.IdsecIdentityCreateAuthProfile
		mockPostResponse  *http.Response
		mockPostError     error
		expectedProfile   *authprofilesmodels.IdsecIdentityAuthProfile
		expectedError     bool
	}{
		{
			name: "success_create_profile_with_first_challenges_only",
			createAuthProfile: &authprofilesmodels.IdsecIdentityCreateAuthProfile{
				AuthProfileName:   "TestProfile",
				FirstChallenges:   []string{"UP"},
				DurationInMinutes: 30,
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, CreateAuthProfileResponseJSON),
			mockPostError:    nil,
			expectedProfile: &authprofilesmodels.IdsecIdentityAuthProfile{
				AuthProfileID:     "profile-123",
				AuthProfileName:   "TestProfile",
				DurationInMinutes: 30,
				FirstChallenges:   []string{"UP"},
				SecondChallenges:  []string{"SMS", "EMAIL"},
			},
			expectedError: false,
		},
		{
			name: "success_create_profile_with_both_challenges",
			createAuthProfile: &authprofilesmodels.IdsecIdentityCreateAuthProfile{
				AuthProfileName:   "TestProfile",
				FirstChallenges:   []string{"UP"},
				SecondChallenges:  []string{"SMS", "EMAIL"},
				DurationInMinutes: 30,
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, CreateAuthProfileResponseJSON),
			mockPostError:    nil,
			expectedProfile: &authprofilesmodels.IdsecIdentityAuthProfile{
				AuthProfileID:     "profile-123",
				AuthProfileName:   "TestProfile",
				DurationInMinutes: 30,
				FirstChallenges:   []string{"UP"},
				SecondChallenges:  []string{"SMS", "EMAIL"},
			},
			expectedError: false,
		},
		{
			name: "success_create_profile_with_additional_data",
			createAuthProfile: &authprofilesmodels.IdsecIdentityCreateAuthProfile{
				AuthProfileName:   "TestProfile",
				FirstChallenges:   []string{"UP"},
				DurationInMinutes: 30,
				AdditionalData:    map[string]interface{}{"key": "value"},
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, CreateAuthProfileResponseJSON),
			mockPostError:    nil,
			expectedProfile: &authprofilesmodels.IdsecIdentityAuthProfile{
				AuthProfileID:     "profile-123",
				AuthProfileName:   "TestProfile",
				DurationInMinutes: 30,
				FirstChallenges:   []string{"UP"},
				SecondChallenges:  []string{"SMS", "EMAIL"},
			},
			expectedError: false,
		},
		{
			name: "error_http_request_failed",
			createAuthProfile: &authprofilesmodels.IdsecIdentityCreateAuthProfile{
				AuthProfileName:   "TestProfile",
				FirstChallenges:   []string{"UP"},
				DurationInMinutes: 30,
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
		{
			name: "error_non_200_status",
			createAuthProfile: &authprofilesmodels.IdsecIdentityCreateAuthProfile{
				AuthProfileName:   "TestProfile",
				FirstChallenges:   []string{"UP"},
				DurationInMinutes: 30,
			},
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name: "error_success_false",
			createAuthProfile: &authprofilesmodels.IdsecIdentityCreateAuthProfile{
				AuthProfileName:   "TestProfile",
				FirstChallenges:   []string{"UP"},
				DurationInMinutes: 30,
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, CreateAuthProfileFailureResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityAuthProfilesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityAuthProfilesService: %v", err)
			}
			service.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)

			result, err := service.CreateAuthProfile(tt.createAuthProfile)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if result.AuthProfileID != tt.expectedProfile.AuthProfileID {
				t.Errorf("Expected profile ID %s, got %s", tt.expectedProfile.AuthProfileID, result.AuthProfileID)
			}
			if result.AuthProfileName != tt.expectedProfile.AuthProfileName {
				t.Errorf("Expected profile name %s, got %s", tt.expectedProfile.AuthProfileName, result.AuthProfileName)
			}
			if result.DurationInMinutes != tt.expectedProfile.DurationInMinutes {
				t.Errorf("Expected duration %d, got %d", tt.expectedProfile.DurationInMinutes, result.DurationInMinutes)
			}
		})
	}
}

func TestUpdateAuthProfile(t *testing.T) {
	tests := []struct {
		name              string
		updateAuthProfile *authprofilesmodels.IdsecIdentityUpdateAuthProfile
		mockPostResponse  *http.Response
		mockPostError     error
		expectedError     bool
		setupMock         func(service *IdsecIdentityAuthProfilesService)
	}{
		{
			name: "success_update_profile_name",
			updateAuthProfile: &authprofilesmodels.IdsecIdentityUpdateAuthProfile{
				AuthProfileID:   "profile-123",
				AuthProfileName: "UpdatedProfile",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UpdateAuthProfileResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityAuthProfilesService) {
				callCount := 0
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						// First call to get existing profile
						return MockHTTPResponse(http.StatusOK, GetAuthProfileResponseJSON), nil
					}
					// Second call to update profile
					return MockHTTPResponse(http.StatusOK, UpdateAuthProfileResponseJSON), nil
				}
			},
		},
		{
			name: "success_update_profile_challenges",
			updateAuthProfile: &authprofilesmodels.IdsecIdentityUpdateAuthProfile{
				AuthProfileID:   "profile-123",
				FirstChallenges: []string{"SMS"},
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UpdateAuthProfileResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityAuthProfilesService) {
				callCount := 0
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, GetAuthProfileResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, UpdateAuthProfileResponseJSON), nil
				}
			},
		},
		{
			name: "success_update_profile_duration",
			updateAuthProfile: &authprofilesmodels.IdsecIdentityUpdateAuthProfile{
				AuthProfileID:     "profile-123",
				DurationInMinutes: 45,
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, UpdateAuthProfileResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
			setupMock: func(service *IdsecIdentityAuthProfilesService) {
				callCount := 0
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, GetAuthProfileResponseJSON), nil
					}
					return MockHTTPResponse(http.StatusOK, UpdateAuthProfileResponseJSON), nil
				}
			},
		},
		{
			name: "error_get_existing_profile_failed",
			updateAuthProfile: &authprofilesmodels.IdsecIdentityUpdateAuthProfile{
				AuthProfileID:   "profile-123",
				AuthProfileName: "UpdatedProfile",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
		{
			name: "error_update_request_failed",
			updateAuthProfile: &authprofilesmodels.IdsecIdentityUpdateAuthProfile{
				AuthProfileID:   "profile-123",
				AuthProfileName: "UpdatedProfile",
			},
			mockPostResponse: nil,
			mockPostError:    nil,
			expectedError:    true,
			setupMock: func(service *IdsecIdentityAuthProfilesService) {
				callCount := 0
				service.DoPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
					callCount++
					if callCount == 1 {
						return MockHTTPResponse(http.StatusOK, GetAuthProfileResponseJSON), nil
					}
					return nil, errors.New("network error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityAuthProfilesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityAuthProfilesService: %v", err)
			}

			if tt.setupMock != nil {
				tt.setupMock(service)
			} else {
				service.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)
			}

			result, err := service.UpdateAuthProfile(tt.updateAuthProfile)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if result == nil {
				t.Errorf("Expected profile result, got nil")
			}
		})
	}
}

func TestAuthProfile(t *testing.T) {
	tests := []struct {
		name             string
		getAuthProfile   *authprofilesmodels.IdsecIdentityGetAuthProfile
		mockPostResponse *http.Response
		mockPostError    error
		expectedProfile  *authprofilesmodels.IdsecIdentityAuthProfile
		expectedError    bool
	}{
		{
			name: "success_get_profile_by_id",
			getAuthProfile: &authprofilesmodels.IdsecIdentityGetAuthProfile{
				AuthProfileID: "profile-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, GetAuthProfileResponseJSON),
			mockPostError:    nil,
			expectedProfile: &authprofilesmodels.IdsecIdentityAuthProfile{
				AuthProfileID:     "profile-123",
				AuthProfileName:   "TestProfile",
				DurationInMinutes: 30,
				FirstChallenges:   []string{"UP"},
				SecondChallenges:  []string{"SMS", "EMAIL"},
			},
			expectedError: false,
		},
		{
			name: "error_http_request_failed",
			getAuthProfile: &authprofilesmodels.IdsecIdentityGetAuthProfile{
				AuthProfileID: "profile-123",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
		{
			name: "error_non_200_status",
			getAuthProfile: &authprofilesmodels.IdsecIdentityGetAuthProfile{
				AuthProfileID: "profile-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusNotFound, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name: "error_success_false",
			getAuthProfile: &authprofilesmodels.IdsecIdentityGetAuthProfile{
				AuthProfileID: "profile-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, CreateAuthProfileFailureResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityAuthProfilesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityAuthProfilesService: %v", err)
			}
			service.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)

			result, err := service.AuthProfile(tt.getAuthProfile)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if result.AuthProfileID != tt.expectedProfile.AuthProfileID {
				t.Errorf("Expected profile ID %s, got %s", tt.expectedProfile.AuthProfileID, result.AuthProfileID)
			}
			if result.AuthProfileName != tt.expectedProfile.AuthProfileName {
				t.Errorf("Expected profile name %s, got %s", tt.expectedProfile.AuthProfileName, result.AuthProfileName)
			}
		})
	}
}

func TestDeleteAuthProfile(t *testing.T) {
	tests := []struct {
		name              string
		deleteAuthProfile *authprofilesmodels.IdsecIdentityDeleteAuthProfile
		mockPostResponse  *http.Response
		mockPostError     error
		expectedError     bool
	}{
		{
			name: "success_delete_profile_by_id",
			deleteAuthProfile: &authprofilesmodels.IdsecIdentityDeleteAuthProfile{
				AuthProfileID: "profile-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, DeleteAuthProfileResponseJSON),
			mockPostError:    nil,
			expectedError:    false,
		},
		{
			name: "error_http_request_failed",
			deleteAuthProfile: &authprofilesmodels.IdsecIdentityDeleteAuthProfile{
				AuthProfileID: "profile-123",
			},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
		{
			name: "error_non_200_status",
			deleteAuthProfile: &authprofilesmodels.IdsecIdentityDeleteAuthProfile{
				AuthProfileID: "profile-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name: "error_success_false",
			deleteAuthProfile: &authprofilesmodels.IdsecIdentityDeleteAuthProfile{
				AuthProfileID: "profile-123",
			},
			mockPostResponse: MockHTTPResponse(http.StatusOK, CreateAuthProfileFailureResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityAuthProfilesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityAuthProfilesService: %v", err)
			}
			service.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)

			err = service.DeleteAuthProfile(tt.deleteAuthProfile)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestListAuthProfiles(t *testing.T) {
	tests := []struct {
		name                string
		mockPostResponse    *http.Response
		mockPostError       error
		expectedProfilesLen int
		expectedError       bool
	}{
		{
			name:                "success_list_profiles",
			mockPostResponse:    MockHTTPResponse(http.StatusOK, ListAuthProfilesResponseJSON),
			mockPostError:       nil,
			expectedProfilesLen: 2,
			expectedError:       false,
		},
		{
			name:                "success_list_empty_profiles",
			mockPostResponse:    MockHTTPResponse(http.StatusOK, ListAuthProfilesEmptyResponseJSON),
			mockPostError:       nil,
			expectedProfilesLen: 0,
			expectedError:       false,
		},
		{
			name:             "error_http_request_failed",
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
		{
			name:             "error_non_200_status",
			mockPostResponse: MockHTTPResponse(http.StatusInternalServerError, ErrorResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
		},
		{
			name:             "error_success_false",
			mockPostResponse: MockHTTPResponse(http.StatusOK, CreateAuthProfileFailureResponseJSON),
			mockPostError:    nil,
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityAuthProfilesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityAuthProfilesService: %v", err)
			}
			service.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)

			result, err := service.ListAuthProfiles()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if len(result) != tt.expectedProfilesLen {
				t.Errorf("Expected %d profiles, got %d", tt.expectedProfilesLen, len(result))
			}
		})
	}
}

func TestListAuthProfilesBy(t *testing.T) {
	tests := []struct {
		name                string
		filters             *authprofilesmodels.IdsecIdentityAuthProfilesFilters
		mockPostResponse    *http.Response
		mockPostError       error
		expectedProfilesLen int
		expectedError       bool
	}{
		{
			name: "success_filter_by_challenges",
			filters: &authprofilesmodels.IdsecIdentityAuthProfilesFilters{
				Challenges: []string{"UP"},
			},
			mockPostResponse:    MockHTTPResponse(http.StatusOK, ListAuthProfilesResponseJSON),
			mockPostError:       nil,
			expectedProfilesLen: 1,
			expectedError:       false,
		},
		{
			name: "success_filter_no_match",
			filters: &authprofilesmodels.IdsecIdentityAuthProfilesFilters{
				Challenges: []string{"NONEXISTENT"},
			},
			mockPostResponse:    MockHTTPResponse(http.StatusOK, ListAuthProfilesResponseJSON),
			mockPostError:       nil,
			expectedProfilesLen: 0,
			expectedError:       false,
		},
		{
			name:             "error_list_profiles_failed",
			filters:          &authprofilesmodels.IdsecIdentityAuthProfilesFilters{},
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityAuthProfilesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityAuthProfilesService: %v", err)
			}
			service.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)

			result, err := service.ListAuthProfilesBy(tt.filters)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if len(result) != tt.expectedProfilesLen {
				t.Errorf("Expected %d profiles, got %d", tt.expectedProfilesLen, len(result))
			}
		})
	}
}

func TestAuthProfilesStats(t *testing.T) {
	tests := []struct {
		name             string
		mockPostResponse *http.Response
		mockPostError    error
		expectedStats    *authprofilesmodels.IdsecIdentityAuthProfilesStats
		expectedError    bool
	}{
		{
			name:             "success_get_stats",
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListAuthProfilesResponseJSON),
			mockPostError:    nil,
			expectedStats: &authprofilesmodels.IdsecIdentityAuthProfilesStats{
				AuthProfilesCount: 2,
			},
			expectedError: false,
		},
		{
			name:             "success_empty_stats",
			mockPostResponse: MockHTTPResponse(http.StatusOK, ListAuthProfilesEmptyResponseJSON),
			mockPostError:    nil,
			expectedStats: &authprofilesmodels.IdsecIdentityAuthProfilesStats{
				AuthProfilesCount: 0,
			},
			expectedError: false,
		},
		{
			name:             "error_list_profiles_failed",
			mockPostResponse: nil,
			mockPostError:    errors.New("network error"),
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service, err := NewIdsecIdentityAuthProfilesService(MockISPAuth())
			if err != nil {
				t.Fatalf("Failed to create IdsecIdentityAuthProfilesService: %v", err)
			}
			service.DoPost = MockPostFunc(tt.mockPostResponse, tt.mockPostError)

			result, err := service.AuthProfilesStats()

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if !reflect.DeepEqual(result, tt.expectedStats) {
				t.Errorf("Expected stats %+v, got %+v", tt.expectedStats, result)
			}
		})
	}
}
