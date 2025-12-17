package certificates

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	certificatesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/certificates/models"
)

// NewMockResponse creates a mock HTTP response for testing.
func NewMockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

// createTestService creates a properly initialized test service with mocked dependencies.
func createTestService() *IdsecSIACertificatesService {
	service := &IdsecSIACertificatesService{}
	service.IdsecBaseService = &services.IdsecBaseService{
		Logger: common.GetLogger("test", common.Unknown),
	}
	return service
}

// TestAddCertificate tests the AddCertificate method.
//
// This test validates the ability to add a new certificate through the API.
// It tests successful addition and various error conditions.
func TestAddCertificate(t *testing.T) {
	testCertBody := "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"

	tests := []struct {
		name             string
		addCertificate   *certificatesmodels.IdsecSIACertificatesAddCertificate
		mockStatusCode   int
		mockBody         string
		setupFile        func(t *testing.T) string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name: "success_certificate_from_body",
			addCertificate: &certificatesmodels.IdsecSIACertificatesAddCertificate{
				CertType:        "PEM",
				CertName:        "test-cert",
				CertDescription: "Test certificate",
				DomainName:      "example.com",
				CertificateBody: testCertBody,
			},
			mockStatusCode: http.StatusCreated,
			mockBody:       `{"certificate_id": "cert-123"}`,
			expectedError:  false,
		},
		{
			name: "success_certificate_from_file",
			addCertificate: &certificatesmodels.IdsecSIACertificatesAddCertificate{
				CertType:        "PEM",
				CertName:        "test-cert",
				CertDescription: "Test certificate",
				DomainName:      "example.com",
			},
			setupFile: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "cert.pem")
				err := os.WriteFile(tmpFile, []byte(testCertBody), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return tmpFile
			},
			mockStatusCode: http.StatusCreated,
			mockBody:       `{"certificate_id": "cert-123"}`,
			expectedError:  false,
		},
		{
			name: "success_with_password",
			addCertificate: &certificatesmodels.IdsecSIACertificatesAddCertificate{
				CertType:        "PEM",
				CertName:        "encrypted-cert",
				CertPassword:    "password123",
				DomainName:      "example.com",
				CertificateBody: testCertBody,
			},
			mockStatusCode: http.StatusCreated,
			mockBody:       `{"certificate_id": "cert-123"}`,
			expectedError:  false,
		},
		{
			name: "success_with_labels",
			addCertificate: &certificatesmodels.IdsecSIACertificatesAddCertificate{
				CertType:        "PEM",
				CertName:        "labeled-cert",
				DomainName:      "example.com",
				CertificateBody: testCertBody,
				Labels: map[string]interface{}{
					"environment": "production",
					"team":        "cyberark",
				},
			},
			mockStatusCode: http.StatusCreated,
			mockBody:       `{"certificate_id": "cert-123"}`,
			expectedError:  false,
		},
		{
			name: "success_der_certificate",
			addCertificate: &certificatesmodels.IdsecSIACertificatesAddCertificate{
				CertType:        "DER",
				CertName:        "der-cert",
				DomainName:      "example.com",
				CertificateBody: testCertBody,
			},
			mockStatusCode: http.StatusCreated,
			mockBody:       `{"certificate_id": "cert-123"}`,
			expectedError:  false,
		},
		{
			name: "error_missing_certificate_body_and_file",
			addCertificate: &certificatesmodels.IdsecSIACertificatesAddCertificate{
				CertType:   "PEM",
				CertName:   "test-cert",
				DomainName: "example.com",
			},
			expectedError:    true,
			expectedErrorMsg: "either CertificateBody or File must be provided",
		},
		{
			name: "error_file_not_found",
			addCertificate: &certificatesmodels.IdsecSIACertificatesAddCertificate{
				CertType:   "PEM",
				CertName:   "test-cert",
				DomainName: "example.com",
				File:       "/nonexistent/file.pem",
			},
			expectedError:    true,
			expectedErrorMsg: "open /nonexistent/file.pem: no such file or directory",
		},
		{
			name: "error_bad_request",
			addCertificate: &certificatesmodels.IdsecSIACertificatesAddCertificate{
				CertType:        "INVALID",
				CertName:        "test-cert",
				DomainName:      "example.com",
				CertificateBody: testCertBody,
			},
			mockStatusCode:   http.StatusBadRequest,
			mockBody:         `{"error": "invalid certificate type"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to add certificate",
		},
		{
			name: "error_unauthorized",
			addCertificate: &certificatesmodels.IdsecSIACertificatesAddCertificate{
				CertType:        "PEM",
				CertName:        "test-cert",
				DomainName:      "example.com",
				CertificateBody: testCertBody,
			},
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to add certificate",
		},
		{
			name: "error_conflict_duplicate",
			addCertificate: &certificatesmodels.IdsecSIACertificatesAddCertificate{
				CertType:        "PEM",
				CertName:        "existing-cert",
				DomainName:      "example.com",
				CertificateBody: testCertBody,
			},
			mockStatusCode:   http.StatusConflict,
			mockBody:         `{"error": "certificate already exists"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to add certificate",
		},
		{
			name: "error_internal_server",
			addCertificate: &certificatesmodels.IdsecSIACertificatesAddCertificate{
				CertType:        "PEM",
				CertName:        "test-cert",
				DomainName:      "example.com",
				CertificateBody: testCertBody,
			},
			mockStatusCode:   http.StatusInternalServerError,
			mockBody:         `{"error": "internal error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to add certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doPost = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(http.StatusOK, `{"id": "cert-123"}`), nil
			}

			// Setup file if needed
			if tt.setupFile != nil {
				filePath := tt.setupFile(t)
				tt.addCertificate.File = filePath
			}

			_, err := service.AddCertificate(tt.addCertificate)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestGetCertificate tests the GetCertificate method.
//
// This test validates retrieval of a specific certificate by ID.
// It tests successful retrieval and various error conditions.
func TestGetCertificate(t *testing.T) {
	mockCertificate := `{
		"id": "cert-123",
		"name": "test-cert",
		"type": "PEM",
		"domain": "example.com",
		"description": "Test certificate",
		"created_at": "2024-01-01T00:00:00Z",
		"body": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
	}`

	tests := []struct {
		name             string
		certificateID    string
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result *certificatesmodels.IdsecSIACertificatesCertificate)
	}{
		{
			name:           "success_get_certificate",
			certificateID:  "cert-123",
			mockStatusCode: http.StatusOK,
			mockBody:       mockCertificate,
			expectedError:  false,
			validateFunc: func(t *testing.T, result *certificatesmodels.IdsecSIACertificatesCertificate) {
				if !strings.Contains(mockCertificate, result.CertBody) {
					t.Errorf("Expected result '%s', got '%v'", mockCertificate, result)
				}
			},
		},
		{
			name:             "error_not_found",
			certificateID:    "nonexistent",
			mockStatusCode:   http.StatusNotFound,
			mockBody:         `{"error": "certificate not found"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to get certificate",
		},
		{
			name:             "error_unauthorized",
			certificateID:    "cert-123",
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to get certificate",
		},
		{
			name:             "error_forbidden",
			certificateID:    "cert-123",
			mockStatusCode:   http.StatusForbidden,
			mockBody:         `{"error": "forbidden"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to get certificate",
		},
		{
			name:             "error_internal_server",
			certificateID:    "cert-123",
			mockStatusCode:   http.StatusInternalServerError,
			mockBody:         `{"error": "internal error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to get certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			result, err := service.Certificate(&certificatesmodels.IdsecSIACertificatesGetCertificate{CertificateID: tt.certificateID})

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if tt.validateFunc != nil {
					tt.validateFunc(t, result)
				}
			}
		})
	}
}

// TestListCertificates tests the ListCertificates method.
//
// This test validates retrieval of the certificate list.
// It tests successful listing with various filter parameters.
func TestListCertificates(t *testing.T) {
	mockCertificatesList := `{
		"certificates": {
			"items": [
				{
					"id": "cert-123",
					"name": "cert1",
					"type": "PEM",
					"domain": "example.com"
				},
				{
					"id": "cert-456",
					"name": "cert2",
					"type": "DER",
					"domain": "test.com"
				}
			],
			"total": 2
		}
	}`

	tests := []struct {
		name             string
		listParams       *certificatesmodels.IdsecSIACertificatesFilter
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
		validateFunc     func(t *testing.T, result []*certificatesmodels.IdsecSIACertificatesShortCertificate)
	}{
		{
			name:           "success_list_all",
			listParams:     nil,
			mockStatusCode: http.StatusOK,
			mockBody:       mockCertificatesList,
			expectedError:  false,
		},
		{
			name: "success_with_domain_filter",
			listParams: &certificatesmodels.IdsecSIACertificatesFilter{
				DomainName: "example.com",
			},
			mockStatusCode: http.StatusOK,
			mockBody:       mockCertificatesList,
			expectedError:  false,
		},
		{
			name:           "success_empty_list",
			listParams:     nil,
			mockStatusCode: http.StatusOK,
			mockBody:       `{"certificates": {"items": [], "total": 0}}`,
			expectedError:  false,
		},
		{
			name:             "error_unauthorized",
			listParams:       nil,
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list certificates",
		},
		{
			name:             "error_bad_request",
			listParams:       nil,
			mockStatusCode:   http.StatusBadRequest,
			mockBody:         `{"error": "invalid parameters"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list certificates",
		},
		{
			name:             "error_internal_server",
			listParams:       nil,
			mockStatusCode:   http.StatusInternalServerError,
			mockBody:         `{"error": "internal error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to list certificates",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			result, err := service.ListCertificatesBy(tt.listParams)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
					return
				}
				if tt.validateFunc != nil {
					tt.validateFunc(t, result)
				}
			}
		})
	}
}

// TestUpdateCertificate tests the UpdateCertificate method.
//
// This test validates updating an existing certificate.
// It tests successful updates and various error conditions.
func TestUpdateCertificate(t *testing.T) {
	tests := []struct {
		name             string
		certificateID    string
		updateData       *certificatesmodels.IdsecSIACertificatesUpdateCertificate
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:          "success_update_description",
			certificateID: "cert-123",
			updateData: &certificatesmodels.IdsecSIACertificatesUpdateCertificate{
				CertDescription: "Updated description",
			},
			mockStatusCode: http.StatusOK,
			mockBody:       `{"success": true}`,
			expectedError:  false,
		},
		{
			name:          "success_update_labels",
			certificateID: "cert-123",
			updateData: &certificatesmodels.IdsecSIACertificatesUpdateCertificate{
				Labels: map[string]interface{}{
					"updated": "true",
				},
			},
			mockStatusCode: http.StatusOK,
			mockBody:       `{"success": true}`,
			expectedError:  false,
		},
		{
			name:          "success_update_multiple_fields",
			certificateID: "cert-123",
			updateData: &certificatesmodels.IdsecSIACertificatesUpdateCertificate{
				CertDescription: "New description",
				Labels: map[string]interface{}{
					"environment": "staging",
				},
			},
			mockStatusCode: http.StatusOK,
			mockBody:       `{"success": true}`,
			expectedError:  false,
		},
		{
			name:          "error_not_found",
			certificateID: "nonexistent",
			updateData: &certificatesmodels.IdsecSIACertificatesUpdateCertificate{
				CertDescription: "Updated description",
			},
			mockStatusCode:   http.StatusNotFound,
			mockBody:         `{"error": "certificate not found"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to update certificate",
		},
		{
			name:          "error_bad_request",
			certificateID: "cert-123",
			updateData: &certificatesmodels.IdsecSIACertificatesUpdateCertificate{
				CertDescription: "",
			},
			mockStatusCode:   http.StatusBadRequest,
			mockBody:         `{"error": "invalid update data"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to update certificate",
		},
		{
			name:          "error_unauthorized",
			certificateID: "cert-123",
			updateData: &certificatesmodels.IdsecSIACertificatesUpdateCertificate{
				CertDescription: "Updated description",
			},
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to update certificate",
		},
		{
			name:          "error_conflict",
			certificateID: "cert-123",
			updateData: &certificatesmodels.IdsecSIACertificatesUpdateCertificate{
				CertDescription: "Updated description",
			},
			mockStatusCode:   http.StatusConflict,
			mockBody:         `{"error": "conflict"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to update certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doPut = func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}
			service.doGet = func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
				return NewMockResponse(http.StatusOK, `{"id": "`+tt.certificateID+`"}`), nil
			}

			tt.updateData.CertificateID = tt.certificateID
			_, err := service.UpdateCertificate(tt.updateData)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestDeleteCertificate tests the DeleteCertificate method.
//
// This test validates deletion of a certificate.
// It tests successful deletion and various error conditions.
func TestDeleteCertificate(t *testing.T) {
	tests := []struct {
		name             string
		certificateID    string
		mockStatusCode   int
		mockBody         string
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:           "success_delete_certificate",
			certificateID:  "cert-123",
			mockStatusCode: http.StatusNoContent,
			mockBody:       "",
			expectedError:  false,
		},
		{
			name:             "error_not_found",
			certificateID:    "nonexistent",
			mockStatusCode:   http.StatusNotFound,
			mockBody:         `{"error": "certificate not found"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to delete certificate",
		},
		{
			name:             "error_unauthorized",
			certificateID:    "cert-123",
			mockStatusCode:   http.StatusUnauthorized,
			mockBody:         `{"error": "unauthorized"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to delete certificate",
		},
		{
			name:             "error_forbidden",
			certificateID:    "cert-123",
			mockStatusCode:   http.StatusForbidden,
			mockBody:         `{"error": "forbidden"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to delete certificate",
		},
		{
			name:             "error_conflict_in_use",
			certificateID:    "cert-123",
			mockStatusCode:   http.StatusConflict,
			mockBody:         `{"error": "certificate is in use"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to delete certificate",
		},
		{
			name:             "error_internal_server",
			certificateID:    "cert-123",
			mockStatusCode:   http.StatusInternalServerError,
			mockBody:         `{"error": "internal error"}`,
			expectedError:    true,
			expectedErrorMsg: "failed to delete certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := createTestService()
			service.doDelete = func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error) {
				return NewMockResponse(tt.mockStatusCode, tt.mockBody), nil
			}

			err := service.DeleteCertificate(&certificatesmodels.IdsecSIACertificatesDeleteCertificate{CertificateID: tt.certificateID})

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
					return
				}
				if tt.expectedErrorMsg != "" && len(err.Error()) >= len(tt.expectedErrorMsg) {
					if err.Error()[:len(tt.expectedErrorMsg)] != tt.expectedErrorMsg {
						t.Errorf("Expected error message to contain '%s', got '%s'", tt.expectedErrorMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}
