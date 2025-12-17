package aws

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	awsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/aws/models"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

const (
	// mockAWSAccountID is the test AWS account ID (12 digits) used across all mock responses
	mockAWSAccountID = "123456789012"
	// mockOrganizationOnboardingID is the test organization onboarding ID used across all mock responses
	mockOrganizationOnboardingID = "0000aaaa0000bbbb0000cccc0000dddd"
	// mockAccountOnboardingID is the test account onboarding ID used across all mock responses
	mockAccountOnboardingID = "aaaa1111bbbb2222cccc3333dddd4444"
	// mockOnboardingType is the onboarding type used across all mock responses
	mockOnboardingType = ccemodels.TerraformProvider
	// mockAddAccountResponseJSON represents the response when adding an account to an organization
	mockAddAccountResponseJSON = `{"id": "` + mockAccountOnboardingID + `"}`
	// mockAccountDetailsJSON represents a successful account onboarding response
	mockAccountDetailsJSON = `{
		"id": "` + mockAccountOnboardingID + `",
		"account_id": "` + mockAWSAccountID + `",
		"onboarding_type": "` + mockOnboardingType + `",
		"services": ["dpa"],
		"services_data": [
			{
				"name": "dpa",
				"status": "Completely added",
				"errors": []
			}
		],
		"status": "Completely added"
	}`
)

func TestScanOrganization_Success(t *testing.T) {
	// ScanOrganization returns empty response
	responseJSON := `{}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/organizations/scan")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call ScanOrganization
	result, err := service.ScanOrganization(&awsmodels.IdsecCCEAWSScanOrganization{})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestScanOrganization_ScanInProgress(t *testing.T) {
	// Mock 409 Conflict response
	responseJSON := `{
		"code": "409",
		"message": "Conflict",
		"description": "A scan is already in progress for the tenant at AWS"
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/organizations/scan")
			},
			StatusCode:   http.StatusConflict,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call ScanOrganization
	result, err := service.ScanOrganization(&awsmodels.IdsecCCEAWSScanOrganization{})

	// Assertions
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "failed to trigger organization scan")
}

func TestScanOrganization_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAWSService(client)
		_, err := service.ScanOrganization(&awsmodels.IdsecCCEAWSScanOrganization{})
		return err
	})
}

func TestAddOrganizationAccountSync_Success(t *testing.T) {
	// Sync version - returns full account details

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/") && strings.Contains(r.URL.Path, "/account")
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: mockAddAccountResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID)
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Create input with sync struct
	input := &awsmodels.IdsecCCEAWSAddOrganizationAccountSync{
		IdsecCCEAWSAddOrganizationAccount: awsmodels.IdsecCCEAWSAddOrganizationAccount{
			OrganizationID: mockOrganizationOnboardingID,
			AccountID:      mockAWSAccountID,
			Services: []ccemodels.IdsecCCEServiceInput{
				{
					ServiceName: ccemodels.DPA,
					Resources: map[string]interface{}{
						"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
					},
				},
			},
		},
	}

	// Call AddOrganizationAccountSync
	account, err := service.TfAddOrganizationAccountSync(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
	require.Equal(t, mockAWSAccountID, account.AccountID)
	require.Equal(t, mockOnboardingType, account.OnboardingType)
}

func TestAddOrganizationAccountSync_With404AndQuickRetry(t *testing.T) {
	// Test the retry logic with fast intervals
	// This test verifies that the sync function polls Organization endpoint for scan completion

	// Use a recent timestamp for the completed scan
	completedScanTime := time.Now().Add(1 * time.Second).Format(time.RFC3339)
	oldScanTime := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)

	addAccountCallCount := 0
	scanCallCount := 0
	orgCallCount := 0

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// Scan endpoint - called once
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/organizations/scan") {
					// Validate request body contains correct AWS organization ID
					bodyBytes, _ := io.ReadAll(r.Body)
					// Restore body for subsequent reads
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					bodyStr := string(bodyBytes)
					// Verify the AWS organization ID (o-123) is passed, not the onboarding ID
					require.Contains(t, bodyStr, `"organizationId":"o-123"`, "Expected scan to be triggered with AWS organization ID 'o-123'")
					return true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				scanCallCount++
			},
		},
		{
			// Organization endpoint - first call returns old timestamp, second returns new
			Matcher: func(r *http.Request) bool {
				if r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID) &&
					!strings.Contains(r.URL.Path, "/account") {
					orgCallCount++
					return orgCallCount == 1
				}
				return false
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"id": "org-123",
				"managementAccountId": "` + mockAWSAccountID + `",
				"organizationId": "o-123",
				"onboardingType": "` + mockOnboardingType + `",
				"lastSuccessfulScan": "` + oldScanTime + `"
			}`,
		},
		{
			// Organization endpoint - subsequent calls return completed scan timestamp
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID) &&
					!strings.Contains(r.URL.Path, "/account") && orgCallCount >= 2
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"id": "org-123",
				"managementAccountId": "` + mockAWSAccountID + `",
				"organizationId": "o-123",
				"onboardingType": "` + mockOnboardingType + `",
				"lastSuccessfulScan": "` + completedScanTime + `"
			}`,
		},
		{
			// First call to add account - returns 404
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/") && strings.Contains(r.URL.Path, "/account") {
					addAccountCallCount++
					return addAccountCallCount == 1
				}
				return false
			},
			StatusCode: http.StatusNotFound,
			ResponseBody: `{
				"code": "404",
				"message": "Account not found"
			}`,
		},
		{
			// Second call to add account - returns success
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/") &&
					strings.Contains(r.URL.Path, "/account") && addAccountCallCount >= 2
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: mockAddAccountResponseJSON,
		},
		{
			// Get account details
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID)
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Configure fast retries for testing (no delay between retries)
	maxRetries := 5
	retryIntervalSeconds := 0

	input := &awsmodels.IdsecCCEAWSAddOrganizationAccountSync{
		IdsecCCEAWSAddOrganizationAccount: awsmodels.IdsecCCEAWSAddOrganizationAccount{
			OrganizationID: mockOrganizationOnboardingID,
			AccountID:      mockAWSAccountID,
			Services: []ccemodels.IdsecCCEServiceInput{
				{
					ServiceName: ccemodels.DPA,
					Resources: map[string]interface{}{
						"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
					},
				},
			},
		},
		ScanProbeMaxRetries:      &maxRetries,
		ScanProbeIntervalSeconds: &retryIntervalSeconds,
	}

	// Call AddOrganizationAccountSync
	account, err := service.TfAddOrganizationAccountSync(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
	require.Equal(t, mockAWSAccountID, account.AccountID)
	require.Equal(t, mockOnboardingType, account.OnboardingType)
	// Verify the flow: scan called once, organization polled multiple times, account added twice
	require.Equal(t, 1, scanCallCount, "Expected exactly 1 scan call")
	require.GreaterOrEqual(t, orgCallCount, 2, "Expected at least 2 organization polls")
	require.Equal(t, 2, addAccountCallCount, "Expected 2 calls to add account (first 404, second success)")
}

func TestAddOrganizationAccountSync_With400ScanInProgress(t *testing.T) {
	// Test handling of 400 "scan is in progress" error
	// This test verifies that when we get 400 scan-in-progress, we poll without triggering a new scan

	// Use a recent timestamp for the completed scan
	completedScanTime := time.Now().Add(1 * time.Second).Format(time.RFC3339Nano)

	addAccountCallCount := 0
	scanCallCount := 0
	orgCallCount := 0

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// Scan endpoint - should NOT be called for 400 error
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/organizations/scan")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				scanCallCount++
			},
		},
		{
			// Organization endpoint - returns completed scan timestamp
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID) &&
					!strings.Contains(r.URL.Path, "/account")
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"id": "org-123",
				"managementAccountId": "` + mockAWSAccountID + `",
				"organizationId": "o-123",
				"onboardingType": "` + mockOnboardingType + `",
				"lastSuccessfulScan": "` + completedScanTime + `"
			}`,
			OnRequest: func(r *http.Request) {
				orgCallCount++
			},
		},
		{
			// First call to add account - returns 400 "scan is in progress"
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/") && strings.Contains(r.URL.Path, "/account") {
					addAccountCallCount++
					return addAccountCallCount == 1
				}
				return false
			},
			StatusCode: http.StatusBadRequest,
			ResponseBody: `{
				"app_error_code": "SCAN_IN_PROGRESS",
				"attributes": null,
				"code": "400",
				"description": "scan is in progress, wait for it to finish before onboarding an account resources to organization",
				"message": "Bad Request"
			}`,
		},
		{
			// Second call to add account - returns success
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/") &&
					strings.Contains(r.URL.Path, "/account") && addAccountCallCount >= 2
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: mockAddAccountResponseJSON,
		},
		{
			// Get account details
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID)
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Configure fast retries for testing (no delay between retries)
	maxRetries := 5
	retryIntervalSeconds := 0

	input := &awsmodels.IdsecCCEAWSAddOrganizationAccountSync{
		IdsecCCEAWSAddOrganizationAccount: awsmodels.IdsecCCEAWSAddOrganizationAccount{
			OrganizationID: mockOrganizationOnboardingID,
			AccountID:      mockAWSAccountID,
			Services: []ccemodels.IdsecCCEServiceInput{
				{
					ServiceName: ccemodels.DPA,
					Resources: map[string]interface{}{
						"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
					},
				},
			},
		},
		ScanProbeMaxRetries:      &maxRetries,
		ScanProbeIntervalSeconds: &retryIntervalSeconds,
	}

	// Call AddOrganizationAccountSync
	account, err := service.TfAddOrganizationAccountSync(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
	require.Equal(t, mockAWSAccountID, account.AccountID)
	require.Equal(t, mockOnboardingType, account.OnboardingType)
	// Verify the flow: NO scan call, organization polled at least once, account added twice
	require.Equal(t, 0, scanCallCount, "Expected NO scan calls (scan already in progress)")
	require.GreaterOrEqual(t, orgCallCount, 1, "Expected at least 1 organization poll")
	require.Equal(t, 2, addAccountCallCount, "Expected 2 calls to add account (first 400, second success)")
}
