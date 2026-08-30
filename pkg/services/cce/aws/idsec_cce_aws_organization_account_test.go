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
			ParentOrganizationID: mockOrganizationOnboardingID,
			AccountID:            mockAWSAccountID,
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

	// completedScanTime must be safely AFTER the scanStartTime the code captures inside the call
	// (time.Now() taken just before triggering the scan). We can't predict how long the initial
	// add-account round-trip and client setup take before that point, so use a comfortably large
	// future offset rather than a tight +1s that a slow first request can overrun (which would make
	// scanTime.After(scanStartTime) never true and time out the poll).
	completedScanTime := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
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
			ParentOrganizationID: mockOrganizationOnboardingID,
			AccountID:            mockAWSAccountID,
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

	// completedScanTime must be safely AFTER the scanStartTime the code captures inside the call
	// (time.Now() taken just before it starts polling). Use a comfortably large future offset rather
	// than a tight +1s that a slow first request can overrun (which would make
	// scanTime.After(scanStartTime) never true and time out the poll).
	completedScanTime := time.Now().Add(1 * time.Hour).Format(time.RFC3339Nano)

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
			ParentOrganizationID: mockOrganizationOnboardingID,
			AccountID:            mockAWSAccountID,
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

// Mock account details JSON with organization ID and services
const mockAccountDetailsWithOrgJSON = `{
	"id": "` + mockAccountOnboardingID + `",
	"account_id": "` + mockAWSAccountID + `",
	"organization_id": "` + mockOrganizationOnboardingID + `",
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

// Mock account details JSON with multiple services
const mockAccountDetailsWithMultipleServicesJSON = `{
	"id": "` + mockAccountOnboardingID + `",
	"account_id": "` + mockAWSAccountID + `",
	"organization_id": "` + mockOrganizationOnboardingID + `",
	"onboarding_type": "` + mockOnboardingType + `",
	"services": ["dpa", "sca"],
	"services_data": [
		{
			"name": "dpa",
			"status": "Completely added",
			"errors": []
		},
		{
			"name": "sca",
			"status": "Completely added",
			"errors": []
		}
	],
	"status": "Completely added"
}`

func TestTfUpdateOrganizationAccount_Success(t *testing.T) {
	// Test successful update with new services to add
	getAccountCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// Get account details - returns account with existing "dpa" service
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			// Add services to organization account
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account")
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			// Get updated account details - returns account with both "dpa" and "sca" services
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithMultipleServicesJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
	require.Equal(t, mockAWSAccountID, account.AccountID)
	require.Equal(t, mockOnboardingType, account.OnboardingType)
	require.Contains(t, account.ServiceNames, "dpa")
	require.Contains(t, account.ServiceNames, "sca")
}

func TestTfUpdateOrganizationAccount_NoServicesToAdd(t *testing.T) {
	// Account already has all desired services ("Completely added") and their currently-deployed
	// resources (exposed under "parameters") match the desired resources exactly. Nothing changed,
	// so the SDK must send NO add-account request (unchanged services are omitted).
	accountJSON := `{
		"id": "` + mockAccountOnboardingID + `",
		"account_id": "` + mockAWSAccountID + `",
		"organization_id": "` + mockOrganizationOnboardingID + `",
		"onboarding_type": "` + mockOnboardingType + `",
		"services": ["dpa", "sca"],
		"services_data": [
			{"name": "dpa", "status": "Completely added", "errors": []},
			{"name": "sca", "status": "Completely added", "errors": []}
		],
		"parameters": {
			"dpa": {"DpaRoleArn": "arn:aws:iam::` + mockAWSAccountID + `:role/DpaRole"},
			"sca": {"ScaRoleArn": "arn:aws:iam::` + mockAWSAccountID + `:role/ScaRole"}
		},
		"status": "Completely added"
	}`

	var postCallCount int
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// Add/re-send services - must NOT be called since nothing changed.
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account")
			},
			StatusCode:   http.StatusNoContent,
			ResponseBody: ``,
			OnRequest:    func(r *http.Request) { postCallCount++ },
		},
		{
			// Get account details - returns account with both "dpa" and "sca" services and their params
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID)
			},
			StatusCode:   http.StatusOK,
			ResponseBody: accountJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions - nothing changed, so no add-account request is sent, and the account is returned.
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
	require.Equal(t, mockAWSAccountID, account.AccountID)
	require.Zero(t, postCallCount, "unchanged already-onboarded services must NOT be re-sent")
}

func TestTfUpdateOrganizationAccount_AccountNotFound(t *testing.T) {
	// Test case where account doesn't exist
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID)
			},
			StatusCode: http.StatusNotFound,
			ResponseBody: `{
				"code": "404",
				"message": "Account not found"
			}`,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
			},
		},
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.Error(t, err)
	require.Nil(t, account)
	require.Contains(t, err.Error(), "failed to get account details")
}

func TestTfUpdateOrganizationAccount_AccountNotInOrganization(t *testing.T) {
	// This test verifies that an account without services_data (missing deployment status)
	// will still work correctly by treating all services as needing to be added.
	accountWithoutServicesDataJSON := `{
		"id": "` + mockAccountOnboardingID + `",
		"account_id": "` + mockAWSAccountID + `",
		"onboarding_type": "` + mockOnboardingType + `",
		"services": ["dpa"],
		"status": "Completely added"
	}`

	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: accountWithoutServicesDataJSON,
			OnRequest: func(r *http.Request) {
				getCallCount++
			},
		},
		{
			// POST to add services (since services_data is missing, dpa is not considered fully deployed)
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account")
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
		},
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
}

func TestTfUpdateOrganizationAccount_FailedToAddServices(t *testing.T) {
	// Test case where adding services fails
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID)
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account")
			},
			StatusCode: http.StatusBadRequest,
			ResponseBody: `{
				"code": "400",
				"message": "Invalid service configuration"
			}`,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.Error(t, err)
	require.Nil(t, account)
	require.Contains(t, err.Error(), "failed to add services to organization account")
}

func TestTfUpdateOrganizationAccount_FailedToFetchUpdatedAccount(t *testing.T) {
	// Test case where adding services succeeds but fetching updated account fails
	getAccountCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// First GET - get account details
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account")
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			// Second GET - fetch updated account (fails)
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode: http.StatusInternalServerError,
			ResponseBody: `{
				"code": "500",
				"message": "Internal server error"
			}`,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.Error(t, err)
	require.Nil(t, account)
	require.Contains(t, err.Error(), "failed to fetch updated account details")
}

func TestTfUpdateOrganizationAccount_WithServiceParameters(t *testing.T) {
	// Test case with service parameters
	getAccountCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					// Verify request body contains serviceParameters
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					bodyStr := string(bodyBytes)
					require.Contains(t, bodyStr, "serviceParameters", "Expected serviceParameters in request body")
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithMultipleServicesJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	serviceParameters := map[string]map[string]interface{}{
		"sca": {
			"region": "us-east-1",
		},
	}

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
		ServiceParameters: serviceParameters,
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
}

func TestTfUpdateOrganizationAccount_ServiceStatusHandling(t *testing.T) {
	// Settled services are (re)sent so in-place resource changes reach the API's idempotent
	// resource diff: "Completely added" and "Waiting for deployment" services are both
	// included. Only services in a transient/mid-operation status (like "In progress") are
	// skipped, to avoid the API rejecting the request while the service is still processing.
	accountWithMixedServiceStatusesJSON := `{
		"id": "` + mockAccountOnboardingID + `",
		"account_id": "` + mockAWSAccountID + `",
		"organization_id": "` + mockOrganizationOnboardingID + `",
		"onboarding_type": "` + mockOnboardingType + `",
		"services": ["dpa", "sca", "secrets_hub"],
		"services_data": [
			{
				"name": "dpa",
				"status": "Completely added",
				"errors": []
			},
			{
				"name": "sca",
				"status": "Waiting for deployment",
				"errors": []
			},
			{
				"name": "secrets_hub",
				"status": "In progress",
				"errors": []
			}
		],
		"status": "Partially added"
	}`

	getAccountCallCount := 0
	postCallCount := 0
	var capturedPostBody string

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// First GET - returns account with mixed service statuses
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: accountWithMixedServiceStatusesJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			// POST to add/re-send services - should include DPA ("Completely added") and SCA
			// ("Waiting for deployment"), but NOT secrets_hub ("In progress").
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					// Capture request body to verify which services are being added
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					capturedPostBody = string(bodyBytes)
					postCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			// Second GET - returns account with all services fully deployed
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"id": "` + mockAccountOnboardingID + `",
				"account_id": "` + mockAWSAccountID + `",
				"organization_id": "` + mockOrganizationOnboardingID + `",
				"onboarding_type": "` + mockOnboardingType + `",
				"services": ["dpa", "sca", "secrets_hub"],
				"services_data": [
					{
						"name": "dpa",
						"status": "Completely added",
						"errors": []
					},
					{
						"name": "sca",
						"status": "Completely added",
						"errors": []
					},
					{
						"name": "secrets_hub",
						"status": "Completely added",
						"errors": []
					}
				],
				"status": "Completely added"
			}`,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
			{
				ServiceName: ccemodels.SecretsHub,
				Resources: map[string]interface{}{
					"SecretsHubRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/SecretsHubRole",
				},
			},
		},
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
	require.Equal(t, mockAWSAccountID, account.AccountID)

	// Verify POST was called (settled services need to be (re)sent)
	require.Equal(t, 1, postCallCount, "Expected POST to be called once")

	// Verify the POST body contains DPA and SCA but NOT secrets_hub:
	// - DPA ("Completely added") is re-sent so any resources change reaches the API's diff
	// - SCA ("Waiting for deployment") is re-sent
	// - SecretsHub ("In progress") is skipped to avoid interfering with its in-flight deployment
	require.Contains(t, capturedPostBody, `"serviceName":"dpa"`, "DPA should be in POST body (re-sent so resource changes apply)")
	require.Contains(t, capturedPostBody, `"serviceName":"sca"`, "SCA should be in POST body (status: 'Waiting for deployment')")
	require.NotContains(t, capturedPostBody, `"serviceName":"secrets_hub"`, "SecretsHub should NOT be in POST body (status: 'In progress')")
}

func TestTfUpdateOrganizationAccount_AllServicesWaitingForDeployment(t *testing.T) {
	// Test case where all services exist but none are "Completely added"
	// All services should be re-added via POST
	accountWithAllServicesWaitingJSON := `{
		"id": "` + mockAccountOnboardingID + `",
		"account_id": "` + mockAWSAccountID + `",
		"organization_id": "` + mockOrganizationOnboardingID + `",
		"onboarding_type": "` + mockOnboardingType + `",
		"services": ["dpa", "sca"],
		"services_data": [
			{
				"name": "dpa",
				"status": "Waiting for deployment",
				"errors": []
			},
			{
				"name": "sca",
				"status": "Waiting for deployment",
				"errors": []
			}
		],
		"status": "Waiting for deployment"
	}`

	getAccountCallCount := 0
	postCallCount := 0
	var capturedPostBody string

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: accountWithAllServicesWaitingJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					capturedPostBody = string(bodyBytes)
					postCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithMultipleServicesJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, 1, postCallCount, "Expected POST to be called (all services waiting for deployment)")

	// Verify both services are in the POST body (both need re-addition)
	require.Contains(t, capturedPostBody, `"serviceName":"dpa"`, "DPA should be in POST body")
	require.Contains(t, capturedPostBody, `"serviceName":"sca"`, "SCA should be in POST body")
}

// TestTfUpdateOrganizationAccount_ResendsFullyDeployedServiceOnResourceChange is a regression
// guard for the "silent no-op on resource change" bug on organization member accounts. The SDK
// used to skip fully-deployed services entirely, so changing an already-deployed service's
// resources produced a green apply with no API call. The update must now re-send fully-deployed
// services (carrying their new resources) to the organization add-account endpoint, which diffs
// resources server-side and applies the change.
func TestTfUpdateOrganizationAccount_ResendsFullyDeployedServiceOnResourceChange(t *testing.T) {
	getAccountCallCount := 0
	var capturedPostBody string
	var postCallCount int

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// First GET - account with DPA already "Completely added"
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					capturedPostBody = string(bodyBytes)
					postCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					// A changed role ARN for the already-deployed DPA service.
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRoleUPDATED",
				},
			},
		},
	}

	account, err := service.TfUpdateOrganizationAccount(input)

	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, 1, postCallCount, "a resources change on a fully-deployed service must trigger the add-account call")
	require.Contains(t, capturedPostBody, `"serviceName":"dpa"`, "the fully-deployed service must be re-sent")
	require.Contains(t, capturedPostBody, "DpaRoleUPDATED", "the re-sent service must carry the new resources")
}
