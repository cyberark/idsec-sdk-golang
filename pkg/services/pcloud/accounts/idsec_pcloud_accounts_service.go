package accounts

import (
	"context"
	"fmt"
	"os"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/pagination"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
	commonpcloud "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/common"

	"io"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// API endpoint paths for account-related operations
const (
	accountsURL                        = "/PasswordVault/api/accounts"
	accountURL                         = "/PasswordVault/api/accounts/%s/"
	accountURLOld                      = "/PasswordVault/WebServices/PIMServices.svc/Accounts/%s/"
	accountSecretVersionsURL           = "/PasswordVault/api/accounts/%s/secret/versions"   // #nosec G101
	generateAccountCredentialsURL      = "/PasswordVault/api/accounts/%s/secret/generate"   // #nosec G101
	verifyAccountCredentialsURL        = "/PasswordVault/api/accounts/%s/verify"            // #nosec G101
	changeAccountCredentialsURL        = "/PasswordVault/api/accounts/%s/change"            // #nosec G101
	setAccountNextCredentialsURL       = "/PasswordVault/api/accounts/%s/setnextpassword"   // #nosec G101
	updateAccountCredentialsInVaultURL = "/PasswordVault/api/accounts/%s/password/update"   // #nosec G101
	retrieveAccountCredentialsURL      = "/PasswordVault/api/accounts/%s/password/retrieve" // #nosec G101
	reconcileAccountCredentialsURL     = "/PasswordVault/api/accounts/%s/reconcile"         // #nosec G101
	linkAccountURL                     = "/PasswordVault/api/accounts/%s/linkaccount"
	unlinkAccountURL                   = "/PasswordVault/api/accounts/%s/linkaccount/%s/"
	accountActivitiesURL               = "/api/accounts/%s/activities"
	complianceInfoURL                  = "/api/rotation/accounts/%s/compliance-info"
	accountOverviewURL                 = "/PasswordVault/api/ExtendedAccounts/%s/overview"
)

// IdsecPCloudAccountsPage is a paginated type for IdsecPCloudAccount
type IdsecPCloudAccountsPage = common.IdsecPage[accountsmodels.IdsecPCloudAccount]

// IdsecPCloudAccountsService is the service for managing pCloud Accounts.
type IdsecPCloudAccountsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecPCloudAccountsService creates a new instance of IdsecPCloudAccountsService.
func NewIdsecPCloudAccountsService(authenticators ...auth.IdsecAuth) (*IdsecPCloudAccountsService, error) {
	pcloudAccountsService := &IdsecPCloudAccountsService{}
	var pcloudAccountsServiceInterface services.IdsecService = pcloudAccountsService
	baseService, err := services.NewIdsecBaseService(pcloudAccountsServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseServiceWithRetry(
		ispAuth,
		"privilegecloud",
		".",
		"",
		pcloudAccountsService.refreshPCloudAccountsAuth,
		commonpcloud.DefaultPCloudRetryStrategy(),
	)
	if err != nil {
		return nil, err
	}

	pcloudAccountsService.IdsecBaseService = baseService
	pcloudAccountsService.IdsecISPBaseService = ispBaseService
	return pcloudAccountsService, nil
}

func (s *IdsecPCloudAccountsService) refreshPCloudAccountsAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

// normalizeAccountItemMap maps API account JSON fields to IdsecPCloudAccount mapstructure keys.
func normalizeAccountItemMap(accountMap map[string]interface{}) error {
	if accountID, ok := accountMap["id"]; ok {
		accountMap["account_id"] = accountID
	}
	if userName, ok := accountMap["user_name"]; ok {
		accountMap["username"] = userName
	}
	if secretManagement, ok := accountMap["secret_management"]; ok {
		secretManagementMap, ok := secretManagement.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid secret_management format")
		}
		if manualManagementReason, ok := secretManagementMap["manual_management_reason"]; ok {
			accountMap["manual_management_reason"] = manualManagementReason
		}
		if automaticManagementEnabled, ok := secretManagementMap["automatic_management_enabled"]; ok {
			accountMap["automatic_management_enabled"] = automaticManagementEnabled
		}
		if lastModifiedTime, ok := secretManagementMap["last_modified_time"]; ok {
			accountMap["last_modified_time"] = lastModifiedTime
		}
	}
	if remoteMachinesAccess, ok := accountMap["remote_machines_access"]; ok {
		remoteMachinesAccessMap, ok := remoteMachinesAccess.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid remote_machines_access format")
		}
		if accessRestrictedToRemoteMachines, ok := remoteMachinesAccessMap["access_restricted_to_remote_machines"]; ok {
			accountMap["access_restricted_to_remote_machines"] = accessRestrictedToRemoteMachines
		}
		if remoteMachines, ok := remoteMachinesAccessMap["remote_machines"]; ok {
			remoteMachinesString, ok := remoteMachines.(string)
			if !ok {
				return fmt.Errorf("invalid remote_machines format")
			}
			accountMap["remote_machines"] = strings.Split(remoteMachinesString, ";")
		}
	}
	return nil
}

func decodeAccountsFromListJSON(accountsJSON []interface{}) ([]*accountsmodels.IdsecPCloudAccount, error) {
	for i, account := range accountsJSON {
		if accountMap, ok := account.(map[string]interface{}); ok {
			if err := normalizeAccountItemMap(accountMap); err != nil {
				return nil, err
			}
			accountsJSON[i] = accountMap
		}
	}
	var accounts []*accountsmodels.IdsecPCloudAccount
	if err := mapstructure.Decode(accountsJSON, &accounts); err != nil {
		return nil, err
	}
	return accounts, nil
}

// decodeAccountsFromResultMap decodes one page of the OData-style accounts list response.
func decodeAccountsFromResultMap(resultMap map[string]interface{}) ([]*accountsmodels.IdsecPCloudAccount, error) {
	accountsJSON, err := pagination.ExtractItemsFromResult(resultMap, "accounts")
	if err != nil {
		return nil, err
	}
	return decodeAccountsFromListJSON(accountsJSON)
}

func (s *IdsecPCloudAccountsService) listAccountsWithFilters(
	ctx context.Context,
	search string,
	searchType string,
	sort string,
	offset int,
	limit int,
	safeName string,
) (<-chan *IdsecPCloudAccountsPage, error) {
	initialQuery := map[string]string{}
	if search != "" {
		initialQuery["search"] = search
	}
	if searchType != "" {
		initialQuery["searchType"] = searchType
	}
	if sort != "" {
		initialQuery["sort"] = sort
	}
	if offset > 0 {
		initialQuery["offset"] = fmt.Sprintf("%d", offset)
	}
	if limit > 0 {
		initialQuery["limit"] = fmt.Sprintf("%d", limit)
	}
	if safeName != "" {
		initialQuery["filter"] = fmt.Sprintf("safeName eq %s", safeName)
	}
	return pagination.ListAllPaginated[accountsmodels.IdsecPCloudAccount](
		ctx,
		pagination.HTTPGetFetch(s.ISPClient(), accountsURL, initialQuery),
		pagination.ListPaginatedConfig[accountsmodels.IdsecPCloudAccount]{
			ResourceName: "accounts",
			Decode:       decodeAccountsFromResultMap,
		},
	)
}

// List retrieves a list of IdsecPCloudAccount pages.
// On failure, returns a non-nil error and a nil channel. On success, returns a channel that yields the pages.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/GetAccounts.htm
func (s *IdsecPCloudAccountsService) List() (<-chan *IdsecPCloudAccountsPage, error) {
	return s.ListContext(context.Background())
}

// ListContext is like List but accepts a context.Context. Callers that stop iterating the
// returned channel early must cancel the context to release the producer goroutine and any
// in-flight request.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/GetAccounts.htm
func (s *IdsecPCloudAccountsService) ListContext(ctx context.Context) (<-chan *IdsecPCloudAccountsPage, error) {
	return s.listAccountsWithFilters(
		ctx,
		"",
		"",
		"",
		0,
		0,
		"",
	)
}

// ListBy retrieves a list of IdsecPCloudAccount pages with filters.
// On failure, returns a non-nil error and a nil channel. On success, returns a channel that yields the pages.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/GetAccounts.htm
func (s *IdsecPCloudAccountsService) ListBy(accountsFilters *accountsmodels.IdsecPCloudAccountsFilter) (<-chan *IdsecPCloudAccountsPage, error) {
	return s.ListByContext(context.Background(), accountsFilters)
}

// ListByContext is like ListBy but accepts a context.Context. Callers that stop iterating the
// returned channel early must cancel the context to release the producer goroutine and any
// in-flight request.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/GetAccounts.htm
func (s *IdsecPCloudAccountsService) ListByContext(ctx context.Context, accountsFilters *accountsmodels.IdsecPCloudAccountsFilter) (<-chan *IdsecPCloudAccountsPage, error) {
	return s.listAccountsWithFilters(
		ctx,
		accountsFilters.Search,
		accountsFilters.SearchType,
		accountsFilters.Sort,
		accountsFilters.Offset,
		accountsFilters.Limit,
		accountsFilters.SafeName,
	)
}

// ListSecretVersions retrieves a list of IdsecPCloudAccountSecretVersion.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Secrets-Get-versions.htm
func (s *IdsecPCloudAccountsService) ListSecretVersions(listAccountSecretVersions *accountsmodels.IdsecPCloudListAccountSecretVersions) ([]*accountsmodels.IdsecPCloudAccountSecretVersion, error) {
	s.Logger.Info("Retrieving account secret versions [%s]", listAccountSecretVersions.AccountID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(accountSecretVersionsURL, listAccountSecretVersions.AccountID), nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get account secret versions - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	accountsSecretVersionsJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	accountsSecretVersionsJSONMap := accountsSecretVersionsJSON.(map[string]interface{})
	var accountSecretVersions []*accountsmodels.IdsecPCloudAccountSecretVersion
	err = mapstructure.Decode(accountsSecretVersionsJSONMap["versions"], &accountSecretVersions)
	if err != nil {
		return nil, err
	}
	return accountSecretVersions, nil
}

// ListActivities retrieves the activities performed on an account.
// https://docs.cyberark.com/privilege-cloud-standard/latest/en/content/sdk/files%20-%20get%20file%20activity%20by%20id.htm
func (s *IdsecPCloudAccountsService) ListActivities(listAccountActivities *accountsmodels.IdsecPCloudListAccountActivities) ([]*accountsmodels.IdsecPCloudAccountActivity, error) {
	s.Logger.Info("Retrieving account activities [%s]", listAccountActivities.AccountID)
	safeName := listAccountActivities.SafeName
	if safeName == "" {
		account, err := s.Get(&accountsmodels.IdsecPCloudGetAccount{AccountID: listAccountActivities.AccountID})
		if err != nil {
			return nil, err
		}
		safeName = account.SafeName
	}
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(accountActivitiesURL, listAccountActivities.AccountID), map[string]string{"safeName": safeName})
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve account activities - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	accountActivitiesJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	accountActivitiesJSONMap, ok := accountActivitiesJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to list account activities: unexpected result")
	}
	raw := accountActivitiesJSONMap["activities"]
	if raw == nil {
		raw = accountActivitiesJSONMap["data"]
	}
	var accountActivities []*accountsmodels.IdsecPCloudAccountActivity
	if err = mapstructure.Decode(raw, &accountActivities); err != nil {
		return nil, err
	}
	if accountActivities == nil {
		accountActivities = []*accountsmodels.IdsecPCloudAccountActivity{}
	}
	return accountActivities, nil
}

// ListActivitiesBy retrieves the activities of an account, filtered by the given criteria.
// The underlying API does not support server-side filtering, so filtering is done client-side.
// https://docs.cyberark.com/privilege-cloud-standard/latest/en/content/sdk/files%20-%20get%20file%20activity%20by%20id.htm
func (s *IdsecPCloudAccountsService) ListActivitiesBy(activitiesFilter *accountsmodels.IdsecPCloudAccountActivitiesFilter) ([]*accountsmodels.IdsecPCloudAccountActivity, error) {
	activities, err := s.ListActivities(&accountsmodels.IdsecPCloudListAccountActivities{AccountID: activitiesFilter.AccountID, SafeName: activitiesFilter.SafeName})
	if err != nil {
		return nil, err
	}
	filteredActivities := make([]*accountsmodels.IdsecPCloudAccountActivity, 0, len(activities))
	for _, activity := range activities {
		if activitiesFilter.User != "" && activity.User != activitiesFilter.User {
			continue
		}
		if activitiesFilter.ActionContains != "" && !strings.Contains(activity.Action, activitiesFilter.ActionContains) {
			continue
		}
		if activitiesFilter.ClientID != "" && activity.ClientID != activitiesFilter.ClientID {
			continue
		}
		if activitiesFilter.AlertsOnly && !activity.Alert {
			continue
		}
		if activitiesFilter.FromDate != 0 && activity.Date < activitiesFilter.FromDate {
			continue
		}
		if activitiesFilter.ToDate != 0 && activity.Date > activitiesFilter.ToDate {
			continue
		}
		filteredActivities = append(filteredActivities, activity)
	}
	return filteredActivities, nil
}

// GetComplianceInfo retrieves the compliance info of an account.
func (s *IdsecPCloudAccountsService) GetComplianceInfo(getAccountComplianceInfo *accountsmodels.IdsecPCloudGetAccountComplianceInfo) (*accountsmodels.IdsecPCloudAccountComplianceInfo, error) {
	s.Logger.Info("Retrieving account compliance info [%s]", getAccountComplianceInfo.AccountID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(complianceInfoURL, getAccountComplianceInfo.AccountID), nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve account compliance info - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	complianceInfoJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	complianceInfoJSONMap, ok := complianceInfoJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to retrieve account compliance info: unexpected result")
	}
	var complianceInfo accountsmodels.IdsecPCloudAccountComplianceInfo
	err = mapstructure.Decode(complianceInfoJSONMap, &complianceInfo)
	if err != nil {
		return nil, err
	}
	return &complianceInfo, nil
}

// GetOverview retrieves the overview of an account.
func (s *IdsecPCloudAccountsService) GetOverview(getAccountOverview *accountsmodels.IdsecPCloudGetAccountOverview) (*accountsmodels.IdsecPCloudAccountOverview, error) {
	s.Logger.Info("Retrieving account overview [%s]", getAccountOverview.AccountID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(accountOverviewURL, getAccountOverview.AccountID), nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve account overview - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	overviewJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	overviewJSONMap, ok := overviewJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to retrieve account overview: unexpected result")
	}
	var overview accountsmodels.IdsecPCloudAccountOverview
	err = mapstructure.Decode(overviewJSONMap, &overview)
	if err != nil {
		return nil, err
	}
	return &overview, nil
}

// defaultBulkMaxConcurrency is the number of accounts processed concurrently when no explicit limit is provided.
const defaultBulkMaxConcurrency = 32

// bulkFetchResult holds the outcome of a single per-account fetch in a bulk operation.
type bulkFetchResult[T any] struct {
	value T
	err   error
}

// runBulkAccountFetch runs fetch for each account ID concurrently using a bounded worker pool.
// Results are returned in the same order as accountIDs.
func runBulkAccountFetch[T any](accountIDs []string, maxConcurrency int, fetch func(accountID string) (T, error)) []bulkFetchResult[T] {
	results := make([]bulkFetchResult[T], len(accountIDs))
	if len(accountIDs) == 0 {
		return results
	}
	if maxConcurrency <= 0 {
		maxConcurrency = defaultBulkMaxConcurrency
	}
	if maxConcurrency > len(accountIDs) {
		maxConcurrency = len(accountIDs)
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < maxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				value, err := fetch(accountIDs[idx])
				results[idx] = bulkFetchResult[T]{value: value, err: err}
			}
		}()
	}
	for i := range accountIDs {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

// BulkGetComplianceInfo retrieves the compliance info of multiple accounts in parallel.
// Failures for individual accounts are reported per-result and do not fail the whole operation.
func (s *IdsecPCloudAccountsService) BulkGetComplianceInfo(bulkGetAccounts *accountsmodels.IdsecPCloudBulkGetAccountComplianceInfo) ([]*accountsmodels.IdsecPCloudBulkAccountComplianceInfoResult, error) {
	if len(bulkGetAccounts.AccountIDs) == 0 {
		return nil, fmt.Errorf("at least one account ID is required")
	}
	s.Logger.Info("Bulk retrieving compliance info for [%d] accounts", len(bulkGetAccounts.AccountIDs))
	fetched := runBulkAccountFetch(bulkGetAccounts.AccountIDs, bulkGetAccounts.MaxConcurrency, func(accountID string) (*accountsmodels.IdsecPCloudAccountComplianceInfo, error) {
		return s.GetComplianceInfo(&accountsmodels.IdsecPCloudGetAccountComplianceInfo{AccountID: accountID})
	})
	results := make([]*accountsmodels.IdsecPCloudBulkAccountComplianceInfoResult, len(fetched))
	for i, item := range fetched {
		result := &accountsmodels.IdsecPCloudBulkAccountComplianceInfoResult{
			AccountID:      bulkGetAccounts.AccountIDs[i],
			ComplianceInfo: item.value,
		}
		if item.err != nil {
			result.Error = item.err.Error()
		}
		results[i] = result
	}
	return results, nil
}

// BulkGetOverview retrieves the overview of multiple accounts in parallel.
// Failures for individual accounts are reported per-result and do not fail the whole operation.
func (s *IdsecPCloudAccountsService) BulkGetOverview(bulkGetAccounts *accountsmodels.IdsecPCloudBulkGetAccountOverview) ([]*accountsmodels.IdsecPCloudBulkAccountOverviewResult, error) {
	if len(bulkGetAccounts.AccountIDs) == 0 {
		return nil, fmt.Errorf("at least one account ID is required")
	}
	s.Logger.Info("Bulk retrieving overview for [%d] accounts", len(bulkGetAccounts.AccountIDs))
	fetched := runBulkAccountFetch(bulkGetAccounts.AccountIDs, bulkGetAccounts.MaxConcurrency, func(accountID string) (*accountsmodels.IdsecPCloudAccountOverview, error) {
		return s.GetOverview(&accountsmodels.IdsecPCloudGetAccountOverview{AccountID: accountID})
	})
	results := make([]*accountsmodels.IdsecPCloudBulkAccountOverviewResult, len(fetched))
	for i, item := range fetched {
		result := &accountsmodels.IdsecPCloudBulkAccountOverviewResult{
			AccountID: bulkGetAccounts.AccountIDs[i],
			Overview:  item.value,
		}
		if item.err != nil {
			result.Error = item.err.Error()
		}
		results[i] = result
	}
	return results, nil
}

// BulkListActivities retrieves the activities of multiple accounts in parallel.
// Failures for individual accounts are reported per-result and do not fail the whole operation.
func (s *IdsecPCloudAccountsService) BulkListActivities(bulkListAccounts *accountsmodels.IdsecPCloudBulkListAccountActivities) ([]*accountsmodels.IdsecPCloudBulkAccountActivitiesResult, error) {
	if len(bulkListAccounts.AccountIDs) == 0 {
		return nil, fmt.Errorf("at least one account ID is required")
	}
	s.Logger.Info("Bulk retrieving activities for [%d] accounts", len(bulkListAccounts.AccountIDs))
	fetched := runBulkAccountFetch(bulkListAccounts.AccountIDs, bulkListAccounts.MaxConcurrency, func(accountID string) ([]*accountsmodels.IdsecPCloudAccountActivity, error) {
		return s.ListActivities(&accountsmodels.IdsecPCloudListAccountActivities{AccountID: accountID, SafeName: bulkListAccounts.SafeName})
	})
	results := make([]*accountsmodels.IdsecPCloudBulkAccountActivitiesResult, len(fetched))
	for i, item := range fetched {
		result := &accountsmodels.IdsecPCloudBulkAccountActivitiesResult{
			AccountID:  bulkListAccounts.AccountIDs[i],
			Activities: item.value,
		}
		if item.err != nil {
			result.Error = item.err.Error()
		}
		results[i] = result
	}
	return results, nil
}

// GenerateCredentials generate a new random password for an existing account with policy restrictions.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Secrets-Generate-Password.htm
func (s *IdsecPCloudAccountsService) GenerateCredentials(generateAccountCredentials *accountsmodels.IdsecPCloudGenerateAccountCredentials) (*accountsmodels.IdsecPCloudAccountCredentials, error) {
	s.Logger.Info("Generating account credentials [%s]", generateAccountCredentials.AccountID)
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(generateAccountCredentialsURL, generateAccountCredentials.AccountID), nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to generate account credentials - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	accountSecretJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	accountSecretJSONMap := accountSecretJSON.(map[string]interface{})
	var accountSecret accountsmodels.IdsecPCloudAccountCredentials
	err = mapstructure.Decode(accountSecretJSONMap["password"], &accountSecret)
	if err != nil {
		return nil, err
	}
	return &accountSecret, nil
}

// VerifyCredentials marks the account for password verification by CPM.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Verify-credentials-v9-10.htm
func (s *IdsecPCloudAccountsService) VerifyCredentials(verifyAccountCredentials *accountsmodels.IdsecPCloudVerifyAccountCredentials) error {
	s.Logger.Info("Verifying account credentials [%s]", verifyAccountCredentials.AccountID)
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(verifyAccountCredentialsURL, verifyAccountCredentials.AccountID), nil)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to verify account credentials - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// ChangeCredentials marks the account for password changing immediately by CPM.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Change-credentials-immediately.htm
func (s *IdsecPCloudAccountsService) ChangeCredentials(changeAccountCredentials *accountsmodels.IdsecPCloudChangeAccountCredentials) error {
	s.Logger.Info("Changing account credentials [%s]", changeAccountCredentials.AccountID)
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(changeAccountCredentialsURL, changeAccountCredentials.AccountID), nil)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to change account credentials - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// SetNextCredentials marks the account to have its password changed to the given one via CPM.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/SetNextPassword.htm
func (s *IdsecPCloudAccountsService) SetNextCredentials(setAccountNextCredentials *accountsmodels.IdsecPCloudSetAccountNextCredentials) error {
	s.Logger.Info("Setting account next credentials [%s]", setAccountNextCredentials.AccountID)
	if setAccountNextCredentials.NewCredentialsFile != "" && setAccountNextCredentials.NewCredentials == "" {
		secret, err := os.ReadFile(setAccountNextCredentials.NewCredentialsFile)
		if err != nil {
			return err
		}
		setAccountNextCredentials.NewCredentials = string(secret)
	}
	if setAccountNextCredentials.NewCredentials == "" {
		return fmt.Errorf("new credentials are required")
	}
	setAccountNextCredentialsJSON, err := common.SerializeJSONCamel(setAccountNextCredentials)
	if err != nil {
		return err
	}
	delete(setAccountNextCredentialsJSON, "accountId")
	delete(setAccountNextCredentialsJSON, "newCredentialsFile")
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(setAccountNextCredentialsURL, setAccountNextCredentials.AccountID), setAccountNextCredentialsJSON)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to set account next credentials - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// UpdateCredentialsInVault updates the account credentials only in the vault without changing it on the machine itself.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/ChangeCredentialsInVault.htm
func (s *IdsecPCloudAccountsService) UpdateCredentialsInVault(updateAccountCredentialsInVault *accountsmodels.IdsecPCloudUpdateAccountCredentialsInVault) error {
	s.Logger.Info("Updating account credentials in vault [%s]", updateAccountCredentialsInVault.AccountID)
	if updateAccountCredentialsInVault.NewCredentialsFile != "" && updateAccountCredentialsInVault.NewCredentials == "" {
		secret, err := os.ReadFile(updateAccountCredentialsInVault.NewCredentialsFile)
		if err != nil {
			return err
		}
		updateAccountCredentialsInVault.NewCredentials = string(secret)
	}
	if updateAccountCredentialsInVault.NewCredentials == "" {
		return fmt.Errorf("new credentials are required")
	}
	updateAccountCredentialsInVaultJSON, err := common.SerializeJSONCamel(updateAccountCredentialsInVault)
	if err != nil {
		return err
	}
	delete(updateAccountCredentialsInVaultJSON, "accountId")
	delete(updateAccountCredentialsInVaultJSON, "newCredentialsFile")
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(updateAccountCredentialsInVaultURL, updateAccountCredentialsInVault.AccountID), updateAccountCredentialsInVaultJSON)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update account credentials in vault - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// ReconcileCredentials marks the account for reconciliation.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Reconcile-account.htm
func (s *IdsecPCloudAccountsService) ReconcileCredentials(reconcileAccountCredentials *accountsmodels.IdsecPCloudReconcileAccountCredentials) error {
	s.Logger.Info("Reconciling account credentials [%s]", reconcileAccountCredentials.AccountID)
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(reconcileAccountCredentialsURL, reconcileAccountCredentials.AccountID), nil)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to reconcile account credentials - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

func (s *IdsecPCloudAccountsService) parseAccountResponse(responseBody io.ReadCloser) (*accountsmodels.IdsecPCloudAccount, error) {
	accountJSON, err := common.DeserializeJSONSnake(responseBody)
	if err != nil {
		return nil, err
	}
	accountJSONMap, ok := accountJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid account response format")
	}
	if err := normalizeAccountItemMap(accountJSONMap); err != nil {
		return nil, err
	}
	var account accountsmodels.IdsecPCloudAccount
	err = mapstructure.Decode(accountJSONMap, &account)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

// Get retrieves an IdsecPCloudAccount by its ID.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Get%20Account%20Details.htm?
func (s *IdsecPCloudAccountsService) Get(getAccount *accountsmodels.IdsecPCloudGetAccount) (*accountsmodels.IdsecPCloudAccount, error) {
	s.Logger.Info("Retrieving account [%s] - [%s]", getAccount.AccountID, getAccount.AccountName)
	if getAccount.AccountID == "" && getAccount.AccountName == "" {
		return nil, fmt.Errorf("either account ID or account name must be provided")
	}
	if getAccount.AccountID == "" && getAccount.AccountName != "" {
		accountsPages, err := s.ListBy(&accountsmodels.IdsecPCloudAccountsFilter{
			Search: getAccount.AccountName,
			Limit:  1,
		})
		if err != nil {
			return nil, err
		}
		for accountsPage := range accountsPages {
			for _, account := range accountsPage.Items {
				if account.Name == getAccount.AccountName {
					getAccount.AccountID = account.AccountID
					break
				}
			}
		}
		if getAccount.AccountID == "" {
			return nil, fmt.Errorf("account with name [%s] not found", getAccount.AccountName)
		}
	}
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(accountURL, getAccount.AccountID), nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve account - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return s.parseAccountResponse(response.Body)
}

// GetCredentials retrieves the credentials of an IdsecPCloudAccount by its ID.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/GetPasswordValueV10.htm?
func (s *IdsecPCloudAccountsService) GetCredentials(getAccount *accountsmodels.IdsecPCloudGetAccountCredentials) (*accountsmodels.IdsecPCloudAccountCredentials, error) {
	s.Logger.Info("Retrieving account credentials [%s]", getAccount.AccountID)
	accountCredentialsJSON, err := common.SerializeJSONCamel(getAccount)
	if err != nil {
		return nil, err
	}
	delete(accountCredentialsJSON, "accountId")
	accountCredentialsJSONCamel := make(map[string]interface{})
	titleCaser := cases.Title(language.English)
	for key, value := range accountCredentialsJSON {
		key = strings.ReplaceAll(key, "_", "")
		key = titleCaser.String(key)
		accountCredentialsJSONCamel[key] = value
	}
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(retrieveAccountCredentialsURL, getAccount.AccountID), accountCredentialsJSONCamel)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve account credentials - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	rawData, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	accountSecret := accountsmodels.IdsecPCloudAccountCredentials{
		AccountID: getAccount.AccountID,
		Password:  string(rawData[1 : len(rawData)-1]),
	}
	return &accountSecret, nil
}

// Create adds a new IdsecPCloudAccount.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Add%20Account%20v10.htm?
func (s *IdsecPCloudAccountsService) Create(addAccount *accountsmodels.IdsecPCloudAddAccount) (*accountsmodels.IdsecPCloudAccount, error) {
	if addAccount.Name == "" {
		addAccount.Name = fmt.Sprintf("%s_%s", addAccount.SafeName, addAccount.PlatformID)
		if addAccount.Address != "" {
			addAccount.Name = fmt.Sprintf("%s_%s", addAccount.Name, addAccount.Address)
		}
		if addAccount.Username != "" {
			addAccount.Name = fmt.Sprintf("%s_%s", addAccount.Name, addAccount.Username)
		}
	}
	if addAccount.SecretFile != "" && addAccount.Secret == "" {
		secret, err := os.ReadFile(addAccount.SecretFile)
		if err != nil {
			return nil, err
		}
		addAccount.Secret = string(secret)
	}
	s.Logger.Info("Adding account [%s]", addAccount.Name)
	addAccountJSON, err := common.SerializeJSONCamel(addAccount)
	if err != nil {
		return nil, err
	}
	delete(addAccountJSON, "accountId")
	delete(addAccountJSON, "automaticManagementEnabled")
	delete(addAccountJSON, "manualManagementReason")
	delete(addAccountJSON, "lastModifiedTime")
	delete(addAccountJSON, "remoteMachines")
	delete(addAccountJSON, "accessRestrictedToRemoteMachines")
	delete(addAccountJSON, "idsecPcloudAccountRemoteMachinesAccess")
	delete(addAccountJSON, "idsecPcloudAccountSecretManagement")
	if addAccount.AutomaticManagementEnabled != nil {
		addAccountJSON["secretManagement"] = map[string]interface{}{
			"automaticManagementEnabled": *addAccount.AutomaticManagementEnabled,
		}
		if addAccount.ManualManagementReason != "" {
			addAccountJSON["secretManagement"].(map[string]interface{})["manualManagementReason"] = addAccount.ManualManagementReason
		}
		if addAccount.LastModifiedTime != 0 {
			addAccountJSON["secretManagement"].(map[string]interface{})["lastModifiedTime"] = addAccount.LastModifiedTime
		}
	}
	if addAccount.RemoteMachines != nil {
		addAccountJSON["remoteMachinesAccess"] = map[string]interface{}{
			"remoteMachines": strings.Join(addAccount.RemoteMachines, ";"),
		}
		if addAccount.AccessRestrictedToRemoteMachines {
			addAccountJSON["remoteMachinesAccess"].(map[string]interface{})["accessRestrictedToRemoteMachines"] = addAccount.AccessRestrictedToRemoteMachines
		}
	}
	response, existingAccount, err := commonpcloud.CreateWithGatewayTimeoutRecovery(
		func() (*http.Response, error) {
			return s.ISPClient().Post(context.Background(), accountsURL, addAccountJSON)
		},
		func() (*accountsmodels.IdsecPCloudAccount, error) {
			return s.Get(&accountsmodels.IdsecPCloudGetAccount{AccountName: addAccount.Name})
		},
	)
	if err != nil {
		return nil, err
	}
	if existingAccount != nil {
		s.Logger.Info("Account [%s] recovered after gateway timeout", addAccount.Name)
		return existingAccount, nil
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode == http.StatusConflict {
		s.Logger.Info("Account [%s] already exists, retrieving existing account", addAccount.Name)
		account, err := s.Get(&accountsmodels.IdsecPCloudGetAccount{
			AccountName: addAccount.Name,
		})
		if err != nil {
			// For some reason, the account creation returned conflict but the account is not found when retrieving it
			// So we try again with a post to create
			s.Logger.Info("Account [%s] not found after conflict, retrying account creation", addAccount.Name)
			response, err = s.ISPClient().Post(context.Background(), accountsURL, addAccountJSON)
			if err != nil {
				return nil, err
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					common.GlobalLogger.Warning("Error closing response body")
				}
			}(response.Body)
		} else {
			return account, nil
		}
	}
	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to add account - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return s.parseAccountResponse(response.Body)
}

// Update updates an existing IdsecPCloudAccount.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/UpdateAccount%20v10.htm
func (s *IdsecPCloudAccountsService) Update(updateAccount *accountsmodels.IdsecPCloudUpdateAccount) (*accountsmodels.IdsecPCloudAccount, error) {
	s.Logger.Info("Updating account [%s]", updateAccount.AccountID)
	if updateAccount.SecretFile != "" && updateAccount.Secret == "" {
		secret, err := os.ReadFile(updateAccount.SecretFile)
		if err != nil {
			return nil, err
		}
		updateAccount.Secret = string(secret)
	}
	updateAccountJSON, err := common.SerializeJSONCamel(updateAccount)
	if err != nil {
		return nil, err
	}
	delete(updateAccountJSON, "secret")
	delete(updateAccountJSON, "secretFile")
	delete(updateAccountJSON, "accountId")
	delete(updateAccountJSON, "automaticManagementEnabled")
	delete(updateAccountJSON, "manualManagementReason")
	delete(updateAccountJSON, "lastModifiedTime")
	delete(updateAccountJSON, "remoteMachines")
	delete(updateAccountJSON, "accessRestrictedToRemoteMachines")
	delete(updateAccountJSON, "idsecPcloudAccountRemoteMachinesAccess")
	delete(updateAccountJSON, "idsecPcloudAccountSecretManagement")
	if updateAccount.AutomaticManagementEnabled != nil {
		updateAccountJSON["secretManagement/automaticManagementEnabled"] = *updateAccount.AutomaticManagementEnabled
		if updateAccount.ManualManagementReason != "" {
			updateAccountJSON["secretManagement/manualManagementReason"] = updateAccount.ManualManagementReason
		}
		if updateAccount.LastModifiedTime != 0 {
			updateAccountJSON["secretManagement/lastModifiedTime"] = updateAccount.LastModifiedTime
		}
	}
	if updateAccount.RemoteMachines != nil {
		updateAccountJSON["remoteMachinesAccess/remoteMachines"] = strings.Join(updateAccount.RemoteMachines, ";")
		if updateAccount.AccessRestrictedToRemoteMachines {
			updateAccountJSON["remoteMachinesAccess/accessRestrictedToRemoteMachines"] = updateAccount.AccessRestrictedToRemoteMachines
		}
	}
	var operations []map[string]interface{}
	for key, val := range updateAccountJSON {
		if key == "secretFile" {
			continue
		}
		operation := map[string]interface{}{
			"op":    "replace",
			"path":  fmt.Sprintf("/%s", key),
			"value": val,
		}
		operations = append(operations, operation)
	}
	var account *accountsmodels.IdsecPCloudAccount
	if len(operations) == 0 {
		pcloudAccount, err := s.Get(&accountsmodels.IdsecPCloudGetAccount{
			AccountID: updateAccount.AccountID,
		})
		if err != nil {
			return nil, err
		}
		account = pcloudAccount
	} else {
		response, err := s.ISPClient().Patch(context.Background(), fmt.Sprintf(accountURL, updateAccount.AccountID), operations)
		if err != nil {
			return nil, err
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				common.GlobalLogger.Warning("Error closing response body")
			}
		}(response.Body)
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to update account - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
		}
		account, err = s.parseAccountResponse(response.Body)
		if err != nil {
			return nil, err
		}
	}
	if updateAccount.Secret != "" {
		err = s.UpdateCredentialsInVault(&accountsmodels.IdsecPCloudUpdateAccountCredentialsInVault{
			AccountID:      updateAccount.AccountID,
			NewCredentials: updateAccount.Secret,
		})
		if err != nil {
			return nil, err
		}
	}
	return account, nil
}

// Delete deletes an existing account.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Delete%20Account.htm
func (s *IdsecPCloudAccountsService) Delete(deleteAccount *accountsmodels.IdsecPCloudDeleteAccount) error {
	s.Logger.Info("Deleting account [%s]", deleteAccount.AccountID)
	account, err := s.Get(&accountsmodels.IdsecPCloudGetAccount{
		AccountID: deleteAccount.AccountID,
	})
	if err != nil {
		return err
	}
	chosenAccountURL := accountURL
	if account.SecretType == accountsmodels.Key {
		chosenAccountURL = accountURLOld
	}
	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(chosenAccountURL, deleteAccount.AccountID), nil, nil)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete account - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// Link links an account
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/WebServices/Link-account.htm
func (s *IdsecPCloudAccountsService) Link(linkAccount *accountsmodels.IdsecPCloudLinkAccount) error {
	s.Logger.Info("Linking account [%v]", linkAccount)
	linkAccountJSON, err := common.SerializeJSONCamel(linkAccount)
	if err != nil {
		return err
	}
	delete(linkAccountJSON, "account_id")
	response, err := s.ISPClient().Post(context.Background(), fmt.Sprintf(linkAccountURL, linkAccount.AccountID), linkAccountJSON)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to link account - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// Unlink unlinks an account
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/WebServices/Link-account-unlink.htm
func (s *IdsecPCloudAccountsService) Unlink(unlinkAccount *accountsmodels.IdsecPCloudUnlinkAccount) error {
	s.Logger.Info("Unlinking account [%s] index [%s]", unlinkAccount.AccountID, unlinkAccount.ExtraPasswordIndex)
	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(unlinkAccountURL, unlinkAccount.AccountID, unlinkAccount.ExtraPasswordIndex), nil, nil)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to unlink account - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// Stats retrieves the statistics of IdsecPCloudAccounts.
func (s *IdsecPCloudAccountsService) Stats() (*accountsmodels.IdsecPCloudAccountsStats, error) {
	s.Logger.Info("Retrieving accounts stats")
	accountsChan, err := s.List()
	if err != nil {
		return nil, err
	}
	accounts := make([]*accountsmodels.IdsecPCloudAccount, 0)
	for page := range accountsChan {
		accounts = append(accounts, page.Items...)
	}
	var accountsStats accountsmodels.IdsecPCloudAccountsStats
	accountsStats.AccountsCount = len(accounts)
	accountsStats.AccountsCountByPlatformID = make(map[string]int)
	accountsStats.AccountsCountBySafeName = make(map[string]int)
	for _, account := range accounts {
		if _, ok := accountsStats.AccountsCountByPlatformID[account.PlatformID]; !ok {
			accountsStats.AccountsCountByPlatformID[account.PlatformID] = 0
		}
		if _, ok := accountsStats.AccountsCountBySafeName[account.SafeName]; !ok {
			accountsStats.AccountsCountBySafeName[account.SafeName] = 0
		}
		accountsStats.AccountsCountByPlatformID[account.PlatformID]++
		accountsStats.AccountsCountBySafeName[account.SafeName]++
	}
	return &accountsStats, nil
}

// ServiceConfig returns the service configuration for the IdsecPCloudAccountsService.
func (s *IdsecPCloudAccountsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
