package accounts

import (
	"context"
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"

	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// API endpoint paths for account-related operations
const (
	accountsURL                        = "/api/accounts"
	accountURL                         = "/api/accounts/%s/"
	accountSecretVersionsURL           = "/api/accounts/%s/secret/versions"   // #nosec G101
	generateAccountCredentialsURL      = "/api/accounts/%s/secret/generate"   // #nosec G101
	verifyAccountCredentialsURL        = "/api/accounts/%s/verify"            // #nosec G101
	changeAccountCredentialsURL        = "/api/accounts/%s/change"            // #nosec G101
	setAccountNextCredentialsURL       = "/api/accounts/%s/setnextpassword"   // #nosec G101
	updateAccountCredentialsInVaultURL = "/api/accounts/%s/password/update"   // #nosec G101
	retrieveAccountCredentialsURL      = "/api/accounts/%s/password/retrieve" // #nosec G101
	reconcileAccountCredentialsURL     = "/api/accounts/%s/reconcile"         // #nosec G101
	linkAccountURL                     = "/api/accounts/%s/linkaccount"
	unlinkAccountURL                   = "/api/accounts/%s/linkaccount/%s/"
)

// IdsecPCloudAccountsPage is a paginated type for IdsecPCloudAccount
type IdsecPCloudAccountsPage = common.IdsecPage[accountsmodels.IdsecPCloudAccount]

// IdsecPCloudAccountsService is the service for managing pCloud Accounts.
type IdsecPCloudAccountsService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
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
	client, err := isp.FromISPAuth(ispAuth, "privilegecloud", ".", "passwordvault", pcloudAccountsService.refreshPCloudAccountsAuth)
	if err != nil {
		return nil, err
	}
	pcloudAccountsService.client = client
	pcloudAccountsService.ispAuth = ispAuth
	pcloudAccountsService.IdsecBaseService = baseService
	return pcloudAccountsService, nil
}

func (s *IdsecPCloudAccountsService) refreshPCloudAccountsAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecPCloudAccountsService) listAccountsWithFilters(
	search string,
	searchType string,
	sort string,
	offset int,
	limit int,
	safeName string,
) (<-chan *IdsecPCloudAccountsPage, error) {
	query := map[string]string{}
	if search != "" {
		query["search"] = search
	}
	if searchType != "" {
		query["searchType"] = searchType
	}
	if sort != "" {
		query["sort"] = sort
	}
	if offset > 0 {
		query["offset"] = fmt.Sprintf("%d", offset)
	}
	if limit > 0 {
		query["limit"] = fmt.Sprintf("%d", limit)
	}
	if safeName != "" {
		query["filter"] = fmt.Sprintf("safeName eq %s", safeName)
	}
	results := make(chan *IdsecPCloudAccountsPage)
	go func() {
		defer close(results)
		for {
			response, err := s.client.Get(context.Background(), accountsURL, query)
			if err != nil {
				s.Logger.Error("Failed to list accounts: %v", err)
				return
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					common.GlobalLogger.Warning("Error closing response body")
				}
			}(response.Body)
			if response.StatusCode != http.StatusOK {
				s.Logger.Error("Failed to list accounts - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
				return
			}
			result, err := common.DeserializeJSONSnake(response.Body)
			if err != nil {
				s.Logger.Error("Failed to decode response: %v", err)
				return
			}
			resultMap := result.(map[string]interface{})
			var accountsJSON []interface{}
			if value, ok := resultMap["value"]; ok {
				accountsJSON = value.([]interface{})
			} else {
				s.Logger.Error("Failed to list accounts, unexpected result")
				return
			}
			for i, account := range accountsJSON {
				if accountMap, ok := account.(map[string]interface{}); ok {
					if accountID, ok := accountMap["id"]; ok {
						accountsJSON[i].(map[string]interface{})["account_id"] = accountID
					}
					if userName, ok := accountMap["user_name"]; ok {
						accountsJSON[i].(map[string]interface{})["username"] = userName
					}
				}
			}
			var accounts []*accountsmodels.IdsecPCloudAccount
			if err := mapstructure.Decode(accountsJSON, &accounts); err != nil {
				s.Logger.Error("Failed to validate accounts: %v", err)
				return
			}
			results <- &IdsecPCloudAccountsPage{Items: accounts}
			if nextLink, ok := resultMap["nextLink"].(string); ok {
				nextQuery, _ := url.Parse(nextLink)
				queryValues := nextQuery.Query()
				query = make(map[string]string)
				for key, values := range queryValues {
					if len(values) > 0 {
						query[key] = values[0]
					}
				}
			} else {
				break
			}
		}
	}()
	return results, nil
}

// ListAccounts retrieves a list of IdsecPCloudAccount pages.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/GetAccounts.htm
func (s *IdsecPCloudAccountsService) ListAccounts() (<-chan *IdsecPCloudAccountsPage, error) {
	return s.listAccountsWithFilters(
		"",
		"",
		"",
		0,
		0,
		"",
	)
}

// ListAccountsBy retrieves a list of IdsecPCloudAccount pages with filters.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/GetAccounts.htm
func (s *IdsecPCloudAccountsService) ListAccountsBy(accountsFilters *accountsmodels.IdsecPCloudAccountsFilter) (<-chan *IdsecPCloudAccountsPage, error) {
	return s.listAccountsWithFilters(
		accountsFilters.Search,
		accountsFilters.SearchType,
		accountsFilters.Sort,
		accountsFilters.Offset,
		accountsFilters.Limit,
		accountsFilters.SafeName,
	)
}

// ListAccountSecretVersions retrieves a list of IdsecPCloudAccountSecretVersion.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Secrets-Get-versions.htm
func (s *IdsecPCloudAccountsService) ListAccountSecretVersions(listAccountSecretVersions *accountsmodels.IdsecPCloudListAccountSecretVersions) ([]*accountsmodels.IdsecPCloudAccountSecretVersion, error) {
	s.Logger.Info("Retrieving account secret versions [%s]", listAccountSecretVersions.AccountID)
	response, err := s.client.Get(context.Background(), fmt.Sprintf(accountSecretVersionsURL, listAccountSecretVersions.AccountID), nil)
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

// GenerateAccountCredentials generate a new random password for an existing account with policy restrictions.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/Secrets-Generate-Password.htm
func (s *IdsecPCloudAccountsService) GenerateAccountCredentials(generateAccountCredentials *accountsmodels.IdsecPCloudGenerateAccountCredentials) (*accountsmodels.IdsecPCloudAccountCredentials, error) {
	s.Logger.Info("Generating account credentials [%s]", generateAccountCredentials.AccountID)
	response, err := s.client.Post(context.Background(), fmt.Sprintf(generateAccountCredentialsURL, generateAccountCredentials.AccountID), nil)
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

// VerifyAccountCredentials marks the account for password verification by CPM.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Verify-credentials-v9-10.htm
func (s *IdsecPCloudAccountsService) VerifyAccountCredentials(verifyAccountCredentials *accountsmodels.IdsecPCloudVerifyAccountCredentials) error {
	s.Logger.Info("Verifying account credentials [%s]", verifyAccountCredentials.AccountID)
	response, err := s.client.Post(context.Background(), fmt.Sprintf(verifyAccountCredentialsURL, verifyAccountCredentials.AccountID), nil)
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

// ChangeAccountCredentials marks the account for password changing immediately by CPM.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Change-credentials-immediately.htm
func (s *IdsecPCloudAccountsService) ChangeAccountCredentials(changeAccountCredentials *accountsmodels.IdsecPCloudChangeAccountCredentials) error {
	s.Logger.Info("Changing account credentials [%s]", changeAccountCredentials.AccountID)
	response, err := s.client.Post(context.Background(), fmt.Sprintf(changeAccountCredentialsURL, changeAccountCredentials.AccountID), nil)
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

// SetAccountNextCredentials marks the account to have its password changed to the given one via CPM.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/SetNextPassword.htm
func (s *IdsecPCloudAccountsService) SetAccountNextCredentials(setAccountNextCredentials *accountsmodels.IdsecPCloudSetAccountNextCredentials) error {
	s.Logger.Info("Setting account next credentials [%s]", setAccountNextCredentials.AccountID)
	setAccountNextCredentialsJSON, err := common.SerializeJSONCamel(setAccountNextCredentials)
	if err != nil {
		return err
	}
	delete(setAccountNextCredentialsJSON, "accountId")
	response, err := s.client.Post(context.Background(), fmt.Sprintf(setAccountNextCredentialsURL, setAccountNextCredentials.AccountID), setAccountNextCredentialsJSON)
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

// UpdateAccountCredentialsInVault updates the account credentials only in the vault without changing it on the machine itself.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/ChangeCredentialsInVault.htm
func (s *IdsecPCloudAccountsService) UpdateAccountCredentialsInVault(updateAccountCredentialsInVault *accountsmodels.IdsecPCloudUpdateAccountCredentialsInVault) error {
	s.Logger.Info("Updating account credentials in vault [%s]", updateAccountCredentialsInVault.AccountID)
	updateAccountCredentialsInVaultJSON, err := common.SerializeJSONCamel(updateAccountCredentialsInVault)
	if err != nil {
		return err
	}
	delete(updateAccountCredentialsInVaultJSON, "accountId")
	response, err := s.client.Post(context.Background(), fmt.Sprintf(updateAccountCredentialsInVaultURL, updateAccountCredentialsInVault.AccountID), updateAccountCredentialsInVaultJSON)
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

// ReconcileAccountCredentials marks the account for reconciliation.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Reconcile-account.htm
func (s *IdsecPCloudAccountsService) ReconcileAccountCredentials(reconcileAccountCredentials *accountsmodels.IdsecPCloudReconcileAccountCredentials) error {
	s.Logger.Info("Reconciling account credentials [%s]", reconcileAccountCredentials.AccountID)
	response, err := s.client.Post(context.Background(), fmt.Sprintf(reconcileAccountCredentialsURL, reconcileAccountCredentials.AccountID), nil)
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

// Account retrieves an IdsecPCloudAccount by its ID.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Get%20Account%20Details.htm?
func (s *IdsecPCloudAccountsService) Account(getAccount *accountsmodels.IdsecPCloudGetAccount) (*accountsmodels.IdsecPCloudAccount, error) {
	s.Logger.Info("Retrieving account [%s]", getAccount.AccountID)
	response, err := s.client.Get(context.Background(), fmt.Sprintf(accountURL, getAccount.AccountID), nil)
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
	accountJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	accountJSONMap := accountJSON.(map[string]interface{})
	if accountID, ok := accountJSONMap["id"]; ok {
		accountJSONMap["account_id"] = accountID
	}
	if userName, ok := accountJSONMap["user_name"]; ok {
		accountJSONMap["username"] = userName
	}
	var account accountsmodels.IdsecPCloudAccount
	err = mapstructure.Decode(accountJSONMap, &account)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

// AccountCredentials retrieves the credentials of an IdsecPCloudAccount by its ID.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/GetPasswordValueV10.htm?
func (s *IdsecPCloudAccountsService) AccountCredentials(getAccount *accountsmodels.IdsecPCloudGetAccountCredentials) (*accountsmodels.IdsecPCloudAccountCredentials, error) {
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
	response, err := s.client.Post(context.Background(), fmt.Sprintf(retrieveAccountCredentialsURL, getAccount.AccountID), accountCredentialsJSONCamel)
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

// AddAccount adds a new IdsecPCloudAccount.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Add%20Account%20v10.htm?
func (s *IdsecPCloudAccountsService) AddAccount(addAccount *accountsmodels.IdsecPCloudAddAccount) (*accountsmodels.IdsecPCloudAccount, error) {
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
	if addAccount.AutomaticManagementEnabled {
		addAccountJSON["secretManagement"] = map[string]interface{}{
			"automaticManagementEnabled": addAccount.AutomaticManagementEnabled,
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
			"remoteMachines": addAccount.RemoteMachines,
		}
		if addAccount.AccessRestrictedToRemoteMachines {
			addAccountJSON["remoteMachinesAccess"].(map[string]interface{})["accessRestrictedToRemoteMachines"] = addAccount.AccessRestrictedToRemoteMachines
		}
	}
	response, err := s.client.Post(context.Background(), accountsURL, addAccountJSON)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to add account - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	accountJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	accountJSONMap := accountJSON.(map[string]interface{})
	if accountID, ok := accountJSONMap["id"]; ok {
		accountJSONMap["account_id"] = accountID
	}
	if userName, ok := accountJSONMap["user_name"]; ok {
		accountJSONMap["username"] = userName
	}
	var account accountsmodels.IdsecPCloudAccount
	err = mapstructure.Decode(accountJSONMap, &account)
	if err != nil {
		return nil, err
	}

	return &account, nil
}

// UpdateAccount updates an existing IdsecPCloudAccount.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/UpdateAccount%20v10.htm
func (s *IdsecPCloudAccountsService) UpdateAccount(updateAccount *accountsmodels.IdsecPCloudUpdateAccount) (*accountsmodels.IdsecPCloudAccount, error) {
	s.Logger.Info("Updating account [%s]", updateAccount.AccountID)
	updateAccountJSON, err := common.SerializeJSONCamel(updateAccount)
	if err != nil {
		return nil, err
	}
	delete(updateAccountJSON, "secret")
	delete(updateAccountJSON, "accountId")
	delete(updateAccountJSON, "automaticManagementEnabled")
	delete(updateAccountJSON, "manualManagementReason")
	delete(updateAccountJSON, "lastModifiedTime")
	delete(updateAccountJSON, "remoteMachines")
	delete(updateAccountJSON, "accessRestrictedToRemoteMachines")
	delete(updateAccountJSON, "idsecPcloudAccountRemoteMachinesAccess")
	delete(updateAccountJSON, "idsecPcloudAccountSecretManagement")
	if updateAccount.AutomaticManagementEnabled {
		updateAccountJSON["secretManagement"] = map[string]interface{}{
			"automaticManagementEnabled": updateAccount.AutomaticManagementEnabled,
		}
		if updateAccount.ManualManagementReason != "" {
			updateAccountJSON["secretManagement"].(map[string]interface{})["manualManagementReason"] = updateAccount.ManualManagementReason
		}
		if updateAccount.LastModifiedTime != 0 {
			updateAccountJSON["secretManagement"].(map[string]interface{})["lastModifiedTime"] = updateAccount.LastModifiedTime
		}
	}
	if updateAccount.RemoteMachines != nil {
		updateAccountJSON["remoteMachinesAccess"] = map[string]interface{}{
			"remoteMachines": updateAccount.RemoteMachines,
		}
		if updateAccount.AccessRestrictedToRemoteMachines {
			updateAccountJSON["remoteMachinesAccess"].(map[string]interface{})["accessRestrictedToRemoteMachines"] = updateAccount.AccessRestrictedToRemoteMachines
		}
	}
	var operations []map[string]interface{}
	for key, val := range updateAccountJSON {
		operation := map[string]interface{}{
			"op":    "replace",
			"path":  fmt.Sprintf("/%s", key),
			"value": val,
		}
		operations = append(operations, operation)
	}
	var account accountsmodels.IdsecPCloudAccount
	if len(operations) == 0 {
		pcloudAccount, err := s.Account(&accountsmodels.IdsecPCloudGetAccount{
			AccountID: updateAccount.AccountID,
		})
		if err != nil {
			return nil, err
		}
		account = *pcloudAccount
	} else {
		response, err := s.client.Patch(context.Background(), fmt.Sprintf(accountURL, updateAccount.AccountID), operations)
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
		accountJSON, err := common.DeserializeJSONSnake(response.Body)
		if err != nil {
			return nil, err
		}
		accountJSONMap := accountJSON.(map[string]interface{})
		if accountID, ok := accountJSONMap["id"]; ok {
			accountJSONMap["account_id"] = accountID
		}
		if userName, ok := accountJSONMap["user_name"]; ok {
			accountJSONMap["username"] = userName
		}
		err = mapstructure.Decode(accountJSONMap, &account)
		if err != nil {
			return nil, err
		}
	}
	if updateAccount.Secret != "" {
		err = s.UpdateAccountCredentialsInVault(&accountsmodels.IdsecPCloudUpdateAccountCredentialsInVault{
			AccountID:      updateAccount.AccountID,
			NewCredentials: updateAccount.Secret,
		})
		if err != nil {
			return nil, err
		}
	}
	return &account, nil
}

// DeleteAccount deletes an existing account.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Delete%20Account.htm
func (s *IdsecPCloudAccountsService) DeleteAccount(deleteAccount *accountsmodels.IdsecPCloudDeleteAccount) error {
	s.Logger.Info("Deleting account [%s]", deleteAccount.AccountID)
	response, err := s.client.Delete(context.Background(), fmt.Sprintf(accountURL, deleteAccount.AccountID), nil, nil)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete account - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// LinkAccount links an account
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/WebServices/Link-account.htm
func (s *IdsecPCloudAccountsService) LinkAccount(linkAccount *accountsmodels.IdsecPCloudLinkAccount) error {
	s.Logger.Info("Linking account [%v]", linkAccount)
	linkAccountJSON, err := common.SerializeJSONCamel(linkAccount)
	if err != nil {
		return err
	}
	delete(linkAccountJSON, "account_id")
	response, err := s.client.Post(context.Background(), fmt.Sprintf(linkAccountURL, linkAccount.AccountID), linkAccountJSON)
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

// UnlinkAccount unlinks an account
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/WebServices/Link-account-unlink.htm
func (s *IdsecPCloudAccountsService) UnlinkAccount(unlinkAccount *accountsmodels.IdsecPCloudUnlinkAccount) error {
	s.Logger.Info("Unlinking account [%s] index [%s]", unlinkAccount.AccountID, unlinkAccount.ExtraPasswordIndex)
	response, err := s.client.Delete(context.Background(), fmt.Sprintf(unlinkAccountURL, unlinkAccount.AccountID, unlinkAccount.ExtraPasswordIndex), nil, nil)
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

// AccountsStats retrieves the statistics of IdsecPCloudAccounts.
func (s *IdsecPCloudAccountsService) AccountsStats() (*accountsmodels.IdsecPCloudAccountsStats, error) {
	s.Logger.Info("Retrieving accounts stats")
	accountsChan, err := s.ListAccounts()
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
