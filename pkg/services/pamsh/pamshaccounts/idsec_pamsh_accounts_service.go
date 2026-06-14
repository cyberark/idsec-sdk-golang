package pamshaccounts

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	pamshinternal "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/internal"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts/models"
)

// API endpoint paths for account-related operations
const (
	accountsURL                        = "/PasswordVault/API/Accounts"
	accountURL                         = "/PasswordVault/API/Accounts/%s/"
	updateAccountCredentialsInVaultURL = "/PasswordVault/API/Accounts/%s/Password/Update" // #nosec G101
)

type pamshAccountsPage = common.IdsecPage[accountsmodels.IdsecPamshAccount]

// IdsecPamshAccountsService manages PAM self-hosted accounts using PVWA-authenticated REST.
type IdsecPamshAccountsService struct {
	*services.IdsecBaseService
	*services.IdsecPVWABaseService
}

// NewIdsecPamshAccountsService creates a new IdsecPamshAccountsService.
func NewIdsecPamshAccountsService(authenticators ...auth.IdsecAuth) (*IdsecPamshAccountsService, error) {
	pamshAccountsService := &IdsecPamshAccountsService{}
	var pamshAccountsServiceInterface services.IdsecService = pamshAccountsService
	baseService, err := services.NewIdsecBaseService(pamshAccountsServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	pvwaBaseAuth, err := baseService.Authenticator("pvwa")
	if err != nil {
		return nil, err
	}
	pvwaAuth, ok := pvwaBaseAuth.(*auth.IdsecPVWAAuth)
	if !ok {
		return nil, fmt.Errorf("pamsh-accounts: expected IdsecPVWAAuth, got %T", pvwaBaseAuth)
	}
	if pvwaAuth.Token == nil {
		return nil, fmt.Errorf("pamsh-accounts: PVWA authenticator has no token; authenticate before constructing the service")
	}

	pamshAccountsService.IdsecBaseService = baseService

	pvwaBase, err := services.NewIdsecPVWABaseServiceWithRESTOptions(
		pvwaAuth,
		"pamsh-accounts",
		nil,
	)
	if err != nil {
		return nil, err
	}
	pamshAccountsService.IdsecPVWABaseService = pvwaBase
	return pamshAccountsService, nil
}

func (s *IdsecPamshAccountsService) listAccountsWithFilters(
	search string,
	searchType string,
	sort string,
	offset int,
	limit int,
	safeName string,
) (<-chan *pamshAccountsPage, <-chan error) {
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
	return pamshinternal.ListPaginated(
		s.PVWAClient(),
		accountsURL,
		query,
		pamshinternal.ListPaginatedConfig[accountsmodels.IdsecPamshAccount]{
			Logger:       s.Logger,
			ResourceName: "accounts",
			ExtractItems: func(resultMap map[string]interface{}) ([]interface{}, error) {
				return pamshinternal.ExtractItemsFromResult(resultMap, "accounts")
			},
			DecodeItems: decodePamshAccountsFromMaps,
		},
	)
}

func (s *IdsecPamshAccountsService) updateCredentialsInVault(accountID, newCredentials string) error {
	s.Logger.Info("Updating account credentials in vault [%s]", accountID)
	if newCredentials == "" {
		return fmt.Errorf("new credentials are required")
	}
	body := map[string]interface{}{
		"newCredentials": newCredentials,
	}
	response, err := s.PVWAClient().Post(context.Background(), fmt.Sprintf(updateAccountCredentialsInVaultURL, accountID), body)
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

func (s *IdsecPamshAccountsService) parseAccountResponse(responseBody io.ReadCloser) (*accountsmodels.IdsecPamshAccount, error) {
	accountJSON, err := common.DeserializeJSONSnake(responseBody)
	if err != nil {
		return nil, err
	}
	accountJSONMap, ok := accountJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse account response: unexpected type %T", accountJSON)
	}
	return decodePamshAccountFromMap(accountJSONMap)
}

func setAccountNameIfMissing(addAccount *accountsmodels.IdsecPamshAddAccount) {
	if addAccount.Name == "" {
		addAccount.Name = fmt.Sprintf("%s_%s", addAccount.SafeName, addAccount.PlatformID)
		if addAccount.Address != "" {
			addAccount.Name = fmt.Sprintf("%s_%s", addAccount.Name, addAccount.Address)
		}
		if addAccount.Username != "" {
			addAccount.Name = fmt.Sprintf("%s_%s", addAccount.Name, addAccount.Username)
		}
	}
}

// Get retrieves an IdsecPamshAccount by its ID.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Get%20Account%20Details.htm?
func (s *IdsecPamshAccountsService) Get(getAccount *accountsmodels.IdsecPamshGetAccount) (*accountsmodels.IdsecPamshAccount, error) {
	s.Logger.Info("Retrieving account [%s] - [%s]", getAccount.AccountID, getAccount.AccountName)
	if getAccount.AccountID == "" && getAccount.AccountName == "" {
		return nil, fmt.Errorf("either account ID or account name must be provided")
	}
	if getAccount.AccountID == "" && getAccount.AccountName != "" {
		accountsPages, errCh := s.listAccountsWithFilters(getAccount.AccountName, "", "", 0, 1, "")
		accounts, err := pamshinternal.DrainPages(accountsPages, errCh)
		if err != nil {
			return nil, err
		}
		for _, account := range accounts {
			if account.Name == getAccount.AccountName {
				getAccount.AccountID = account.AccountID
				break
			}
		}
		if getAccount.AccountID == "" {
			return nil, fmt.Errorf("account with name [%s] not found", getAccount.AccountName)
		}
	}
	response, err := s.PVWAClient().Get(context.Background(), fmt.Sprintf(accountURL, getAccount.AccountID), nil)
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

// Create adds a new IdsecPamshAccount.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Add%20Account%20v10.htm?
func (s *IdsecPamshAccountsService) Create(addAccount *accountsmodels.IdsecPamshAddAccount) (*accountsmodels.IdsecPamshAccount, error) {
	setAccountNameIfMissing(addAccount)
	s.Logger.Info("Adding account [%s]", addAccount.Name)
	if addAccount.SecretManagement != nil && !addAccount.SecretManagement.AutomaticManagementEnabled {
		addAccount.SecretManagement = nil
	}
	addAccountJSON, err := common.SerializeJSONCamel(addAccount)
	if err != nil {
		return nil, err
	}
	response, err := s.PVWAClient().Post(context.Background(), accountsURL, addAccountJSON)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusConflict {
		pamshinternal.ClosePVWAResponse(response)
		s.Logger.Info("Account [%s] already exists, retrieving existing account", addAccount.Name)
		account, err := s.Get(&accountsmodels.IdsecPamshGetAccount{
			AccountName: addAccount.Name,
		})
		if err != nil {
			// For some reason, the account creation returned conflict but the account is not found when retrieving it
			// So we try again with a post to create
			s.Logger.Info("Account [%s] not found after conflict, retrying account creation", addAccount.Name)
			response, err = s.PVWAClient().Post(context.Background(), accountsURL, addAccountJSON)
			if err != nil {
				return nil, err
			}
		} else {
			return account, nil
		}
	}
	if response.StatusCode != http.StatusCreated {
		createErr := fmt.Errorf("failed to add account - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
		pamshinternal.ClosePVWAResponse(response)
		return nil, createErr
	}
	account, err := s.parseAccountResponse(response.Body)
	pamshinternal.ClosePVWAResponse(response)
	if err != nil {
		return nil, err
	}
	return account, nil
}

// Update updates an existing IdsecPamshAccount.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/UpdateAccount%20v10.htm
func (s *IdsecPamshAccountsService) Update(updateAccount *accountsmodels.IdsecPamshUpdateAccount) (*accountsmodels.IdsecPamshAccount, error) {
	s.Logger.Info("Updating account [%s]", updateAccount.AccountID)
	if updateAccount.SecretManagement != nil && !updateAccount.SecretManagement.AutomaticManagementEnabled {
		updateAccount.SecretManagement = nil
	}
	updateAccountJSON, err := common.SerializeJSONCamel(updateAccount)
	if err != nil {
		return nil, err
	}
	operations := buildPamshAccountPatchOperations(updateAccountJSON)
	var account *accountsmodels.IdsecPamshAccount
	if len(operations) == 0 {
		pamshAccount, err := s.Get(&accountsmodels.IdsecPamshGetAccount{
			AccountID: updateAccount.AccountID,
		})
		if err != nil {
			return nil, err
		}
		account = pamshAccount
	} else {
		response, err := s.PVWAClient().Patch(context.Background(), fmt.Sprintf(accountURL, updateAccount.AccountID), operations)
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
		err = s.updateCredentialsInVault(updateAccount.AccountID, updateAccount.Secret)
		if err != nil {
			return nil, err
		}
	}
	return account, nil
}

// Delete deletes an existing account.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Delete%20Account.htm
func (s *IdsecPamshAccountsService) Delete(deleteAccount *accountsmodels.IdsecPamshDeleteAccount) error {
	s.Logger.Info("Deleting account [%s]", deleteAccount.AccountID)
	response, err := s.PVWAClient().Delete(context.Background(), fmt.Sprintf(accountURL, deleteAccount.AccountID), nil, nil)
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

// ServiceConfig returns the service configuration for the IdsecPamshAccountsService.
func (s *IdsecPamshAccountsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
