package users

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	commonpcloud "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/common"
	usersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/users/models"
)

const (
	usersURL = "/PasswordVault/api/Users"
	userURL  = "/PasswordVault/api/Users/%d"
)

// IdsecPCloudUsersService manages Vault-native users via the PVWA REST API.
type IdsecPCloudUsersService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecPCloudUsersService creates a new instance of IdsecPCloudUsersService.
func NewIdsecPCloudUsersService(authenticators ...auth.IdsecAuth) (*IdsecPCloudUsersService, error) {
	pcloudUsersService := &IdsecPCloudUsersService{}
	var pcloudUsersServiceInterface services.IdsecService = pcloudUsersService
	baseService, err := services.NewIdsecBaseService(pcloudUsersServiceInterface, authenticators...)
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
		pcloudUsersService.refreshPCloudUsersAuth,
		commonpcloud.DefaultPCloudRetryStrategy(),
	)
	if err != nil {
		return nil, err
	}

	pcloudUsersService.IdsecBaseService = baseService
	pcloudUsersService.IdsecISPBaseService = ispBaseService
	return pcloudUsersService, nil
}

func (s *IdsecPCloudUsersService) refreshPCloudUsersAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// serializeUserPayload serializes v to a camelCase JSON map and removes the
// output-only "userId" key so it is never sent in request payloads.
func serializeUserPayload(v interface{}) (map[string]interface{}, error) {
	m, err := common.SerializeJSONCamel(v)
	if err != nil {
		return nil, err
	}
	delete(m, "userId")
	return m, nil
}

func (s *IdsecPCloudUsersService) parseUserResponse(responseBody io.ReadCloser) (*usersmodels.IdsecPCloudUser, error) {
	userJSON, err := common.DeserializeJSONSnake(responseBody)
	if err != nil {
		return nil, err
	}
	userJSONMap, ok := userJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid user response format")
	}
	// The API returns "id" not "user_id" — normalize before decoding.
	if id, ok := userJSONMap["id"]; ok {
		userJSONMap["user_id"] = id
	}
	var user usersmodels.IdsecPCloudUser
	if err := mapstructure.Decode(userJSONMap, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// Create adds a new Vault user via POST /PasswordVault/api/Users.
func (s *IdsecPCloudUsersService) Create(addUser *usersmodels.IdsecPCloudAddUser) (*usersmodels.IdsecPCloudUser, error) {
	s.Logger.Info("Creating pCloud user [%s] of type [%s]", addUser.Username, addUser.UserType)

	addUserJSON, err := serializeUserPayload(addUser)
	if err != nil {
		return nil, err
	}

	response, err := s.ISPClient().Post(context.Background(), usersURL, addUserJSON)
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
		return nil, fmt.Errorf("failed to create user - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return s.parseUserResponse(response.Body)
}

// Get retrieves a Vault user by its numeric ID via GET /PasswordVault/api/Users/{id}.
func (s *IdsecPCloudUsersService) Get(getUser *usersmodels.IdsecPCloudGetUser) (*usersmodels.IdsecPCloudUser, error) {
	s.Logger.Info("Retrieving pCloud user [%d]", getUser.UserID)
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(userURL, getUser.UserID), nil)
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
		return nil, fmt.Errorf("failed to retrieve user - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return s.parseUserResponse(response.Body)
}

// Update modifies an existing Vault user via PUT /PasswordVault/api/Users/{id}.
func (s *IdsecPCloudUsersService) Update(updateUser *usersmodels.IdsecPCloudUpdateUser) (*usersmodels.IdsecPCloudUser, error) {
	s.Logger.Info("Updating pCloud user [%d]", updateUser.UserID)
	updateUserJSON, err := serializeUserPayload(updateUser)
	if err != nil {
		return nil, err
	}

	response, err := s.ISPClient().Put(context.Background(), fmt.Sprintf(userURL, updateUser.UserID), updateUserJSON)
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
		return nil, fmt.Errorf("failed to update user - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return s.parseUserResponse(response.Body)
}

// Delete removes a Vault user via DELETE /PasswordVault/api/Users/{id}.
func (s *IdsecPCloudUsersService) Delete(deleteUser *usersmodels.IdsecPCloudDeleteUser) error {
	s.Logger.Info("Deleting pCloud user [%d]", deleteUser.UserID)
	response, err := s.ISPClient().Delete(context.Background(), fmt.Sprintf(userURL, deleteUser.UserID), nil, nil)
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
		return fmt.Errorf("failed to delete user - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// ServiceConfig returns the service configuration for IdsecPCloudUsersService.
func (s *IdsecPCloudUsersService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
