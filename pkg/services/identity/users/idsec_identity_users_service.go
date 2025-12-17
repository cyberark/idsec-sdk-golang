package users

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles"
	rolesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles/models"
	usersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/users/models"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	createUserURL        = "CDirectoryService/CreateUser"
	deleteUserURL        = "CDirectoryService/DeleteUser"
	updateUserURL        = "CDirectoryService/ChangeUser"
	removeUsersURL       = "UserMgmt/RemoveUsers"
	resetUserPasswordURL = "UserMgmt/ResetUserPassword" // #nosec G101
	redrockQueryURL      = "Redrock/query"
	userInfoURL          = "OAuth2/UserInfo/__idaptive_cybr_user_oidc"
)

// IdsecIdentityUsersService is the service for managing identity users.
type IdsecIdentityUsersService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
}

// NewIdsecIdentityUsersService creates a new instance of IdsecIdentityUsersService.
func NewIdsecIdentityUsersService(authenticators ...auth.IdsecAuth) (*IdsecIdentityUsersService, error) {
	identityUsersService := &IdsecIdentityUsersService{}
	var identityUsersServiceInterface services.IdsecService = identityUsersService
	baseService, err := services.NewIdsecBaseService(identityUsersServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "", "", "api/idadmin", identityUsersService.refreshIdentityUsersAuth)
	if err != nil {
		return nil, err
	}
	client.UpdateHeaders(map[string]string{
		"X-IDAP-NATIVE-CLIENT": "true",
	})
	identityUsersService.client = client
	identityUsersService.ispAuth = ispAuth
	identityUsersService.IdsecBaseService = baseService
	return identityUsersService, nil
}

func (s *IdsecIdentityUsersService) refreshIdentityUsersAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

// CreateUser creates a new user in the identity service.
func (s *IdsecIdentityUsersService) CreateUser(createUser *usersmodels.IdsecIdentityCreateUser) (*usersmodels.IdsecIdentityUser, error) {
	if createUser.Username == "" {
		createUser.Username = fmt.Sprintf("idsec_user_%s", common.RandomString(10))
	}
	if createUser.DisplayName == "" {
		titleCaser := cases.Title(language.English)
		createUser.DisplayName = fmt.Sprintf("%s %s", titleCaser.String(common.RandomString(5)), titleCaser.String(common.RandomString(7)))
	}
	if createUser.Email == "" {
		createUser.Email = fmt.Sprintf("%s@email.com", strings.ToLower(common.RandomString(6)))
	}
	if createUser.MobileNumber == "" {
		createUser.MobileNumber = fmt.Sprintf("+44-987-654-%s", common.RandomNumberString(4))
	}
	if createUser.Password == "" {
		createUser.Password = common.RandomPassword(25)
	}
	if createUser.Roles == nil {
		createUser.Roles = usersmodels.DefaultAdminRoles
	}
	s.Logger.Info("Creating identity user [%s]", createUser.Username)
	if createUser.Suffix == "" {
		directoriesService, err := directories.NewIdsecIdentityDirectoriesService(s.ispAuth)
		if err != nil {
			return nil, err
		}
		createUser.Suffix, err = directoriesService.TenantDefaultSuffix()
		if err != nil {
			return nil, err
		}
	}
	createUserRequest := map[string]interface{}{
		"DisplayName":             createUser.DisplayName,
		"Name":                    fmt.Sprintf("%s@%s", createUser.Username, createUser.Suffix),
		"Mail":                    createUser.Email,
		"Password":                createUser.Password,
		"MobileNumber":            createUser.MobileNumber,
		"InEverybodyRole":         "true",
		"InSysAdminRole":          "false",
		"ForcePasswordChangeNext": "false",
		"SendEmailInvite":         "false",
		"SendSmsInvite":           "false",
	}
	response, err := s.client.Post(context.Background(), createUserURL, createUserRequest)
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
		return nil, fmt.Errorf("failed to create user - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if !result["success"].(bool) {
		return nil, fmt.Errorf("failed to create user - [%v]", result)
	}
	if createUser.Roles != nil {
		rolesService, err := roles.NewIdsecIdentityRolesService(s.ispAuth)
		if err != nil {
			return nil, err
		}
		for _, role := range createUser.Roles {
			err := rolesService.AddUserToRole(&rolesmodels.IdsecIdentityAddUserToRole{
				Username: fmt.Sprintf("%s@%s", createUser.Username, createUser.Suffix),
				RoleName: role,
			})
			if err != nil {
				return nil, err
			}
		}
	}
	userID := result["Result"].(string)
	s.Logger.Info("User created successfully with id [%s]", userID)
	return &usersmodels.IdsecIdentityUser{
		UserID:       userID,
		Username:     fmt.Sprintf("%s@%s", createUser.Username, createUser.Suffix),
		DisplayName:  createUser.DisplayName,
		Email:        createUser.Email,
		MobileNumber: createUser.MobileNumber,
		Roles:        createUser.Roles,
	}, nil
}

// UpdateUser updates an existing user in the identity service.
func (s *IdsecIdentityUsersService) UpdateUser(updateUser *usersmodels.IdsecIdentityUpdateUser) error {
	s.Logger.Info("Updating identity user [%s]", updateUser.Username)
	var err error
	if updateUser.Username != "" && updateUser.UserID == "" {
		updateUser.UserID, err = s.UserIDByName(&usersmodels.IdsecIdentityUserIDByName{Username: updateUser.Username})
		if err != nil {
			return err
		}
	}
	updateMap := make(map[string]interface{})
	if updateUser.NewUsername != "" {
		if !strings.Contains(updateUser.NewUsername, "@") {
			tenantSuffix := strings.Split(updateUser.Username, "@")[1]
			updateUser.NewUsername = fmt.Sprintf("%s@%s", updateUser.NewUsername, tenantSuffix)
		}
		updateMap["Name"] = updateUser.NewUsername
	}
	if updateUser.DisplayName != "" {
		updateMap["DisplayName"] = updateUser.DisplayName
	}
	if updateUser.Email != "" {
		updateMap["Mail"] = updateUser.Email
	}
	if updateUser.MobileNumber != "" {
		updateMap["MobileNumber"] = updateUser.MobileNumber
	}
	updateMap["ID"] = updateUser.UserID
	response, err := s.client.Post(context.Background(), updateUserURL, updateMap)
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
		return fmt.Errorf("failed to update user - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return err
	}
	if !result["success"].(bool) {
		return fmt.Errorf("failed to update user - [%v]", result)
	}
	s.Logger.Info("User updated successfully")
	return nil
}

// DeleteUser deletes an existing user in the identity service.
func (s *IdsecIdentityUsersService) DeleteUser(deleteUser *usersmodels.IdsecIdentityDeleteUser) error {
	s.Logger.Info("Deleting identity user [%s]", deleteUser.Username)
	if deleteUser.Username == "" && deleteUser.UserID == "" {
		return fmt.Errorf("userID or username is required")
	}
	deleteMap := make(map[string]interface{})
	deleteMap["ID"] = deleteUser.UserID
	if deleteUser.UserID == "" && deleteUser.Username != "" {
		deleteMap["ID"] = deleteUser.Username
	}
	response, err := s.client.Post(context.Background(), deleteUserURL, deleteMap)
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
		return fmt.Errorf("failed to delete user - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return err
	}
	if !result["success"].(bool) {
		return fmt.Errorf("failed to delete user - [%v]", result)
	}
	s.Logger.Info("User deleted successfully")
	return nil
}

// DeleteUsers deletes multiple users in the identity service.
func (s *IdsecIdentityUsersService) DeleteUsers(deleteUsers *usersmodels.IdsecIdentityDeleteUsers) error {
	s.Logger.Info("Deleting identity users [%v]", deleteUsers.UserIDs)
	if len(deleteUsers.UserIDs) == 0 {
		return fmt.Errorf("userIDs is required")
	}
	deleteMap := make(map[string]interface{})
	deleteMap["Users"] = deleteUsers.UserIDs
	response, err := s.client.Post(context.Background(), removeUsersURL, deleteMap)
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
		return fmt.Errorf("failed to delete users - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return err
	}
	if !result["success"].(bool) {
		return fmt.Errorf("failed to delete users - [%v]", result)
	}
	s.Logger.Info("Users deleted successfully")
	return nil
}

// UserIDByName retrieves the user ID by username.
func (s *IdsecIdentityUsersService) UserIDByName(user *usersmodels.IdsecIdentityUserIDByName) (string, error) {
	s.Logger.Info("Getting identity user ID by name [%s]", user.Username)
	if user.Username == "" {
		return "", fmt.Errorf("username is required")
	}
	redrockQuery := map[string]interface{}{
		"Script": fmt.Sprintf("Select ID, Username from User WHERE Username='%s'", strings.ToLower(user.Username)),
	}
	response, err := s.client.Post(context.Background(), redrockQueryURL, redrockQuery)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get user ID - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return "", err
	}
	if !result["success"].(bool) {
		return "", fmt.Errorf("failed to get user ID - [%v]", result)
	}
	if len(result["Result"].(map[string]interface{})["Results"].([]interface{})) == 0 {
		return "", fmt.Errorf("failed to retrieve user id by name")
	}
	return result["Result"].(map[string]interface{})["Results"].([]interface{})[0].(map[string]interface{})["Row"].(map[string]interface{})["ID"].(string), nil
}

// UserByName retrieves the user by username.
func (s *IdsecIdentityUsersService) UserByName(user *usersmodels.IdsecIdentityUserByName) (*usersmodels.IdsecIdentityUser, error) {
	s.Logger.Info("Getting identity user by name [%s]", user.Username)
	if user.Username == "" {
		return nil, fmt.Errorf("username is required")
	}
	redrockQuery := map[string]interface{}{
		"Script": fmt.Sprintf("Select ID, Username, DisplayName, Email, MobileNumber, LastLogin from User WHERE Username='%s'", strings.ToLower(user.Username)),
	}
	response, err := s.client.Post(context.Background(), redrockQueryURL, redrockQuery)
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
		return nil, fmt.Errorf("failed to get user - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if !result["success"].(bool) || len(result["Result"].(map[string]interface{})["Results"].([]interface{})) == 0 {
		return nil, fmt.Errorf("failed to retrieve user id by name")
	}

	userRow := result["Result"].(map[string]interface{})["Results"].([]interface{})[0].(map[string]interface{})["Row"].(map[string]interface{})
	var lastLogin *time.Time

	if rawLastLogin, ok := userRow["LastLogin"].(string); ok {
		parts := strings.Split(rawLastLogin, "(")
		if len(parts) > 1 {
			timestamp := strings.Split(parts[1], ")")[0]
			timestamp = fmt.Sprintf("%s.%s", timestamp[:10], timestamp[10:]) // for milliseconds
			parsedTime, err := strconv.ParseFloat(timestamp, 64)
			if err == nil {
				t := time.Unix(0, int64(parsedTime*1e6)).UTC()
				lastLogin = &t
			} else {
				s.Logger.Debug("Failed to parse last login [%s] [%s]", rawLastLogin, err.Error())
			}
		}
	}
	return &usersmodels.IdsecIdentityUser{
		UserID:       userRow["ID"].(string),
		Username:     userRow["Username"].(string),
		DisplayName:  userRow["DisplayName"].(string),
		Email:        userRow["Email"].(string),
		MobileNumber: userRow["MobileNumber"].(string),
		LastLogin:    lastLogin,
	}, nil
}

// UserByID retrieves the user by user ID.
func (s *IdsecIdentityUsersService) UserByID(userByID *usersmodels.IdsecIdentityUserByID) (*usersmodels.IdsecIdentityUser, error) {
	s.Logger.Info("Getting identity user by id [%s]", userByID.UserID)
	if userByID.UserID == "" {
		return nil, fmt.Errorf("userID is required")
	}
	redrockQuery := map[string]interface{}{
		"Script": fmt.Sprintf("Select ID, Username, DisplayName, Email, MobileNumber, LastLogin from User WHERE ID='%s'", userByID.UserID),
	}
	response, err := s.client.Post(context.Background(), redrockQueryURL, redrockQuery)
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
		return nil, fmt.Errorf("failed to get user - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if !result["success"].(bool) || len(result["Result"].(map[string]interface{})["Results"].([]interface{})) == 0 {
		return nil, fmt.Errorf("failed to retrieve user id by name")
	}

	userRow := result["Result"].(map[string]interface{})["Results"].([]interface{})[0].(map[string]interface{})["Row"].(map[string]interface{})
	var lastLogin *time.Time

	if rawLastLogin, ok := userRow["LastLogin"].(string); ok {
		parts := strings.Split(rawLastLogin, "(")
		if len(parts) > 1 {
			timestamp := strings.Split(parts[1], ")")[0]
			timestamp = fmt.Sprintf("%s.%s", timestamp[:10], timestamp[10:]) // for milliseconds
			parsedTime, err := strconv.ParseFloat(timestamp, 64)
			if err == nil {
				t := time.Unix(0, int64(parsedTime*1e6)).UTC()
				lastLogin = &t
			} else {
				s.Logger.Debug("Failed to parse last login [%s] [%s]", rawLastLogin, err.Error())
			}
		}
	}
	return &usersmodels.IdsecIdentityUser{
		UserID:       userRow["ID"].(string),
		Username:     userRow["Username"].(string),
		DisplayName:  userRow["DisplayName"].(string),
		Email:        userRow["Email"].(string),
		MobileNumber: userRow["MobileNumber"].(string),
		LastLogin:    lastLogin,
	}, nil
}

// ResetUserPassword resets the password for an existing user in the identity service.
func (s *IdsecIdentityUsersService) ResetUserPassword(resetUserPassword *usersmodels.IdsecIdentityResetUserPassword) error {
	s.Logger.Info("Resetting identity user password [%s]", resetUserPassword.Username)
	userID, err := s.UserIDByName(&usersmodels.IdsecIdentityUserIDByName{Username: resetUserPassword.Username})
	if err != nil {
		return err
	}
	resetPasswordMap := make(map[string]interface{})
	resetPasswordMap["ID"] = userID
	resetPasswordMap["newPassword"] = resetUserPassword.NewPassword
	response, err := s.client.Post(context.Background(), resetUserPasswordURL, resetPasswordMap)
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
		return fmt.Errorf("failed to reset user password - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return err
	}
	if !result["success"].(bool) {
		return fmt.Errorf("failed to reset user password - [%v]", result)
	}
	s.Logger.Info("User password reset successfully")
	return nil
}

// UserInfo retrieves the user info from the identity service.
func (s *IdsecIdentityUsersService) UserInfo() (*usersmodels.IdsecIdentityUserInfo, error) {
	s.Logger.Info("Getting identity user info")
	userInfoMap := map[string]interface{}{
		"Scopes": []string{"userInfo"},
	}
	response, err := s.client.Post(context.Background(), userInfoURL, userInfoMap)
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
		return nil, fmt.Errorf("failed to get user info - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	var userInfo usersmodels.IdsecIdentityUserInfo
	err = mapstructure.Decode(result, &userInfo)
	if err != nil {
		return nil, err
	}
	return &userInfo, nil
}

// ServiceConfig returns the service configuration for the IdsecIdentityUsersService.
func (s *IdsecIdentityUsersService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
