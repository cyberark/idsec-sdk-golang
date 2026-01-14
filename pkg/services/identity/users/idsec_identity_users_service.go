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

const (
	defaultPageSize             = 10000
	defaultLimit                = 10000
	randomPasswordDefaultLength = 32
)

// IdsecIdentityUsersPage is a page of IdsecIdentityUser items.
type IdsecIdentityUsersPage = common.IdsecPage[usersmodels.IdsecIdentityUser]

// IdsecIdentityUsersService is the service for managing identity users.
type IdsecIdentityUsersService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth            *auth.IdsecISPAuth
	client             *isp.IdsecISPServiceClient
	DirectoriesService *directories.IdsecIdentityDirectoriesService

	DoPost             func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	DoRedrockQueryPost func(ctx context.Context, path string, body interface{}) (*http.Response, error)
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
	identityUsersService.DirectoriesService, err = directories.NewIdsecIdentityDirectoriesService(ispAuth)
	if err != nil {
		return nil, err
	}
	return identityUsersService, nil
}

func (s *IdsecIdentityUsersService) postOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.DoPost != nil {
		return s.DoPost
	}
	return s.client.Post
}

func (s *IdsecIdentityUsersService) redrockQueryPostOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.DoRedrockQueryPost != nil {
		return s.DoRedrockQueryPost
	}
	return s.client.Post
}

func (s *IdsecIdentityUsersService) refreshIdentityUsersAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecIdentityUsersService) parseTimestamp(rawTimestamp string) (*time.Time, error) {
	lastLogin := &time.Time{}
	parts := strings.Split(rawTimestamp, "(")
	if len(parts) > 1 {
		timestamp := strings.Split(parts[1], ")")[0]
		timestamp = fmt.Sprintf("%s.%s", timestamp[:10], timestamp[10:]) // for milliseconds
		parsedTime, err := strconv.ParseFloat(timestamp, 64)
		if err == nil {
			t := time.Unix(0, int64(parsedTime*1e6)).UTC()
			lastLogin = &t
		} else {
			return nil, err
		}
	}
	return lastLogin, nil
}

// CreateUser creates a new user in the identity service.
func (s *IdsecIdentityUsersService) CreateUser(createUser *usersmodels.IdsecIdentityCreateUser) (*usersmodels.IdsecIdentityUser, error) {
	if createUser.Username == "" || createUser.Email == "" {
		return nil, fmt.Errorf("username and email are required")
	}
	if createUser.DisplayName == "" {
		parts := strings.Split(createUser.Username, "@")
		// Check if theres _ or . in the name part to convert to space
		parts[0] = strings.ReplaceAll(parts[0], "_", " ")
		parts[0] = strings.ReplaceAll(parts[0], ".", " ")
		createUser.DisplayName = cases.Title(language.English).String(parts[0])
	}
	if createUser.Password == "" {
		createUser.Password = common.RandomPassword(randomPasswordDefaultLength)
	}
	s.Logger.Info("Creating identity user [%s]", createUser.Username)
	if createUser.Suffix == "" {
		if strings.Contains(createUser.Username, "@") {
			parts := strings.Split(createUser.Username, "@")
			createUser.Suffix = parts[1]
		} else {
			var err error
			createUser.Suffix, err = s.DirectoriesService.TenantDefaultSuffix()
			if err != nil {
				return nil, err
			}
		}
	}
	if !strings.Contains(createUser.Username, "@") {
		createUser.Username = fmt.Sprintf("%s@%s", createUser.Username, createUser.Suffix)
	}
	if createUser.InEverybodyRole == nil {
		defaultInEverybodyRole := true
		createUser.InEverybodyRole = &defaultInEverybodyRole
	}
	if createUser.InSysAdminRole == nil {
		defaultInSysAdminRole := false
		createUser.InSysAdminRole = &defaultInSysAdminRole
	}
	if createUser.ForcePasswordChangeNext == nil {
		defaultForcePasswordChangeNext := true
		createUser.ForcePasswordChangeNext = &defaultForcePasswordChangeNext
	}
	if createUser.SendEmailInvite == nil {
		defaultSendEmailInvite := false
		createUser.SendEmailInvite = &defaultSendEmailInvite
	}
	if createUser.SendSmsInvite == nil {
		defaultSendSmsInvite := false
		createUser.SendSmsInvite = &defaultSendSmsInvite
	}
	createUserRequest := map[string]interface{}{
		"DisplayName":             createUser.DisplayName,
		"Name":                    createUser.Username,
		"Mail":                    createUser.Email,
		"Password":                createUser.Password,
		"MobileNumber":            createUser.MobileNumber,
		"InEverybodyRole":         fmt.Sprintf("%v", *createUser.InEverybodyRole),
		"InSysAdminRole":          fmt.Sprintf("%v", *createUser.InSysAdminRole),
		"ForcePasswordChangeNext": fmt.Sprintf("%v", *createUser.ForcePasswordChangeNext),
		"SendEmailInvite":         fmt.Sprintf("%v", *createUser.SendEmailInvite),
		"SendSmsInvite":           fmt.Sprintf("%v", *createUser.SendSmsInvite),
	}
	response, err := s.postOperation()(context.Background(), createUserURL, createUserRequest)
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
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to create user - [%v]", result)
	}
	if _, ok := result["Result"].(string); !ok {
		return nil, fmt.Errorf("failed to retrieve created user id - [%v]", result)
	}
	userID := result["Result"].(string)
	s.Logger.Info("User created successfully with id [%s]", userID)
	return &usersmodels.IdsecIdentityUser{
		UserID:       userID,
		Username:     createUser.Username,
		Password:     &createUser.Password,
		DisplayName:  createUser.DisplayName,
		Email:        createUser.Email,
		MobileNumber: createUser.MobileNumber,
		Suffix:       createUser.Suffix,
		LastLogin:    nil,
	}, nil
}

// UpdateUser updates an existing user in the identity service.
func (s *IdsecIdentityUsersService) UpdateUser(updateUser *usersmodels.IdsecIdentityUpdateUser) (*usersmodels.IdsecIdentityUser, error) {
	s.Logger.Info("Updating identity user [%s]", updateUser.UserID)
	updateMap := make(map[string]interface{})
	if updateUser.Username != "" {
		if !strings.Contains(updateUser.Username, "@") {
			tenantSuffix, err := s.DirectoriesService.TenantDefaultSuffix()
			if err != nil {
				return nil, err
			}
			updateUser.Username = fmt.Sprintf("%s@%s", updateUser.Username, tenantSuffix)
		}
		updateMap["Name"] = updateUser.Username
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
	if updateUser.InEverybodyRole != nil {
		updateMap["InEverybodyRole"] = fmt.Sprintf("%v", *updateUser.InEverybodyRole)
	}
	if updateUser.InSysAdminRole != nil {
		updateMap["InSysAdminRole"] = fmt.Sprintf("%v", *updateUser.InSysAdminRole)
	}
	if updateUser.ForcePasswordChangeNext != nil {
		updateMap["ForcePasswordChangeNext"] = fmt.Sprintf("%v", *updateUser.ForcePasswordChangeNext)
	}
	if updateUser.SendEmailInvite != nil {
		updateMap["SendEmailInvite"] = fmt.Sprintf("%v", *updateUser.SendEmailInvite)
	}
	if updateUser.SendSmsInvite != nil {
		updateMap["SendSmsInvite"] = fmt.Sprintf("%v", *updateUser.SendSmsInvite)
	}
	updateMap["ID"] = updateUser.UserID
	response, err := s.postOperation()(context.Background(), updateUserURL, updateMap)
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
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to update user - [%v]", result)
	}
	s.Logger.Info("User updated successfully")
	return s.User(&usersmodels.IdsecIdentityGetUser{UserID: updateUser.UserID})
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
	response, err := s.postOperation()(context.Background(), deleteUserURL, deleteMap)
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
	response, err := s.postOperation()(context.Background(), removeUsersURL, deleteMap)
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
	if res, ok := result["success"].(bool); !ok || !res {
		return fmt.Errorf("failed to delete users - [%v]", result)
	}
	s.Logger.Info("Users deleted successfully")
	return nil
}

// User retrieves the user by username.
func (s *IdsecIdentityUsersService) User(user *usersmodels.IdsecIdentityGetUser) (*usersmodels.IdsecIdentityUser, error) {
	s.Logger.Info("Getting identity user by name [%s]", user.Username)
	if user.Username == "" && user.UserID == "" {
		return nil, fmt.Errorf("username or userID is required")
	}
	var redrockQuery map[string]interface{}
	if user.UserID != "" {
		redrockQuery = map[string]interface{}{
			"Script": fmt.Sprintf("Select ID, Username, DisplayName, Email, MobileNumber, LastLogin from User WHERE ID='%s'", user.UserID),
		}
	} else {
		redrockQuery = map[string]interface{}{
			"Script": fmt.Sprintf("Select ID, Username, DisplayName, Email, MobileNumber, LastLogin from User WHERE Username='%s'", strings.ToLower(user.Username)),
		}
	}
	response, err := s.redrockQueryPostOperation()(context.Background(), redrockQueryURL, redrockQuery)
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
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to retrieve user id by name")
	}
	if _, ok := result["Result"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("user not found")
	}
	if _, ok := result["Result"].(map[string]interface{})["Results"].([]interface{}); !ok {
		return nil, fmt.Errorf("user not found")
	}
	if len(result["Result"].(map[string]interface{})["Results"].([]interface{})) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	userRow := result["Result"].(map[string]interface{})["Results"].([]interface{})[0].(map[string]interface{})["Row"].(map[string]interface{})
	var lastLogin *time.Time

	if rawLastLogin, ok := userRow["LastLogin"].(string); ok {
		lastLogin, err = s.parseTimestamp(rawLastLogin)
		if err != nil {
			s.Logger.Debug("Failed to parse last login [%s] [%s]", rawLastLogin, err.Error())
		}
	}
	return &usersmodels.IdsecIdentityUser{
		UserID:       userRow["ID"].(string),
		Username:     userRow["Username"].(string),
		DisplayName:  userRow["DisplayName"].(string),
		Email:        userRow["Email"].(string),
		MobileNumber: userRow["MobileNumber"].(string),
		Suffix:       strings.Split(userRow["Username"].(string), "@")[1],
		LastLogin:    lastLogin,
	}, nil
}

func (s *IdsecIdentityUsersService) listUsers(pageSize int, limit int, pageNumber int, maxPageCount int, search string) (<-chan *IdsecIdentityUsersPage, error) {
	s.Logger.Info("Listing identity users")

	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if limit <= 0 {
		limit = defaultLimit
	}
	if maxPageCount == 0 {
		maxPageCount = -1
	}

	output := make(chan *IdsecIdentityUsersPage)

	go func() {
		defer close(output)

		pageNumber := 1
		totalRetrieved := 0

		for maxPageCount <= 0 || pageNumber <= maxPageCount {
			// Check if we've reached the limit
			if totalRetrieved >= limit {
				break
			}

			// Build the query with pagination
			script := "Select ID, Username, DisplayName, Email, MobileNumber, LastLogin from User"
			if search != "" {
				script += fmt.Sprintf(" WHERE Username LIKE '%%%s%%' OR DisplayName LIKE '%%%s%%' OR Email LIKE '%%%s%%'",
					search, search, search)
			}

			redrockQuery := map[string]interface{}{
				"Script": script,
				"args": map[string]interface{}{
					"PageNumber": pageNumber,
					"PageSize":   pageSize,
					"Limit":      limit - totalRetrieved,
				},
			}

			response, err := s.redrockQueryPostOperation()(context.Background(), redrockQueryURL, redrockQuery)
			if err != nil {
				s.Logger.Error("Failed to list users: %v", err)
				return
			}

			if response.StatusCode != http.StatusOK {
				s.Logger.Error("Failed to list users - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
				_ = response.Body.Close()
				return
			}

			var result map[string]interface{}
			err = json.NewDecoder(response.Body).Decode(&result)
			_ = response.Body.Close()

			if err != nil {
				s.Logger.Error("Failed to decode response: %v", err)
				return
			}

			if res, ok := result["success"].(bool); !ok || !res {
				s.Logger.Error("Failed to retrieve users: %v", result)
				return
			}
			if _, ok := result["Result"].(map[string]interface{}); !ok {
				s.Logger.Info("No more users found")
				break
			}
			results, ok := result["Result"].(map[string]interface{})["Results"].([]interface{})
			if !ok || len(results) == 0 {
				break
			}

			users := make([]*usersmodels.IdsecIdentityUser, 0, len(results))
			for _, item := range results {
				userRow := item.(map[string]interface{})["Row"].(map[string]interface{})
				var lastLogin *time.Time

				if rawLastLogin, ok := userRow["LastLogin"].(string); ok {
					lastLogin, err = s.parseTimestamp(rawLastLogin)
					if err != nil {
						s.Logger.Debug("Failed to parse last login [%s] [%s]", rawLastLogin, err.Error())
					}
				}

				users = append(users, &usersmodels.IdsecIdentityUser{
					UserID:       userRow["ID"].(string),
					Username:     userRow["Username"].(string),
					DisplayName:  userRow["DisplayName"].(string),
					Email:        userRow["Email"].(string),
					MobileNumber: userRow["MobileNumber"].(string),
					LastLogin:    lastLogin,
				})

				totalRetrieved++
				if totalRetrieved >= limit {
					break
				}
			}

			if len(users) > 0 {
				output <- &IdsecIdentityUsersPage{Items: users}
			}

			// If we got fewer results than page size, we've reached the end
			if len(results) < pageSize {
				break
			}

			pageNumber++
		}
	}()

	return output, nil
}

// ListUsers retrieves users with pagination using channels.
//
// ListUsers queries the identity service for users matching the provided criteria
// and returns a channel that yields pages of users. The function supports pagination
// with configurable page size and limits.
//
// Parameters:
//   - listUsers: The list users request containing search and pagination parameters
//
// Returns a channel of user pages and any error encountered during the initial query.
// The channel is closed when all pages have been sent or an error occurs.
//
// Example:
//
//	pages, err := service.ListUsers(&usersmodels.IdsecIdentityListUsers{
//	    Search: "john",
//	    PageSize: 100,
//	})
//	if err != nil {
//	    return err
//	}
//	for page := range pages {
//	    for _, user := range page.Items {
//	        fmt.Printf("User: %s\n", user.Username)
//	    }
//	}
func (s *IdsecIdentityUsersService) ListUsers() (<-chan *IdsecIdentityUsersPage, error) {
	return s.listUsers(defaultPageSize, defaultLimit, 1, -1, "")
}

// ListUsersBy retrieves users based on the provided filters with pagination using channels.
//
// ListUsersBy queries the identity service for users matching the provided filters
// and returns a channel that yields pages of users. The function supports pagination
// with configurable page size, limits, and search criteria.
//
// Parameters:
//   - userFilters: The filters to apply when listing users, including search string,
//     page size, limit, maximum page count, and starting page number.
//
// Returns a channel of user pages and any error encountered during the initial query.
// The channel is closed when all pages have been sent or an error occurs.
//
// Example:
//
//	pages, err := service.ListUsersBy(&usersmodels.IdsecIdentityUserFilters{
//	    Search: "john",
//	    PageSize: 100,
//	    Limit: 500,
//	    MaxPageCount: 5,
//	    PageNumber: 1,
//	})
//	if err != nil {
//	    return err
//	}
//	for page := range pages {
//	    for _, user := range page.Items {
//	        fmt.Printf("User: %s\n", user.Username)
//	    }
//	}
func (s *IdsecIdentityUsersService) ListUsersBy(userFilters *usersmodels.IdsecIdentityUserFilters) (<-chan *IdsecIdentityUsersPage, error) {
	return s.listUsers(userFilters.PageSize, userFilters.Limit, userFilters.PageNumber, userFilters.MaxPageCount, userFilters.Search)
}

// ResetUserPassword resets the password for an existing user in the identity service.
func (s *IdsecIdentityUsersService) ResetUserPassword(resetUserPassword *usersmodels.IdsecIdentityResetUserPassword) error {
	s.Logger.Info("Resetting identity user password [%s]", resetUserPassword.Username)
	user, err := s.User(&usersmodels.IdsecIdentityGetUser{Username: resetUserPassword.Username})
	if err != nil {
		return err
	}
	resetPasswordMap := make(map[string]interface{})
	resetPasswordMap["ID"] = user.UserID
	resetPasswordMap["newPassword"] = resetUserPassword.NewPassword
	response, err := s.postOperation()(context.Background(), resetUserPasswordURL, resetPasswordMap)
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
	if res, ok := result["success"].(bool); !ok || !res {
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
	response, err := s.postOperation()(context.Background(), userInfoURL, userInfoMap)
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
	result, err := common.DeserializeJSONSnake(response.Body)
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

// UsersStats retrieves statistics about users in the identity service.
func (s *IdsecIdentityUsersService) UsersStats() (*usersmodels.IdsecIdentityUsersStats, error) {
	s.Logger.Info("Getting identity users stats")
	pages, err := s.ListUsers()
	if err != nil {
		return nil, err
	}
	totalUsers := 0
	for page := range pages {
		totalUsers += len(page.Items)
	}
	return &usersmodels.IdsecIdentityUsersStats{
		UsersCount: totalUsers,
	}, nil
}

// ServiceConfig returns the service configuration for the IdsecIdentityUsersService.
func (s *IdsecIdentityUsersService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
