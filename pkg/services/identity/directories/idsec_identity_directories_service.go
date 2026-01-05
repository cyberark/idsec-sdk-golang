package directories

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common/identity"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	directoriesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories/models"

	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const (
	tenantSuffixURL          = "Core/GetCdsAliasesForTenant"
	getDirectoryServicesURL  = "Core/GetDirectoryServices"
	directoryServiceQueryURL = "UserMgmt/DirectoryServiceQuery"
)

// IdsecIdentityEntitiesPage is a page of IdsecIdentityBaseEntity items.
type IdsecIdentityEntitiesPage = common.IdsecPage[directoriesmodels.IdsecIdentityEntity]

// IdsecIdentityDirectoriesService is the service for managing identity directories.
type IdsecIdentityDirectoriesService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
	env     commonmodels.EnvObject
}

// NewIdsecIdentityDirectoriesService creates a new instance of IdsecIdentityDirectoriesService.
func NewIdsecIdentityDirectoriesService(authenticators ...auth.IdsecAuth) (*IdsecIdentityDirectoriesService, error) {
	identityDirectoriesService := &IdsecIdentityDirectoriesService{}
	var identityDirectoriesServiceInterface services.IdsecService = identityDirectoriesService
	baseService, err := services.NewIdsecBaseService(identityDirectoriesServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "", "", "api/idadmin", identityDirectoriesService.refreshIdentityDirectoriesAuth)
	if err != nil {
		return nil, err
	}
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(ispAuth.Token.Token, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	claims := parsedToken.Claims.(jwt.MapClaims)
	identityIss := claims["iss"].(string)
	identityURL, err := url.Parse(identityIss)
	if err != nil {
		return nil, fmt.Errorf("failed to parse identity URL: %w", err)
	}
	// Directories API for some reason do not work directly with the platform URL
	// So we use identity URL directly here
	client.BaseURL = fmt.Sprintf("%s://%s", identityURL.Scheme, identityURL.Host)
	client.UpdateHeaders(map[string]string{
		"X-IDAP-NATIVE-CLIENT": "true",
	})
	awsEnvList, isExist := commonmodels.GetAwsEnvFromList()
	if !isExist {
		return nil, fmt.Errorf("%s env is not supported", awsEnvList.AwsEnv)
	}
	identityDirectoriesService.client = client
	identityDirectoriesService.ispAuth = ispAuth
	identityDirectoriesService.IdsecBaseService = baseService
	identityDirectoriesService.env = awsEnvList
	return identityDirectoriesService, nil
}

func (s *IdsecIdentityDirectoriesService) refreshIdentityDirectoriesAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

// ListDirectories retrieves the directory services for the specified directories.
func (s *IdsecIdentityDirectoriesService) ListDirectories(listDirectories *directoriesmodels.IdsecIdentityListDirectories) ([]*directoriesmodels.IdsecIdentityDirectory, error) {
	if len(listDirectories.Directories) == 0 {
		listDirectories.Directories = identity.AllDirectoryTypes
	}
	s.Logger.Info("Retrieving directory services for directories [%v]", listDirectories)
	response, err := s.client.Get(context.Background(), getDirectoryServicesURL, nil)
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
		return nil, fmt.Errorf("failed to get directory services - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if !result["success"].(bool) {
		return nil, fmt.Errorf("failed to list directories - [%v]", result)
	}
	var directoriesResponse identity.GetDirectoryServicesResponse
	err = mapstructure.Decode(result, &directoriesResponse)
	if err != nil {
		return nil, err
	}
	var directories []*directoriesmodels.IdsecIdentityDirectory
	for _, service := range directoriesResponse.Result.Results {
		if slices.Contains(listDirectories.Directories, service.Row.Service) {
			directories = append(directories, &directoriesmodels.IdsecIdentityDirectory{
				Directory:            service.Row.Service,
				DirectoryServiceUUID: service.Row.DirectoryServiceUUID,
			})
		}
	}
	if len(directories) == 0 {
		return nil, fmt.Errorf("could not find any directory services matching [%v]", listDirectories.Directories)
	}
	return directories, nil
}

// ListDirectoriesEntities retrieves the entities for the specified directories.
func (s *IdsecIdentityDirectoriesService) ListDirectoriesEntities(listDirectoriesEntities *directoriesmodels.IdsecIdentityListDirectoriesEntities) (<-chan *IdsecIdentityEntitiesPage, error) {
	s.Logger.Info("Listing directories entities")
	directories, err := s.ListDirectories(&directoriesmodels.IdsecIdentityListDirectories{
		Directories: listDirectoriesEntities.Directories,
	})
	if err != nil {
		return nil, err
	}
	if len(listDirectoriesEntities.EntityTypes) == 0 {
		listDirectoriesEntities.EntityTypes = []string{directoriesmodels.EntityTypeUser, directoriesmodels.EntityTypeGroup, directoriesmodels.EntityTypeRole}
	}
	directoriesUuids := make([]string, 0, len(directories))
	for _, directory := range directories {
		directoriesUuids = append(directoriesUuids, directory.DirectoryServiceUUID)
	}

	exclusions := make([]string, 0)
	if len(listDirectoriesEntities.EntityTypes) >= 0 {
		if !slices.Contains(listDirectoriesEntities.EntityTypes, directoriesmodels.EntityTypeUser) {
			exclusions = append(exclusions, "user")
		}
		if !slices.Contains(listDirectoriesEntities.EntityTypes, directoriesmodels.EntityTypeGroup) {
			exclusions = append(exclusions, "group")
		}
		if !slices.Contains(listDirectoriesEntities.EntityTypes, directoriesmodels.EntityTypeRole) {
			exclusions = append(exclusions, "roles")
		}
	}
	directoryRequest := identity.NewDirectoryServiceQueryRequest(listDirectoriesEntities.Search)
	directoryRequest.DirectoryServices = directoriesUuids
	directoryRequest.Args.PageSize = listDirectoriesEntities.PageSize
	directoryRequest.Args.Limit = listDirectoriesEntities.Limit
	directoryRequest.Args.PageNumber = 1
	directoryRequestMap := make(map[string]interface{})
	err = mapstructure.Decode(directoryRequest, &directoryRequestMap)
	if err != nil {
		return nil, err
	}
	for _, exclusion := range exclusions {
		delete(directoryRequestMap, exclusion)
	}
	response, err := s.client.Post(context.Background(), directoryServiceQueryURL, directoryRequestMap)
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
		return nil, fmt.Errorf("failed to get directory entities - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if !result["success"].(bool) {
		return nil, fmt.Errorf("failed to list directories entities - [%v]", result)
	}
	var directoryServiceQueryResponse identity.DirectoryServiceQueryResponse
	err = mapstructure.Decode(result, &directoryServiceQueryResponse)
	if err != nil {
		return nil, err
	}
	entities := make([]*directoriesmodels.IdsecIdentityEntity, 0)
	if directoryServiceQueryResponse.Result.Users != nil && len(directoryServiceQueryResponse.Result.Users.Results) > 0 {
		for _, user := range directoryServiceQueryResponse.Result.Users.Results {
			userEntity := &directoriesmodels.IdsecIdentityUserEntity{
				IdsecIdentityBaseEntity: directoriesmodels.IdsecIdentityBaseEntity{
					ID:                       user.Row.InternalID,
					Name:                     user.Row.SystemName,
					EntityType:               directoriesmodels.EntityTypeUser,
					DirectoryServiceType:     user.Row.DirectoryServiceType,
					DisplayName:              user.Row.DisplayName,
					ServiceInstanceLocalized: user.Row.ServiceInstanceLocalized,
				},
				Email:       user.Row.Email,
				Description: user.Row.Description,
			}
			var userEntityIfs directoriesmodels.IdsecIdentityEntity = userEntity
			entities = append(entities, &userEntityIfs)
		}
	}
	if directoryServiceQueryResponse.Result.Groups != nil && len(directoryServiceQueryResponse.Result.Groups.Results) > 0 {
		for _, group := range directoryServiceQueryResponse.Result.Groups.Results {
			groupEntity := &directoriesmodels.IdsecIdentityGroupEntity{
				IdsecIdentityBaseEntity: directoriesmodels.IdsecIdentityBaseEntity{
					ID:                       group.Row.InternalID,
					Name:                     group.Row.SystemName,
					EntityType:               directoriesmodels.EntityTypeGroup,
					DirectoryServiceType:     group.Row.DirectoryServiceType,
					DisplayName:              group.Row.DisplayName,
					ServiceInstanceLocalized: group.Row.ServiceInstanceLocalized,
				},
			}
			var groupEntityIfs directoriesmodels.IdsecIdentityEntity = groupEntity
			entities = append(entities, &groupEntityIfs)
		}
	}
	if directoryServiceQueryResponse.Result.Roles != nil && len(directoryServiceQueryResponse.Result.Roles.Results) > 0 {
		for _, role := range directoryServiceQueryResponse.Result.Roles.Results {
			roleEntity := &directoriesmodels.IdsecIdentityRoleEntity{
				IdsecIdentityBaseEntity: directoriesmodels.IdsecIdentityBaseEntity{
					ID:                       role.Row.ID,
					Name:                     role.Row.Name,
					EntityType:               directoriesmodels.EntityTypeRole,
					DirectoryServiceType:     identity.Identity,
					DisplayName:              role.Row.Name,
					ServiceInstanceLocalized: identity.Identity,
				},
				AdminRights: role.Row.AdminRights,
				IsHidden:    role.Row.IsHidden,
				Description: role.Row.Description,
			}
			var roleEntityIfs directoriesmodels.IdsecIdentityEntity = roleEntity
			entities = append(entities, &roleEntityIfs)
		}
	}
	output := make(chan *IdsecIdentityEntitiesPage)
	go func() {
		defer close(output)
		for len(entities) > 0 {
			if len(entities) <= listDirectoriesEntities.PageSize {
				output <- &IdsecIdentityEntitiesPage{Items: entities}
				break
			} else {
				page := entities[:listDirectoriesEntities.PageSize]
				entities = entities[listDirectoriesEntities.PageSize:]
				output <- &IdsecIdentityEntitiesPage{Items: page}
			}
		}
	}()
	return output, nil
}

// TenantDefaultSuffix retrieves the default tenant suffix for the identity directories service.
func (s *IdsecIdentityDirectoriesService) TenantDefaultSuffix() (string, error) {
	s.Logger.Info("Discovering default tenant suffix")
	response, err := s.client.Post(context.Background(), tenantSuffixURL, nil)
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
		return "", fmt.Errorf("failed to get tenant default suffix - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return "", err
	}
	tenantSuffixesResult := identity.GetTenantSuffixResult{}
	err = mapstructure.Decode(result, &tenantSuffixesResult)
	if err != nil {
		return "", err
	}
	var tenantSuffixesList []string
	for _, res := range tenantSuffixesResult.Result["Results"].([]interface{}) {
		entities := res.(map[string]interface{})["Entities"].([]interface{})
		if len(entities) > 0 {
			tenantSuffixesList = append(tenantSuffixesList, entities[0].(map[string]interface{})["Key"].(string))
		}
	}
	if len(tenantSuffixesList) == 0 {
		return "", fmt.Errorf("no tenant suffix has been found")
	}
	var filteredUrls []string
	for _, suffix := range tenantSuffixesList {
		if commonmodels.CheckIfIdentityGeneratedSuffix(suffix) || strings.Contains(suffix, s.env.RootDomain) {
			filteredUrls = append(filteredUrls, suffix)
		}
	}
	if len(filteredUrls) > 0 {
		return filteredUrls[0], nil
	}
	return tenantSuffixesList[0], nil
}

// ServiceConfig returns the service configuration for the IdsecIdentityDirectoriesService.
func (s *IdsecIdentityDirectoriesService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
