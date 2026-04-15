package applications

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/go-viper/mapstructure/v2"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"

	applicationsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/applications/models"
	commonpcloud "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/common"
)

const (
	applicationsURL           = "WebServices/PIMServices.svc/Applications"
	applicationURL            = "WebServices/PIMServices.svc/Applications/%s"
	applicationAuthMethodsURL = "WebServices/PIMServices.svc/Applications/%s/Authentications"
	applicationAuthMethodURL  = "WebServices/PIMServices.svc/Applications/%s/Authentications/%s"
)

// IdsecPCloudApplicationsService is the service for managing pCloud Applications.
type IdsecPCloudApplicationsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService

	doGet    func(ctx context.Context, path string, params interface{}) (*http.Response, error)
	doPost   func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	doDelete func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error)
}

// NewIdsecPCloudApplicationsService creates a new instance of IdsecPCloudApplicationsService.
func NewIdsecPCloudApplicationsService(authenticators ...auth.IdsecAuth) (*IdsecPCloudApplicationsService, error) {
	pcloudApplicationsService := &IdsecPCloudApplicationsService{}
	var pcloudApplicationsServiceInterface services.IdsecService = pcloudApplicationsService
	baseService, err := services.NewIdsecBaseService(pcloudApplicationsServiceInterface, authenticators...)
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
		"passwordvault",
		pcloudApplicationsService.refreshPCloudApplicationsAuth,
		commonpcloud.DefaultPCloudRetryStrategy(),
	)
	if err != nil {
		return nil, err
	}

	pcloudApplicationsService.IdsecBaseService = baseService
	pcloudApplicationsService.IdsecISPBaseService = ispBaseService
	return pcloudApplicationsService, nil
}

func (s *IdsecPCloudApplicationsService) refreshPCloudApplicationsAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecPCloudApplicationsService) getOperation() func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
	if s.doGet != nil {
		return s.doGet
	}
	return s.ISPClient().Get
}

func (s *IdsecPCloudApplicationsService) postOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.doPost != nil {
		return s.doPost
	}
	return s.ISPClient().Post
}

func (s *IdsecPCloudApplicationsService) deleteOperation() func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error) {
	if s.doDelete != nil {
		return s.doDelete
	}
	return s.ISPClient().Delete
}

// Create creates a new pCloud application.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud/Latest/en/Content/WebServices/Add%20Application.htm
func (s *IdsecPCloudApplicationsService) Create(createApplication *applicationsmodels.IdsecPCloudCreateApplication) (*applicationsmodels.IdsecPCloudApplication, error) {
	s.Logger.Info("Creating pCloud application")
	createAppJSON, err := common.SerializeJSONPascal(createApplication)
	if err != nil {
		return nil, err
	}
	delete(createAppJSON, "AppId")
	createAppJSON["AppID"] = createApplication.AppID
	response, err := s.postOperation()(context.Background(), applicationsURL, map[string]interface{}{"application": createAppJSON})
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
		return nil, fmt.Errorf("failed to create application - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return s.Get(&applicationsmodels.IdsecPCloudGetApplication{AppID: createApplication.AppID})
}

// Get retrieves a pCloud application.
// https://docs.cyberark.com/privilege-cloud-standard/latest/en/content/webservices/list%20a%20specific%20application.htm
func (s *IdsecPCloudApplicationsService) Get(getApplication *applicationsmodels.IdsecPCloudGetApplication) (*applicationsmodels.IdsecPCloudApplication, error) {
	s.Logger.Info("Retrieving pCloud application")
	response, err := s.getOperation()(context.Background(), fmt.Sprintf(applicationURL, getApplication.AppID), nil)
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
		return nil, fmt.Errorf("failed to retrieve application - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	applicationJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	applicationsJSONMap := applicationJSON.(map[string]interface{})
	applicationJSONMap, ok := applicationsJSONMap["application"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid application response format")
	}
	if appID, ok := applicationJSONMap["app_i_d"]; ok {
		applicationJSONMap["app_id"] = appID
	}
	var application applicationsmodels.IdsecPCloudApplication
	err = mapstructure.Decode(applicationJSONMap, &application)
	if err != nil {
		return nil, err
	}
	return &application, nil
}

// Delete deletes a pCloud application.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud/Latest/en/Content/WebServices/Delete%20a%20Specific%20Application.htm
func (s *IdsecPCloudApplicationsService) Delete(deleteApplication *applicationsmodels.IdsecPCloudDeleteApplication) error {
	s.Logger.Info("Deleting pCloud application")
	response, err := s.deleteOperation()(context.Background(), fmt.Sprintf(applicationURL, deleteApplication.AppID), nil, nil)
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
		return fmt.Errorf("failed to delete application - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// List lists all pCloud applications.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud/Latest/en/Content/WebServices/List%20Applications.htm
func (s *IdsecPCloudApplicationsService) List() ([]*applicationsmodels.IdsecPCloudApplication, error) {
	s.Logger.Info("Listing pCloud applications")
	response, err := s.getOperation()(context.Background(), applicationsURL, nil)
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
		return nil, fmt.Errorf("failed to list applications - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	applicationsJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	applicationsJSONMap := applicationsJSON.(map[string]interface{})
	applicationsJSONArray, ok := applicationsJSONMap["application"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid applications response format")
	}
	applications := []*applicationsmodels.IdsecPCloudApplication{}
	for _, appJSON := range applicationsJSONArray {
		appJSONMap, ok := appJSON.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid application format in applications list")
		}
		if appID, ok := appJSONMap["app_i_d"]; ok {
			appJSONMap["app_id"] = appID
		}
		var application applicationsmodels.IdsecPCloudApplication
		err = mapstructure.Decode(appJSONMap, &application)
		if err != nil {
			return nil, err
		}
		applications = append(applications, &application)
	}
	return applications, nil
}

// ListBy lists pCloud applications based on the provided filter.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud/Latest/en/Content/WebServices/List%20Applications.htm
func (s *IdsecPCloudApplicationsService) ListBy(filter *applicationsmodels.IdsecPCloudApplicationsFilter) ([]*applicationsmodels.IdsecPCloudApplication, error) {
	s.Logger.Info("Listing pCloud applications by filter")
	applications, err := s.List()
	if err != nil {
		return nil, err
	}
	filteredApplications := []*applicationsmodels.IdsecPCloudApplication{}
	for _, app := range applications {
		if filter.Location != "" && app.Location != filter.Location {
			continue
		}
		if filter.OnlyEnabled != nil && *filter.OnlyEnabled && app.Disabled {
			continue
		}
		if filter.BusinessOwnerName != "" {
			fullName := fmt.Sprintf("%s %s", app.BusinessOwnerFName, app.BusinessOwnerLName)
			if fullName != filter.BusinessOwnerName {
				continue
			}
		}
		if filter.BusinessOwnerEmail != "" && app.BusinessOwnerEmail != filter.BusinessOwnerEmail {
			continue
		}
		filteredApplications = append(filteredApplications, app)
	}
	return filteredApplications, nil
}

// CreateAuthMethod creates a new pCloud application auth method.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud/Latest/en/Content/WebServices/Add%20Authentication.htm
func (s *IdsecPCloudApplicationsService) CreateAuthMethod(createApplicationAuthMethod *applicationsmodels.IdsecPCloudCreateApplicationAuthMethod) (*applicationsmodels.IdsecPCloudApplicationAuthMethod, error) {
	s.Logger.Info("Creating pCloud application auth method")
	authMethodJSON := map[string]interface{}{
		"AuthType": createApplicationAuthMethod.AuthType,
	}
	switch createApplicationAuthMethod.AuthType {
	case applicationsmodels.ApplicationAuthMethodHash,
		applicationsmodels.ApplicationAuthMethodMachineAddress,
		applicationsmodels.ApplicationAuthMethodOsUser,
		applicationsmodels.ApplicationAuthMethodPath,
		applicationsmodels.ApplicationAuthMethodCertificateSerialNumber:
		if createApplicationAuthMethod.AuthValue == "" {
			return nil, fmt.Errorf("auth value is required")
		}
		authMethodJSON["AuthValue"] = createApplicationAuthMethod.AuthValue
		authMethodJSON["Comment"] = createApplicationAuthMethod.Comment
		if createApplicationAuthMethod.AuthType == applicationsmodels.ApplicationAuthMethodPath {
			authMethodJSON["IsFolder"] = createApplicationAuthMethod.IsFolder
			authMethodJSON["AllowInternalScripts"] = createApplicationAuthMethod.AllowInternalScripts
		}
	case applicationsmodels.ApplicationAuthMethodCertificateAttr:
		if createApplicationAuthMethod.Subject == nil && createApplicationAuthMethod.Issuer == nil && createApplicationAuthMethod.SubjectAlternateName == nil {
			return nil, fmt.Errorf("at least one of subject, issuer, or subject alternate name must be provided for certificate attribute auth type")
		}
		authMethodJSON["AuthValue"] = createApplicationAuthMethod.AuthValue
		if createApplicationAuthMethod.Subject != nil {
			authMethodJSON["Subject"] = createApplicationAuthMethod.Subject
		}
		if createApplicationAuthMethod.Issuer != nil {
			authMethodJSON["Issuer"] = createApplicationAuthMethod.Issuer
		}
		if createApplicationAuthMethod.SubjectAlternateName != nil {
			authMethodJSON["SubjectAlternateName"] = createApplicationAuthMethod.SubjectAlternateName
		}
	case applicationsmodels.ApplicationAuthMethodKubernetes:
		if createApplicationAuthMethod.Namespace == "" || createApplicationAuthMethod.Image == "" || createApplicationAuthMethod.EnvVarName == "" || createApplicationAuthMethod.EnvVarValue == "" {
			return nil, fmt.Errorf("all Kubernetes fields must be provided for Kubernetes auth type")
		}
		authMethodJSON["AuthValue"] = createApplicationAuthMethod.AuthValue
		authMethodJSON["Namespace"] = createApplicationAuthMethod.Namespace
		authMethodJSON["Image"] = createApplicationAuthMethod.Image
		authMethodJSON["EnvVarName"] = createApplicationAuthMethod.EnvVarName
		authMethodJSON["EnvVarValue"] = createApplicationAuthMethod.EnvVarValue
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", createApplicationAuthMethod.AuthType)
	}
	response, err := s.postOperation()(context.Background(), fmt.Sprintf(applicationAuthMethodsURL, createApplicationAuthMethod.AppID), map[string]interface{}{"authentication": authMethodJSON})
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
		return nil, fmt.Errorf("failed to create application auth method - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	authMethods, err := s.ListAuthMethodsBy(&applicationsmodels.IdsecPCloudApplicationAuthMethodsFilter{
		AppID:     createApplicationAuthMethod.AppID,
		AuthTypes: []string{createApplicationAuthMethod.AuthType},
	})
	if err != nil {
		return nil, err
	}
	for _, authMethod := range authMethods {
		if authMethod.AuthType == createApplicationAuthMethod.AuthType {
			return authMethod, nil
		}
	}
	return nil, fmt.Errorf("created auth method not found")
}

// GetAuthMethod retrieves a pCloud application auth method.
func (s *IdsecPCloudApplicationsService) GetAuthMethod(getApplicationAuthMethod *applicationsmodels.IdsecPCloudGetApplicationAuthMethod) (*applicationsmodels.IdsecPCloudApplicationAuthMethod, error) {
	s.Logger.Info("Retrieving pCloud application auth method [%v] - [%v]", getApplicationAuthMethod.AppID, getApplicationAuthMethod.AuthID)
	appAuthMethods, err := s.ListAuthMethods(&applicationsmodels.IdsecPCloudListApplicationAuthMethods{AppID: getApplicationAuthMethod.AppID})
	if err != nil {
		return nil, err
	}
	for _, authMethod := range appAuthMethods {
		if authMethod.AuthID == getApplicationAuthMethod.AuthID {
			return authMethod, nil
		}
	}
	return nil, fmt.Errorf("application auth method not found")
}

// DeleteAuthMethod deletes a pCloud application auth method.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud/Latest/en/Content/WebServices/Delete%20a%20Specific%20Authentication.htm
func (s *IdsecPCloudApplicationsService) DeleteAuthMethod(deleteApplicationAuthMethod *applicationsmodels.IdsecPCloudDeleteApplicationAuthMethod) error {
	s.Logger.Info("Deleting pCloud application auth method")
	response, err := s.deleteOperation()(context.Background(), fmt.Sprintf(applicationAuthMethodURL, deleteApplicationAuthMethod.AppID, deleteApplicationAuthMethod.AuthID), nil, nil)
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
		return fmt.Errorf("failed to delete application auth method - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// ListAuthMethods lists all auth methods for a given pCloud application.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud/Latest/en/Content/WebServices/List%20all%20Authentication%20Methods%20of%20a%20Specific%20Application.htm
func (s *IdsecPCloudApplicationsService) ListAuthMethods(listApplicationAuthMethods *applicationsmodels.IdsecPCloudListApplicationAuthMethods) ([]*applicationsmodels.IdsecPCloudApplicationAuthMethod, error) {
	s.Logger.Info("Listing pCloud application auth methods")
	response, err := s.getOperation()(context.Background(), fmt.Sprintf(applicationAuthMethodsURL, listApplicationAuthMethods.AppID), nil)
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
		return nil, fmt.Errorf("failed to list application auth methods - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	authMethodsJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	authMethodsJSONMap := authMethodsJSON.(map[string]interface{})
	authMethodsJSONArray, ok := authMethodsJSONMap["authentication"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid application auth methods response format")
	}
	authMethods := []*applicationsmodels.IdsecPCloudApplicationAuthMethod{}
	for _, authMethodJSON := range authMethodsJSONArray {
		authMethodJSONMap, ok := authMethodJSON.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid application auth method format in auth methods list")
		}
		if appID, ok := authMethodJSONMap["auth_i_d"]; ok {
			authMethodJSONMap["auth_id"] = appID
		}
		authMethodJSONMap["app_id"] = listApplicationAuthMethods.AppID
		var authMethod applicationsmodels.IdsecPCloudApplicationAuthMethod
		err = mapstructure.Decode(authMethodJSONMap, &authMethod)
		if err != nil {
			return nil, err
		}
		authMethods = append(authMethods, &authMethod)
	}
	return authMethods, nil
}

// ListAuthMethodsBy lists pCloud application auth methods based on the provided filter.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud/Latest/en/Content/WebServices/List%20all%20Authentication%20Methods%20of%20a%20Specific%20Application.htm
func (s *IdsecPCloudApplicationsService) ListAuthMethodsBy(filter *applicationsmodels.IdsecPCloudApplicationAuthMethodsFilter) ([]*applicationsmodels.IdsecPCloudApplicationAuthMethod, error) {
	s.Logger.Info("Listing pCloud application auth methods by filter")
	authMethods, err := s.ListAuthMethods(&applicationsmodels.IdsecPCloudListApplicationAuthMethods{AppID: filter.AppID})
	if err != nil {
		return nil, err
	}
	filteredAuthMethods := []*applicationsmodels.IdsecPCloudApplicationAuthMethod{}
	for _, authMethod := range authMethods {
		if len(filter.AuthTypes) > 0 {
			matched := false
			for _, authType := range filter.AuthTypes {
				if authMethod.AuthType == authType {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		filteredAuthMethods = append(filteredAuthMethods, authMethod)
	}
	return filteredAuthMethods, nil
}

// Stats retrieves statistics about pCloud applications.
func (s *IdsecPCloudApplicationsService) Stats() (*applicationsmodels.IdsecPCloudApplicationsStats, error) {
	s.Logger.Info("Retrieving pCloud applications stats")
	applications, err := s.List()
	if err != nil {
		return nil, err
	}
	appStats := &applicationsmodels.IdsecPCloudApplicationsStats{
		ApplicationsCount:           len(applications),
		DisabledApps:                []string{},
		AuthTypeCount:               make(map[string]int),
		ApplicationsAuthMethodTypes: make(map[string][]string),
	}
	for _, app := range applications {
		if app.Disabled {
			appStats.DisabledApps = append(appStats.DisabledApps, app.AppID)
		}
		authMethods, err := s.ListAuthMethods(&applicationsmodels.IdsecPCloudListApplicationAuthMethods{AppID: app.AppID})
		if err != nil {
			return nil, err
		}
		for _, authMethod := range authMethods {
			appStats.AuthTypeCount[authMethod.AuthType]++
			appStats.ApplicationsAuthMethodTypes[app.AppID] = append(appStats.ApplicationsAuthMethodTypes[app.AppID], authMethod.AuthType)
		}
	}
	return appStats, nil
}

// ServiceConfig returns the service configuration for the IdsecPCloudApplicationsService.
func (s *IdsecPCloudApplicationsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
