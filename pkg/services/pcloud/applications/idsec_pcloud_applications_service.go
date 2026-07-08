package applications

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

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

	maxAuthMethodCreationRetries = 5
	authMethodCreationRetryDelay = 1 * time.Second
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

// Update updates a pCloud application.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud/Latest/en/Content/WebServices/Update%20an%20Application.htm
func (s *IdsecPCloudApplicationsService) Update(updateApplication *applicationsmodels.IdsecPCloudUpdateApplication) (*applicationsmodels.IdsecPCloudApplication, error) {
	s.Logger.Info("Updating pCloud application")
	_, err := s.Get(&applicationsmodels.IdsecPCloudGetApplication{AppID: updateApplication.AppID})
	if err != nil {
		return nil, err
	}
	err = s.Delete(&applicationsmodels.IdsecPCloudDeleteApplication{AppID: updateApplication.AppID})
	if err != nil {
		return nil, err
	}
	return s.Create(&applicationsmodels.IdsecPCloudCreateApplication{
		AppID:               updateApplication.AppID,
		Description:         updateApplication.Description,
		Location:            updateApplication.Location,
		AccessPermittedFrom: updateApplication.AccessPermittedFrom,
		AccessPermittedTo:   updateApplication.AccessPermittedTo,
		ExpirationDate:      updateApplication.ExpirationDate,
		Disabled:            updateApplication.Disabled,
		BusinessOwnerFName:  updateApplication.BusinessOwnerFName,
		BusinessOwnerLName:  updateApplication.BusinessOwnerLName,
		BusinessOwnerEmail:  updateApplication.BusinessOwnerEmail,
		BusinessOwnerPhone:  updateApplication.BusinessOwnerPhone,
	})
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
	if !slices.Contains(applicationsmodels.ApplicationAuthMethodTypes, createApplicationAuthMethod.AuthType) {
		return nil, fmt.Errorf("unsupported auth type: %s", createApplicationAuthMethod.AuthType)
	}
	authMethodJSON := map[string]interface{}{
		"AuthType": createApplicationAuthMethod.AuthType,
	}
	if createApplicationAuthMethod.AuthType != applicationsmodels.ApplicationAuthMethodCertificateAttr {
		if createApplicationAuthMethod.AuthValue == "" {
			return nil, fmt.Errorf("auth value is required")
		}
		authMethodJSON["AuthValue"] = createApplicationAuthMethod.AuthValue
	}
	switch createApplicationAuthMethod.AuthType {
	case applicationsmodels.ApplicationAuthMethodPath:
		authMethodJSON["AuthValue"] = createApplicationAuthMethod.AuthValue
		if createApplicationAuthMethod.IsFolder != nil {
			authMethodJSON["IsFolder"] = *createApplicationAuthMethod.IsFolder
		}
		if createApplicationAuthMethod.AllowInternalScripts != nil {
			authMethodJSON["AllowInternalScripts"] = *createApplicationAuthMethod.AllowInternalScripts
		}
	case applicationsmodels.ApplicationAuthMethodHash,
		applicationsmodels.ApplicationAuthMethodCertificateSerialNumber:
		if createApplicationAuthMethod.Comment != nil {
			authMethodJSON["Comment"] = *createApplicationAuthMethod.Comment
		}
	case applicationsmodels.ApplicationAuthMethodCertificateAttr:
		if createApplicationAuthMethod.Subject != nil {
			subjects := []string{}
			for _, subject := range createApplicationAuthMethod.Subject {
				subjects = append(subjects, fmt.Sprintf("%s=%s", subject.Key, subject.Value))
			}
			authMethodJSON["Subject"] = subjects
		}
		if createApplicationAuthMethod.Issuer != nil {
			issuers := []string{}
			for _, issuer := range createApplicationAuthMethod.Issuer {
				issuers = append(issuers, fmt.Sprintf("%s=%s", issuer.Key, issuer.Value))
			}
			authMethodJSON["Issuer"] = issuers
		}
		if createApplicationAuthMethod.SubjectAlternativeName != nil {
			subjectAlternativeNames := []string{}
			for _, subjectAlternativeName := range createApplicationAuthMethod.SubjectAlternativeName {
				subjectAlternativeNames = append(subjectAlternativeNames, fmt.Sprintf("%s=%s", subjectAlternativeName.Key, subjectAlternativeName.Value))
			}
			authMethodJSON["SubjectAlternativeName"] = subjectAlternativeNames
		}
	case applicationsmodels.ApplicationAuthMethodKubernetes:
		if createApplicationAuthMethod.Namespace == nil || createApplicationAuthMethod.Image == nil || createApplicationAuthMethod.EnvVarName == nil || createApplicationAuthMethod.EnvVarValue == nil {
			return nil, fmt.Errorf("all Kubernetes fields must be provided for Kubernetes auth type: namespace, image, env-var-name, env-var-value")
		}
		authMethodJSON["Namespace"] = *createApplicationAuthMethod.Namespace
		authMethodJSON["Image"] = *createApplicationAuthMethod.Image
		authMethodJSON["EnvVarName"] = *createApplicationAuthMethod.EnvVarName
		authMethodJSON["EnvVarValue"] = *createApplicationAuthMethod.EnvVarValue
	}
	// Retry in cases of parallel auth method creations
	for i := 0; i < maxAuthMethodCreationRetries; i++ {
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
		time.Sleep(authMethodCreationRetryDelay)
	}
	return nil, fmt.Errorf("created auth method not found")
}

// UpdateAuthMethod updates a pCloud application auth method.
// https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud/Latest/en/Content/WebServices/Add%20Authentication.htm
func (s *IdsecPCloudApplicationsService) UpdateAuthMethod(updateApplicationAuthMethod *applicationsmodels.IdsecPCloudUpdateApplicationAuthMethod) (*applicationsmodels.IdsecPCloudApplicationAuthMethod, error) {
	s.Logger.Info("Updating pCloud application auth method")
	_, err := s.GetAuthMethod(&applicationsmodels.IdsecPCloudGetApplicationAuthMethod{AppID: updateApplicationAuthMethod.AppID, AuthID: updateApplicationAuthMethod.AuthID})
	if err != nil {
		return nil, err
	}
	err = s.DeleteAuthMethod(&applicationsmodels.IdsecPCloudDeleteApplicationAuthMethod{AppID: updateApplicationAuthMethod.AppID, AuthID: updateApplicationAuthMethod.AuthID})
	if err != nil {
		return nil, err
	}
	return s.CreateAuthMethod(&applicationsmodels.IdsecPCloudCreateApplicationAuthMethod{
		AppID:                  updateApplicationAuthMethod.AppID,
		AuthType:               updateApplicationAuthMethod.AuthType,
		AuthValue:              updateApplicationAuthMethod.AuthValue,
		IsFolder:               updateApplicationAuthMethod.IsFolder,
		AllowInternalScripts:   updateApplicationAuthMethod.AllowInternalScripts,
		Comment:                updateApplicationAuthMethod.Comment,
		Namespace:              updateApplicationAuthMethod.Namespace,
		Image:                  updateApplicationAuthMethod.Image,
		EnvVarName:             updateApplicationAuthMethod.EnvVarName,
		EnvVarValue:            updateApplicationAuthMethod.EnvVarValue,
		Subject:                updateApplicationAuthMethod.Subject,
		Issuer:                 updateApplicationAuthMethod.Issuer,
		SubjectAlternativeName: updateApplicationAuthMethod.SubjectAlternativeName,
	})
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

// parseCertKeyValStrings parses a raw value made of "key=value" strings (as returned for the
// Subject, Issuer and SubjectAlternativeName certificate auth method attributes) back into a list
// of key/value maps that mapstructure can decode into []IdsecPCloudApplicationAuthMethodCertKeyVal.
func parseCertKeyValStrings(raw interface{}) ([]map[string]interface{}, error) {
	var rawItems []interface{}
	switch v := raw.(type) {
	case []interface{}:
		rawItems = v
	case string:
		rawItems = []interface{}{v}
	default:
		return nil, fmt.Errorf("unsupported format [%T]", raw)
	}
	certKeyVals := make([]map[string]interface{}, 0, len(rawItems))
	for _, rawItem := range rawItems {
		item, ok := rawItem.(string)
		if !ok {
			return nil, fmt.Errorf("unsupported item format [%T]", rawItem)
		}
		key, value, found := strings.Cut(item, "=")
		if !found {
			return nil, fmt.Errorf("expected format \"key=value\", got [%s]", item)
		}
		certKeyVals = append(certKeyVals, map[string]interface{}{"key": key, "value": value})
	}
	return certKeyVals, nil
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
		if isFolder, ok := authMethodJSONMap["is_folder"]; ok && isFolder != nil {
			isFolderBool, err := strconv.ParseBool(strings.ToLower(fmt.Sprintf("%v", isFolder)))
			if err != nil {
				return nil, fmt.Errorf("failed to parse is_folder value [%v] as boolean - [%w]", isFolder, err)
			}
			authMethodJSONMap["is_folder"] = isFolderBool
		}
		if allowInternalScripts, ok := authMethodJSONMap["allow_internal_scripts"]; ok && allowInternalScripts != nil {
			allowInternalScriptsBool, err := strconv.ParseBool(strings.ToLower(fmt.Sprintf("%v", allowInternalScripts)))
			if err != nil {
				return nil, fmt.Errorf("failed to parse allow_internal_scripts value [%v] as boolean - [%w]", allowInternalScripts, err)
			}
			authMethodJSONMap["allow_internal_scripts"] = allowInternalScriptsBool
		}
		for _, certKeyValField := range []string{"subject", "issuer", "subject_alternative_name"} {
			if rawCertKeyVals, ok := authMethodJSONMap[certKeyValField]; ok && rawCertKeyVals != nil {
				certKeyVals, err := parseCertKeyValStrings(rawCertKeyVals)
				if err != nil {
					return nil, fmt.Errorf("failed to parse %s value [%v] - [%w]", certKeyValField, rawCertKeyVals, err)
				}
				authMethodJSONMap[certKeyValField] = certKeyVals
			}
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
