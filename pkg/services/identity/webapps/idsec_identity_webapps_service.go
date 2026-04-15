package webapps

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"

	"github.com/go-viper/mapstructure/v2"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	identitycommon "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories"
	directoriesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories/models"
	webappsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/webapps/models"
)

const (
	importAppFromTemplateURL              = "SaasManage/ImportAppFromTemplate"
	updateApplicationURL                  = "SaasManage/UpdateApplicationDE"
	getApplicationURL                     = "SaasManage/GetApplication"
	deleteApplicationURL                  = "SaasManage/DeleteApplication"
	getApplicationIDByNameURL             = "SaasManage/GetAppIDByServiceName"
	setApplicationPermissionsURL          = "SaasManage/SetApplicationPermissions"
	getApplicationPermissionsURL          = "Acl/GetRowAces"
	getApplicationsTemplatesCategoriesURL = "SaasManage/GetCategories"
	getApplicationsTemplatesURL           = "SaasManage/GetPaginatedTemplates"
	getApplicationsCustomTemplatesURL     = "SaasManage/GetCustomWebAppTemplates"
	redrockQueryURL                       = "Redrock/query"
)

const (
	defaultPageSize = 10000
	defaultLimit    = 10000
)

// RightsAceTable maps each ApplicationRights string value to its corresponding RightsBits mask.
//
// This mirrors the server-side RightsAceTable (acl.cs) for webapp permissions and is used
// to translate the human-readable permission level strings ("Admin", "Grant", "View",
// "ViewDetail", "Execute", "Automatic", "Delete") into the bitmask representation expected by the API.
var RightsAceTable = map[string]webappsmodels.RightsBits{
	webappsmodels.GrantRightAdmin:      webappsmodels.RightsBitsFromArr([]webappsmodels.RightsBits{webappsmodels.Rights.Read, webappsmodels.Rights.Write, webappsmodels.Rights.List}),
	webappsmodels.GrantRightGrant:      webappsmodels.Rights.Owner,
	webappsmodels.GrantRightView:       webappsmodels.Rights.Read,
	webappsmodels.GrantRightViewDetail: webappsmodels.RightsBitsFromArr([]webappsmodels.RightsBits{webappsmodels.Rights.Read, webappsmodels.Rights.List}),
	webappsmodels.GrantRightExecute:    webappsmodels.Rights.Execute,
	webappsmodels.GrantRightAutomatic:  webappsmodels.Rights.Automatic,
	webappsmodels.GrantRightDelete:     webappsmodels.Rights.Delete,
}

// IdsecIdentityWebappsPage is a page of IdsecIdentityWebapp items.
type IdsecIdentityWebappsPage = common.IdsecPage[webappsmodels.IdsecIdentityWebapp]

// IdsecIdentityWebappsTemplatePage is a page of IdsecIdentityWebappTemplate items.
type IdsecIdentityWebappsTemplatePage = common.IdsecPage[webappsmodels.IdsecIdentityWebappTemplate]

// IdsecIdentityWebappsService is the service for managing identity webapps.
type IdsecIdentityWebappsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
	DirectoriesService *directories.IdsecIdentityDirectoriesService

	DoPost             func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	DoRedrockQueryPost func(ctx context.Context, path string, body interface{}) (*http.Response, error)
}

// NewIdsecIdentityWebappsService creates a new instance of IdsecIdentityWebappsService.
func NewIdsecIdentityWebappsService(authenticators ...auth.IdsecAuth) (*IdsecIdentityWebappsService, error) {
	identityWebappsService := &IdsecIdentityWebappsService{}
	var identityWebappsServiceInterface services.IdsecService = identityWebappsService
	baseService, err := services.NewIdsecBaseService(identityWebappsServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	// Create ISP base service which handles client creation
	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "", "", "api/idadmin", identityWebappsService.refreshIdentityWebappsAuth)
	if err != nil {
		return nil, err
	}

	// Update headers for identity service
	ispBaseService.ISPClient().UpdateHeaders(map[string]string{
		"X-IDAP-NATIVE-CLIENT": "true",
	})

	// Update identity URL accordingly
	baseURL, err := identitycommon.ResolveIdentityServiceURL(ispAuth, ispBaseService.ISPClient().BaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve identity service URL: %w", err)
	}
	ispBaseService.ISPClient().BaseURL = baseURL

	identityWebappsService.IdsecBaseService = baseService
	identityWebappsService.IdsecISPBaseService = ispBaseService
	identityWebappsService.DirectoriesService, err = directories.NewIdsecIdentityDirectoriesService(ispAuth)
	if err != nil {
		return nil, err
	}
	return identityWebappsService, nil
}

func (s *IdsecIdentityWebappsService) postOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.DoPost != nil {
		return s.DoPost
	}
	return s.ISPClient().Post
}

func (s *IdsecIdentityWebappsService) redrockQueryPostOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.DoRedrockQueryPost != nil {
		return s.DoRedrockQueryPost
	}
	return s.ISPClient().Post
}

func (s *IdsecIdentityWebappsService) refreshIdentityWebappsAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecIdentityWebappsService) getWebappIDByServiceName(webappName string) (string, error) {
	s.Logger.Info("Getting webapp ID by name: [%s]", webappName)
	getIDRequest := map[string]interface{}{
		"Name": webappName,
	}
	response, err := s.postOperation()(context.Background(), getApplicationIDByNameURL, getIDRequest)
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
		return "", fmt.Errorf("failed to get application ID by name - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return "", err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return "", fmt.Errorf("failed to get application ID by name - [%v]", result)
	}
	if _, ok := result["Result"].(string); !ok {
		return "", fmt.Errorf("failed to retrieve application ID - [%v]", result)
	}
	return result["Result"].(string), nil
}

func (s *IdsecIdentityWebappsService) getWebappIDByName(webappName string) (string, error) {
	webappID, err := s.getWebappIDByServiceName(webappName)
	if err == nil {
		return webappID, nil
	}
	pages, err := s.ListBy(&webappsmodels.IdsecIdentityWebappsFilters{
		Search:   webappName,
		Limit:    1,
		PageSize: 1,
	})
	if err != nil {
		return "", err
	}
	for page := range pages {
		for _, app := range page.Items {
			if strings.EqualFold(app.WebappName, webappName) {
				return app.WebappID, nil
			}
		}
	}
	return "", fmt.Errorf("webapp with name [%s] not found", webappName)
}

// Import imports a webapp into the system and returns the imported webapp details.
func (s *IdsecIdentityWebappsService) Import(importWebapp *webappsmodels.IdsecIdentityImportWebapp) (*webappsmodels.IdsecIdentityWebapp, error) {
	s.Logger.Info("Importing webapp with template name: [%s]", importWebapp.TemplateName)
	importTemplateRequest := map[string]interface{}{
		"ID": []string{importWebapp.TemplateName},
	}
	response, err := s.postOperation()(context.Background(), importAppFromTemplateURL, importTemplateRequest)
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
		return nil, fmt.Errorf("failed to import application - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to import application - [%v]", result)
	}
	if _, ok := result["Result"].([]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve imported app id - [%v]", result)
	}
	webappInfo := result["Result"].([]interface{})[0]
	if _, ok := webappInfo.(map[string]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve imported app info - [%v]", result)
	}
	webappInfoMap := webappInfo.(map[string]interface{})
	if _, ok := webappInfoMap["_RowKey"].(string); !ok {
		return nil, fmt.Errorf("failed to retrieve imported app info id - [%v]", result)
	}
	webappID := webappInfoMap["_RowKey"].(string)
	if importWebapp.WebappName != nil || importWebapp.Description != nil || importWebapp.IdsecIdentityWebappAppsConfiguration != (webappsmodels.IdsecIdentityWebappAppsConfiguration{}) || importWebapp.IdsecIdentityWebappPolicyConfiguration != (webappsmodels.IdsecIdentityWebappPolicyConfiguration{}) {
		return s.Update(&webappsmodels.IdsecIdentityUpdateWebapp{
			IdsecIdentityWebappAppsConfiguration:   importWebapp.IdsecIdentityWebappAppsConfiguration,
			IdsecIdentityWebappPolicyConfiguration: importWebapp.IdsecIdentityWebappPolicyConfiguration,
			WebappID:                               webappID,
			WebappName:                             importWebapp.WebappName,
			ServiceName:                            importWebapp.ServiceName,
			Description:                            importWebapp.Description,
		})
	}
	return s.Get(&webappsmodels.IdsecIdentityGetWebapp{WebappID: webappID})
}

func (s *IdsecIdentityWebappsService) serializeOauthProfile(oauthProfile *webappsmodels.IdsecIdentityWebappOAuthProfile) (map[string]interface{}, error) {
	oauthProfileType := reflect.TypeOf(webappsmodels.IdsecIdentityWebappOAuthProfile{})
	oauthProfileSerialized, err := common.SerializeJSONPascalSchema(oauthProfile, &oauthProfileType)
	if err != nil {
		return nil, err
	}
	if oauthProfile.AllowedAuth != nil {
		oauthProfileSerialized["AllowedAuth"] = strings.Join(oauthProfile.AllowedAuth, ",")
	}
	if oauthProfile.TokenType == "" {
		oauthProfileSerialized["TokenType"] = webappsmodels.DefaultOAuthTokenType
	}
	if oauthProfile.TokenLifetimeString == "" {
		oauthProfileSerialized["TokenLifetimeString"] = webappsmodels.DefaultOAuthTokenLifetimeString
	}
	return oauthProfileSerialized, nil
}

func (s *IdsecIdentityWebappsService) serializeAuthRules(authRules *webappsmodels.IdsecIdentityWebappPolicyAuthRule) (map[string]interface{}, error) {
	authRuleType := reflect.TypeOf(webappsmodels.IdsecIdentityWebappPolicyAuthRule{})
	authRuleJson, err := common.SerializeJSONPascalSchema(authRules, &authRuleType)
	if err != nil {
		return nil, err
	}
	if authRules.Type == "" {
		authRuleJson["Type"] = webappsmodels.DefaultWebappPolicyAuthRuleType
	}
	if authRules.UniqueKey == "" {
		authRuleJson["UniqueKey"] = webappsmodels.DefaultWebappPolicyAuthRuleUniqueKey
	}
	authRuleJson["_Type"] = authRuleJson["Type"]
	authRuleJson["_UniqueKey"] = authRuleJson["UniqueKey"]
	authRuleJson["_Value"] = authRuleJson["Value"]
	return authRuleJson, nil
}

// Update updates the details of an existing webapp and returns the updated webapp details.
func (s *IdsecIdentityWebappsService) Update(updateWebapp *webappsmodels.IdsecIdentityUpdateWebapp) (*webappsmodels.IdsecIdentityWebapp, error) {
	s.Logger.Info("Updating webapp with id: [%s]", updateWebapp.WebappID)
	// First get existing app
	webapp, err := s.Get(&webappsmodels.IdsecIdentityGetWebapp{WebappID: updateWebapp.WebappID})
	if err != nil {
		return nil, fmt.Errorf("failed to get existing webapp details: %w", err)
	}

	updateWebappRequest := map[string]interface{}{
		"_RowKey": updateWebapp.WebappID,
	}
	if updateWebapp.WebappName != nil {
		updateWebappRequest["Name"] = updateWebapp.WebappName
	} else {
		updateWebappRequest["Name"] = webapp.WebappName
	}
	if updateWebapp.ServiceName != nil {
		updateWebappRequest["ServiceName"] = updateWebapp.ServiceName
	} else {
		updateWebappRequest["ServiceName"] = webapp.ServiceName
	}
	if updateWebapp.Description != nil {
		updateWebappRequest["Description"] = updateWebapp.Description
	} else {
		updateWebappRequest["Description"] = webapp.Description
	}
	if updateWebapp.OpenIDConnectScript != nil {
		updateWebappRequest["OpenIDConnectScript"] = updateWebapp.OpenIDConnectScript
	} else if webapp.OpenIDConnectScript != nil {
		updateWebappRequest["OpenIDConnectScript"] = webapp.OpenIDConnectScript
	}
	if updateWebapp.OAuthProfile != nil {
		updateWebappRequest["OAuthProfile"], err = s.serializeOauthProfile(updateWebapp.OAuthProfile)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize OAuth profile: %w", err)
		}
	} else if webapp.OAuthProfile != nil {
		updateWebappRequest["OAuthProfile"], err = s.serializeOauthProfile(webapp.OAuthProfile)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize OAuth profile: %w", err)
		}
	}
	if updateWebapp.UserMapScript != nil {
		updateWebappRequest["UserMapScript"] = updateWebapp.UserMapScript
	} else if webapp.UserMapScript != nil {
		updateWebappRequest["UserMapScript"] = webapp.UserMapScript
	}
	if updateWebapp.UserPassScript != nil {
		updateWebappRequest["UserPassScript"] = updateWebapp.UserPassScript
	} else if webapp.UserPassScript != nil {
		updateWebappRequest["UserPassScript"] = webapp.UserPassScript
	}
	if updateWebapp.UserNameStrategy != nil {
		updateWebappRequest["UserNameStrategy"] = updateWebapp.UserNameStrategy
	} else if webapp.UserNameStrategy != nil {
		updateWebappRequest["UserNameStrategy"] = webapp.UserNameStrategy
	}
	if updateWebapp.Username != nil {
		updateWebappRequest["Username"] = updateWebapp.Username
		updateWebappRequest["UserNameArg"] = updateWebapp.Username
	} else if webapp.Username != nil {
		updateWebappRequest["Username"] = webapp.Username
		updateWebappRequest["UserNameArg"] = webapp.Username
	}
	if updateWebapp.Password != nil {
		updateWebappRequest["Password"] = updateWebapp.Password
	} else if webapp.Password != nil {
		updateWebappRequest["Password"] = webapp.Password
	}
	if updateWebapp.Url != nil {
		updateWebappRequest["Url"] = updateWebapp.Url
	} else if webapp.Url != nil {
		updateWebappRequest["Url"] = webapp.Url
	}
	if updateWebapp.MobileUrl != nil {
		updateWebappRequest["MobileUrl"] = updateWebapp.MobileUrl
	} else if webapp.MobileUrl != nil {
		updateWebappRequest["MobileUrl"] = webapp.MobileUrl
	}
	if updateWebapp.ADAttribute != nil {
		updateWebappRequest["ADAttribute"] = updateWebapp.ADAttribute
	} else if webapp.ADAttribute != nil {
		updateWebappRequest["ADAttribute"] = webapp.ADAttribute
	}
	if updateWebapp.AdditionalIdentifierValue != nil {
		updateWebappRequest["AdditionalIdentifierValue"] = updateWebapp.AdditionalIdentifierValue
	} else if webapp.AdditionalIdentifierValue != nil {
		updateWebappRequest["AdditionalIdentifierValue"] = webapp.AdditionalIdentifierValue
	}
	if updateWebapp.CorpIdentifier != nil {
		updateWebappRequest["CorpIdentifier"] = updateWebapp.CorpIdentifier
	} else if webapp.CorpIdentifier != nil {
		updateWebappRequest["CorpIdentifier"] = webapp.CorpIdentifier
	}
	if updateWebapp.IsScaEnabled != nil {
		updateWebappRequest["IsScaEnabled"] = updateWebapp.IsScaEnabled
	} else if webapp.IsScaEnabled != nil {
		updateWebappRequest["IsScaEnabled"] = webapp.IsScaEnabled
	}
	if updateWebapp.Safe != nil {
		updateWebappRequest["Safe"] = updateWebapp.Safe
	} else if webapp.Safe != nil {
		updateWebappRequest["Safe"] = webapp.Safe
	}
	if updateWebapp.AccountName != nil {
		updateWebappRequest["AccountName"] = updateWebapp.AccountName
	} else if webapp.AccountName != nil {
		updateWebappRequest["AccountName"] = webapp.AccountName
	}
	if updateWebapp.ExtAccountId != nil {
		updateWebappRequest["ExtAccountId"] = updateWebapp.ExtAccountId
	} else if webapp.ExtAccountId != nil {
		updateWebappRequest["ExtAccountId"] = webapp.ExtAccountId
	}
	if updateWebapp.IsPrivilegedApp != nil {
		updateWebappRequest["IsPrivilegedApp"] = updateWebapp.IsPrivilegedApp
	} else if webapp.IsPrivilegedApp != nil {
		updateWebappRequest["IsPrivilegedApp"] = webapp.IsPrivilegedApp
	}
	if updateWebapp.AllowViewFixedCredentials != nil {
		updateWebappRequest["AllowViewFixedCredentials"] = updateWebapp.AllowViewFixedCredentials
	} else if webapp.AllowViewFixedCredentials != nil {
		updateWebappRequest["AllowViewFixedCredentials"] = webapp.AllowViewFixedCredentials
	}
	if updateWebapp.WebappLoginType != nil {
		updateWebappRequest["WebAppLoginType"] = updateWebapp.WebappLoginType
	} else if webapp.WebappLoginType != nil {
		updateWebappRequest["WebAppLoginType"] = webapp.WebappLoginType
	}
	if updateWebapp.DefaultAuthProfile != nil {
		updateWebappRequest["DefaultAuthProfile"] = updateWebapp.DefaultAuthProfile
	} else if webapp.DefaultAuthProfile != nil {
		updateWebappRequest["DefaultAuthProfile"] = webapp.DefaultAuthProfile
	}
	if updateWebapp.BypassLoginMfa != nil {
		updateWebappRequest["BypassLoginMFA"] = updateWebapp.BypassLoginMfa
	} else if webapp.BypassLoginMfa != nil {
		updateWebappRequest["BypassLoginMFA"] = webapp.BypassLoginMfa
	}
	if updateWebapp.AuthRules != nil {
		updateWebappRequest["AuthRules"], err = s.serializeAuthRules(updateWebapp.AuthRules)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize auth rules: %w", err)
		}
	} else if webapp.AuthRules != nil {
		updateWebappRequest["AuthRules"], err = s.serializeAuthRules(webapp.AuthRules)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize auth rules: %w", err)
		}
	}
	response, err := s.postOperation()(context.Background(), updateApplicationURL, updateWebappRequest)
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
		return nil, fmt.Errorf("failed to update application - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to update application - [%v]", result)
	}
	return s.Get(&webappsmodels.IdsecIdentityGetWebapp{WebappID: updateWebapp.WebappID})
}

// Delete deletes an existing webapp from the system.
func (s *IdsecIdentityWebappsService) Delete(deleteWebapp *webappsmodels.IdsecIdentityDeleteWebapp) error {
	if deleteWebapp.WebappID == "" && deleteWebapp.WebappName != "" {
		webappID, err := s.getWebappIDByName(deleteWebapp.WebappName)
		if err != nil {
			return fmt.Errorf("failed to get webapp ID by name: %w", err)
		}
		deleteWebapp.WebappID = webappID
	} else if deleteWebapp.WebappID == "" && deleteWebapp.WebappName == "" {
		return fmt.Errorf("either webapp ID or name must be provided for deletion")
	}
	s.Logger.Info("Deleting webapp with id: [%s]", deleteWebapp.WebappID)
	deleteWebappRequest := map[string]interface{}{
		"_RowKey": []string{deleteWebapp.WebappID},
	}
	response, err := s.postOperation()(context.Background(), deleteApplicationURL, deleteWebappRequest)
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
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return fmt.Errorf("failed to delete application - [%v]", result)
	}
	return nil
}

// Get fetches the details of a specific webapp by ID or name.
func (s *IdsecIdentityWebappsService) Get(getWebapp *webappsmodels.IdsecIdentityGetWebapp) (*webappsmodels.IdsecIdentityWebapp, error) {
	if getWebapp.WebappID == "" && getWebapp.WebappName != "" {
		webappID, err := s.getWebappIDByName(getWebapp.WebappName)
		if err != nil {
			return nil, fmt.Errorf("failed to get webapp ID by name: %w", err)
		}
		getWebapp.WebappID = webappID
	} else if getWebapp.WebappID == "" && getWebapp.WebappName == "" {
		return nil, fmt.Errorf("either webapp ID or name must be provided for fetching details")
	}
	s.Logger.Info("Getting webapp details with id: [%s]", getWebapp.WebappID)
	getWebappRequest := map[string]interface{}{
		"_RowKey": getWebapp.WebappID,
	}
	response, err := s.postOperation()(context.Background(), getApplicationURL, getWebappRequest)
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
		return nil, fmt.Errorf("failed to get application details - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to get application details - [%v]", result)
	}
	if _, ok := result["Result"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve application details - [%v]", result)
	}
	webappInfo := result["Result"].(map[string]interface{})
	webappSnakeInfo := common.ConvertToSnakeCase(webappInfo, nil)
	webappSnakeInfoMap := webappSnakeInfo.(map[string]interface{})
	webappSnakeInfoMap["webapp_id"] = webappSnakeInfoMap["_row_key"]
	webappSnakeInfoMap["webapp_name"] = webappSnakeInfoMap["name"]
	if _, ok := webappSnakeInfoMap["web_app_type"]; ok {
		webappSnakeInfoMap["webapp_type"] = webappSnakeInfoMap["web_app_type"]
	}
	if _, ok := webappSnakeInfoMap["webapp_type_display_name"]; !ok {
		if val, ok := webappSnakeInfoMap["web_app_type"].(string); ok {
			webappSnakeInfoMap["webapp_type_display_name"] = val
		}
	}
	if _, ok := webappSnakeInfoMap["auth_rules"]; ok {
		if val, ok := webappSnakeInfoMap["auth_rules"].(map[string]interface{})["_type"]; ok {
			webappSnakeInfoMap["auth_rules"].(map[string]interface{})["type"] = val
		}
		if val, ok := webappSnakeInfoMap["auth_rules"].(map[string]interface{})["_unique_key"]; ok {
			webappSnakeInfoMap["auth_rules"].(map[string]interface{})["unique_key"] = val
		}
		if val, ok := webappSnakeInfoMap["auth_rules"].(map[string]interface{})["_value"]; ok {
			webappSnakeInfoMap["auth_rules"].(map[string]interface{})["value"] = val
		}
	}
	if _, ok := webappSnakeInfoMap["o_auth_profile"]; ok {
		if val, ok := webappSnakeInfoMap["o_auth_profile"].(map[string]interface{})["allowed_auth"]; ok {
			allowedAuthStr := val.(string)
			allowedAuthArr := strings.Split(allowedAuthStr, ",")
			webappSnakeInfoMap["o_auth_profile"].(map[string]interface{})["allowed_auth"] = allowedAuthArr
		}
		webappSnakeInfoMap["oauth_profile"] = webappSnakeInfoMap["o_auth_profile"]
	}
	var webappDetails webappsmodels.IdsecIdentityWebapp
	err = mapstructure.Decode(webappSnakeInfoMap, &webappDetails)
	if err != nil {
		return nil, err
	}
	return &webappDetails, nil
}

func (s *IdsecIdentityWebappsService) listApps(pageSize int, limit int, pageNumber int, maxPageCount int, search string) (<-chan *IdsecIdentityWebappsPage, error) {
	s.Logger.Info("Listing identity apps")

	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if limit <= 0 {
		limit = defaultLimit
	}
	if maxPageCount == 0 {
		maxPageCount = -1
	}

	output := make(chan *IdsecIdentityWebappsPage)

	go func() {
		defer close(output)

		pageNumber := 1
		totalRetrieved := 0

		for maxPageCount <= 0 || pageNumber <= maxPageCount {
			// Check if we've reached the limit
			if totalRetrieved >= limit {
				break
			}
			args := map[string]interface{}{
				"PageNumber": pageNumber,
				"PageSize":   pageSize,
				"Limit":      limit - totalRetrieved,
			}
			if search != "" {
				args["FilterBy"] = []string{
					"Name",
					"AppTypeDisplayName",
					"Description",
					"State",
				}
				args["FilterValue"] = search
			}

			redrockQuery := map[string]interface{}{
				"Script": "@@Web Applications PLV8",
				"Args":   args,
			}

			response, err := s.redrockQueryPostOperation()(context.Background(), redrockQueryURL, redrockQuery)
			if err != nil {
				s.Logger.Error("Failed to list apps: %v", err)
				return
			}

			if response.StatusCode != http.StatusOK {
				s.Logger.Error("Failed to list apps - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
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
				s.Logger.Error("Failed to retrieve apps: %v", result)
				return
			}
			if _, ok := result["Result"].(map[string]interface{}); !ok {
				s.Logger.Info("No more apps found")
				break
			}
			results, ok := result["Result"].(map[string]interface{})["Results"].([]interface{})
			if !ok || len(results) == 0 {
				break
			}

			webapps := make([]*webappsmodels.IdsecIdentityWebapp, 0, len(results))
			for _, item := range results {
				webappRow := item.(map[string]interface{})["Row"].(map[string]interface{})
				webapp := webappsmodels.IdsecIdentityWebapp{
					WebappID:              webappRow["ID"].(string),
					WebappName:            webappRow["Name"].(string),
					DisplayName:           webappRow["DisplayName"].(string),
					Description:           webappRow["Description"].(string),
					WebappType:            webappRow["WebAppType"].(string),
					WebappTypeDisplayName: webappRow["WebAppTypeDisplayName"].(string),
					AppTypeDisplayName:    webappRow["AppTypeDisplayName"].(string),
					TemplateName:          webappRow["TemplateName"].(string),
					State:                 webappRow["State"].(string),
				}
				if value, ok := webappRow["Category"]; ok && value != nil {
					stringVal := value.(string)
					webapp.Category = &stringVal
				}
				if value, ok := webappRow["WebAppLoginType"]; ok && value != nil {
					stringVal := value.(string)
					webapp.WebappLoginType = &stringVal
				}
				if value, ok := webappRow["IsScaEnabled"]; ok && value != nil {
					boolVal := value.(bool)
					webapp.IsScaEnabled = &boolVal
				}
				if value, ok := webappRow["IsSwsEnabled"]; ok && value != nil {
					boolVal := value.(bool)
					webapp.IsSwsEnabled = &boolVal
				}
				if value, ok := webappRow["Generic"]; ok && value != nil {
					boolVal := value.(bool)
					webapp.Generic = &boolVal
				}
				webapps = append(webapps, &webapp)
				totalRetrieved++
				if totalRetrieved >= limit {
					break
				}
			}

			if len(webapps) > 0 {
				output <- &IdsecIdentityWebappsPage{Items: webapps}
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

// List fetches a list of webapps based on the provided filters and returns a channel of IdsecIdentityWebappsPage.
func (s *IdsecIdentityWebappsService) List() (<-chan *IdsecIdentityWebappsPage, error) {
	return s.listApps(defaultPageSize, defaultLimit, 1, -1, "")
}

// ListBy fetches a list of webapps based on the provided filters and returns a channel of IdsecIdentityWebappsPage.
func (s *IdsecIdentityWebappsService) ListBy(filters *webappsmodels.IdsecIdentityWebappsFilters) (<-chan *IdsecIdentityWebappsPage, error) {
	return s.listApps(filters.PageSize, filters.Limit, filters.PageNumber, filters.MaxPageCount, filters.Search)
}

func (s *IdsecIdentityWebappsService) parseGrants(grants int) ([]string, error) {
	var grantsList []string
	for grantStr, grantBits := range RightsAceTable {
		if grantBits.Lo != 0 && (grants&int(grantBits.Lo)) == int(grantBits.Lo) {
			grantsList = append(grantsList, grantStr)
		} else if grantBits.Hi != 0 && (grants&int(grantBits.Hi)) == int(grantBits.Hi) {
			grantsList = append(grantsList, grantStr)
		}
	}
	return grantsList, nil
}

// SetPermissions sets the permissions for a specific webapp and returns the updated permissions.
func (s *IdsecIdentityWebappsService) SetPermissions(setPermissions *webappsmodels.IdsecIdentitySetWebappPermissions) (*webappsmodels.IdsecIdentityWebappPermissions, error) {
	if setPermissions.WebappID == "" && setPermissions.WebappName != "" {
		webappID, err := s.getWebappIDByName(setPermissions.WebappName)
		if err != nil {
			return nil, fmt.Errorf("failed to get webapp ID by name: %w", err)
		}
		setPermissions.WebappID = webappID
	} else if setPermissions.WebappID == "" && setPermissions.WebappName == "" {
		return nil, fmt.Errorf("either webapp ID or name must be provided for fetching details")
	}
	s.Logger.Info("Setting permissions for webapp with id: [%s]", setPermissions.WebappID)
	setPermissionsRequest := map[string]interface{}{
		"ID":     setPermissions.WebappID,
		"Grants": []map[string]interface{}{},
	}
	grantMaps := make([]map[string]interface{}, len(setPermissions.Grants))
	grantErrors := make([]error, len(setPermissions.Grants))
	var wg sync.WaitGroup
	for i, grant := range setPermissions.Grants {
		wg.Add(1)
		go func(idx int, g webappsmodels.IdsecIdentityWebappGrant) {
			defer wg.Done()
			grantMap := map[string]interface{}{
				"Principal":  g.Principal,
				"SystemName": g.Principal,
				"PType":      g.PrincipalType,
				"Rights":     strings.Join(g.Rights, ","),
			}
			if g.Type == nil {
				grantMap["Type"] = g.PrincipalType
			} else {
				grantMap["Type"] = *g.Type
			}
			if g.PrincipalId != nil {
				grantMap["PrincipalId"] = *g.PrincipalId
			} else {
				var entityType string
				switch g.PrincipalType {
				case webappsmodels.PrincipalTypeGroup:
					entityType = directoriesmodels.EntityTypeGroup
				case webappsmodels.PrincipalTypeRole:
					entityType = directoriesmodels.EntityTypeRole
				default:
					entityType = directoriesmodels.EntityTypeUser
				}
				pages, err := s.DirectoriesService.ListEntities(&directoriesmodels.IdsecIdentityListDirectoriesEntities{
					EntityTypes:  []string{entityType},
					Search:       g.Principal,
					Limit:        1,
					PageSize:     1,
					MaxPageCount: 1,
				})
				if err != nil {
					grantErrors[idx] = fmt.Errorf("failed to get entity details for principal [%s]: %w", g.Principal, err)
					return
				}
				entityFound := false
				for page := range pages {
					for _, entity := range page.Items {
						baseEntity := *entity
						if baseEntity.GetEntityType() == directoriesmodels.EntityTypeUser {
							userEntity := baseEntity.(*directoriesmodels.IdsecIdentityUserEntity)
							if strings.EqualFold(userEntity.Name, g.Principal) {
								grantMap["PrincipalId"] = userEntity.ID
								if g.DirectoryServiceUuid != nil {
									grantMap["DirectoryServiceUuid"] = *g.DirectoryServiceUuid
								} else {
									grantMap["DirectoryServiceUuid"] = userEntity.DirectoryServiceUuid
								}
								if g.ExternalUuid != nil {
									grantMap["ExternalUuid"] = *g.ExternalUuid
								} else if userEntity.ExternalUuid != "" {
									grantMap["ExternalUuid"] = userEntity.ExternalUuid
								} else {
									grantMap["ExternalUuid"] = userEntity.ID
								}
								entityFound = true
								break
							}
						} else if baseEntity.GetEntityType() == directoriesmodels.EntityTypeGroup {
							groupEntity := baseEntity.(*directoriesmodels.IdsecIdentityGroupEntity)
							if strings.EqualFold(groupEntity.Name, g.Principal) {
								grantMap["PrincipalId"] = groupEntity.ID
								if g.DirectoryServiceUuid != nil {
									grantMap["DirectoryServiceUuid"] = *g.DirectoryServiceUuid
								} else {
									grantMap["DirectoryServiceUuid"] = groupEntity.DirectoryServiceUuid
								}
								if g.ExternalUuid != nil {
									grantMap["ExternalUuid"] = *g.ExternalUuid
								} else if groupEntity.ExternalUuid != "" {
									grantMap["ExternalUuid"] = groupEntity.ExternalUuid
								} else {
									grantMap["ExternalUuid"] = groupEntity.ID
								}
								entityFound = true
								break
							}
						} else if baseEntity.GetEntityType() == directoriesmodels.EntityTypeRole {
							roleEntity := baseEntity.(*directoriesmodels.IdsecIdentityRoleEntity)
							if strings.EqualFold(roleEntity.Name, g.Principal) {
								entityFound = true
								break
							}
						}
					}
					if entityFound {
						break
					}
				}
				if !entityFound {
					grantErrors[idx] = fmt.Errorf("entity with name [%s] not found for permission grant", g.Principal)
					return
				}
			}
			grantMaps[idx] = grantMap
		}(i, grant)
	}
	wg.Wait()
	for _, grantErr := range grantErrors {
		if grantErr != nil {
			return nil, grantErr
		}
	}
	for _, grantMap := range grantMaps {
		setPermissionsRequest["Grants"] = append(setPermissionsRequest["Grants"].([]map[string]interface{}), grantMap)
	}
	response, err := s.postOperation()(context.Background(), setApplicationPermissionsURL, setPermissionsRequest)
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
		return nil, fmt.Errorf("failed to set application permissions - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to set application permissions - [%v]", result)
	}
	return s.GetPermissions(&webappsmodels.IdsecIdentityGetWebappPermissions{WebappID: setPermissions.WebappID})
}

// SetPermission sets the permissions for a specific principal on a webapp and returns the updated permission details for that principal.
func (s *IdsecIdentityWebappsService) SetPermission(setPermission *webappsmodels.IdsecIdentitySetWebappPermission) (*webappsmodels.IdsecIdentityWebappPermission, error) {
	permissions, err := s.SetPermissions(&webappsmodels.IdsecIdentitySetWebappPermissions{
		WebappID: setPermission.WebappID,
		Grants:   []webappsmodels.IdsecIdentityWebappGrant{setPermission.IdsecIdentityWebappGrant},
	})
	if err != nil {
		return nil, err
	}
	for _, grant := range permissions.Grants {
		if grant.Principal == setPermission.Principal && grant.PrincipalType == setPermission.PrincipalType {
			return &webappsmodels.IdsecIdentityWebappPermission{
				IdsecIdentityWebappGrant: webappsmodels.IdsecIdentityWebappGrant{
					Principal:     grant.Principal,
					PrincipalId:   grant.PrincipalId,
					PrincipalType: grant.PrincipalType,
					Type:          grant.Type,
					Rights:        grant.Rights,
				},
				WebappID: permissions.WebappID,
			}, nil
		}
	}
	return nil, fmt.Errorf("failed to find updated permission for principal [%s] after setting permission", setPermission.Principal)
}

// GetPermissions fetches the permissions of a specific webapp by ID or name.
func (s *IdsecIdentityWebappsService) GetPermissions(getPermissions *webappsmodels.IdsecIdentityGetWebappPermissions) (*webappsmodels.IdsecIdentityWebappPermissions, error) {
	if getPermissions.WebappID == "" && getPermissions.WebappName != "" {
		webappID, err := s.getWebappIDByName(getPermissions.WebappName)
		if err != nil {
			return nil, fmt.Errorf("failed to get webapp ID by name: %w", err)
		}
		getPermissions.WebappID = webappID
	} else if getPermissions.WebappID == "" && getPermissions.WebappName == "" {
		return nil, fmt.Errorf("either webapp ID or name must be provided for fetching details")
	}
	s.Logger.Info("Getting permissions for webapp with id: [%s]", getPermissions.WebappID)
	getPermissionsRequest := map[string]interface{}{
		"RowKey":         getPermissions.WebappID,
		"Table":          "Application",
		"ReduceSysadmin": true,
	}
	response, err := s.postOperation()(context.Background(), getApplicationPermissionsURL, getPermissionsRequest)
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
		return nil, fmt.Errorf("failed to get application permissions - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to get application permissions - [%v]", result)
	}
	if _, ok := result["Result"].([]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve application permissions - [%v]", result)
	}
	grantsData := result["Result"].([]interface{})
	webappPerms := &webappsmodels.IdsecIdentityWebappPermissions{
		WebappID: getPermissions.WebappID,
		Grants:   []webappsmodels.IdsecIdentityWebappGrant{},
	}
	for _, grant := range grantsData {
		grantMap := grant.(map[string]interface{})
		webappGrant := webappsmodels.IdsecIdentityWebappGrant{
			Principal:     grantMap["PrincipalName"].(string),
			PrincipalId:   common.Ptr(grantMap["Principal"].(string)),
			PrincipalType: grantMap["PrincipalType"].(string),
		}
		if value, ok := grantMap["Type"]; ok && value != nil {
			webappGrant.Type = common.Ptr(value.(string))
		} else {
			webappGrant.Type = common.Ptr("User")
		}
		grantBits := grantMap["Grant"].(float64)
		parsedGrants, err := s.parseGrants(int(grantBits))
		if err != nil {
			return nil, fmt.Errorf("failed to parse grants: %w", err)
		}
		webappGrant.Rights = parsedGrants
		webappPerms.Grants = append(webappPerms.Grants, webappGrant)
	}
	return webappPerms, nil
}

// GetPermission fetches the permissions for a specific principal on a webapp by webapp ID or name and principal name or ID.
func (s *IdsecIdentityWebappsService) GetPermission(getPermission *webappsmodels.IdsecIdentityGetWebappPermission) (*webappsmodels.IdsecIdentityWebappPermission, error) {
	if getPermission.Principal == nil && getPermission.PrincipalId == nil {
		return nil, fmt.Errorf("either principal name or principal ID must be provided to get specific permission")
	}
	permissions, err := s.GetPermissions(&webappsmodels.IdsecIdentityGetWebappPermissions{
		WebappID:   getPermission.WebappID,
		WebappName: getPermission.WebappName,
	})
	if err != nil {
		return nil, err
	}
	for _, grant := range permissions.Grants {
		if (getPermission.Principal != nil && grant.Principal == *getPermission.Principal) || (getPermission.PrincipalId != nil && grant.PrincipalId != nil && *grant.PrincipalId == *getPermission.PrincipalId) && grant.PrincipalType == getPermission.PrincipalType {
			return &webappsmodels.IdsecIdentityWebappPermission{
				IdsecIdentityWebappGrant: webappsmodels.IdsecIdentityWebappGrant{
					Principal:     grant.Principal,
					PrincipalId:   grant.PrincipalId,
					PrincipalType: grant.PrincipalType,
					Type:          grant.Type,
					Rights:        grant.Rights,
				},
				WebappID: permissions.WebappID,
			}, nil
		}
	}
	return nil, fmt.Errorf("failed to find permission for principal [%v]", getPermission.Principal)
}

func (s *IdsecIdentityWebappsService) listAppsTemplates(pageSize int, limit int, pageNumber int, maxPageCount int, search string) (<-chan *IdsecIdentityWebappsTemplatePage, error) {
	s.Logger.Info("Listing identity apps templates")

	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	if limit <= 0 {
		limit = defaultLimit
	}
	if maxPageCount == 0 {
		maxPageCount = -1
	}

	output := make(chan *IdsecIdentityWebappsTemplatePage)

	go func() {
		defer close(output)

		pageNumber := 1
		totalRetrieved := 0

		for maxPageCount <= 0 || pageNumber <= maxPageCount {
			// Check if we've reached the limit
			if totalRetrieved >= limit {
				break
			}
			args := map[string]interface{}{
				"PageNumber": pageNumber,
				"PageSize":   pageSize,
				"Limit":      limit - totalRetrieved,
			}
			if search != "" {
				args["FilterBy"] = []string{
					"DisplayName",
					"Name",
					"WebAppType",
				}
				args["FilterValue"] = search
			}
			response, err := s.postOperation()(context.Background(), getApplicationsTemplatesURL, map[string]interface{}{
				"Args": args,
			})
			if err != nil {
				s.Logger.Error("Failed to list apps templates: %v", err)
				return
			}

			if response.StatusCode != http.StatusOK {
				s.Logger.Error("Failed to list apps templates - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
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
				s.Logger.Error("Failed to retrieve apps templates: %v", result)
				return
			}
			if _, ok := result["Result"].(map[string]interface{}); !ok {
				s.Logger.Info("No more apps templates found")
				break
			}
			appTemplates, ok := result["Result"].(map[string]interface{})["AppTemplates"].(map[string]interface{})
			if !ok {
				break
			}
			results := appTemplates["Results"].([]interface{})
			if !ok || len(results) == 0 {
				break
			}

			webappsTemplates := make([]*webappsmodels.IdsecIdentityWebappTemplate, 0, len(results))
			for _, item := range results {
				webappTemplateRow := item.(map[string]interface{})["Row"].(map[string]interface{})
				webappTemplate := webappsmodels.IdsecIdentityWebappTemplate{
					WebappTemplateID:      webappTemplateRow["ID"].(string),
					WebappTemplateName:    webappTemplateRow["Name"].(string),
					DisplayName:           webappTemplateRow["DisplayName"].(string),
					AppTypeDisplayName:    webappTemplateRow["AppTypeDisplayName"].(string),
					Description:           webappTemplateRow["Description"].(string),
					AppType:               webappTemplateRow["AppType"].(string),
					WebappTypeDisplayName: webappTemplateRow["WebAppTypeDisplayName"].(string),
				}
				if value, ok := webappTemplateRow["Category"]; ok && value != nil {
					strVal := value.(string)
					webappTemplate.Category = &strVal
				}
				if value, ok := webappTemplateRow["Version"]; ok && value != nil {
					strVal := value.(string)
					webappTemplate.Version = &strVal
				}
				if value, ok := webappTemplateRow["WebAppLoginType"]; ok && value != nil {
					strVal := value.(string)
					webappTemplate.WebappLoginType = &strVal
				}
				if value, ok := webappTemplateRow["ServiceName"]; ok && value != nil {
					strVal := value.(string)
					webappTemplate.ServiceName = &strVal
				}
				if value, ok := webappTemplateRow["TemplateName"]; ok && value != nil {
					strVal := value.(string)
					webappTemplate.TemplateName = &strVal
				}
				if value, ok := webappTemplateRow["IsSwsEnabled"]; ok && value != nil {
					boolVal := value.(bool)
					webappTemplate.IsSwsEnabled = &boolVal
				}
				if value, ok := webappTemplateRow["IsScaEnabled"]; ok && value != nil {
					boolVal := value.(bool)
					webappTemplate.IsScaEnabled = &boolVal
				}
				if value, ok := webappTemplateRow["Generic"]; ok && value != nil {
					boolVal := value.(bool)
					webappTemplate.Generic = &boolVal
				}
				webappsTemplates = append(webappsTemplates, &webappTemplate)

				totalRetrieved++
				if totalRetrieved >= limit {
					break
				}
			}

			if len(webappsTemplates) > 0 {
				output <- &IdsecIdentityWebappsTemplatePage{Items: webappsTemplates}
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

// ListTemplates fetches a list of webapp templates based on the provided filters and returns a channel of IdsecIdentityWebappsTemplatePage.
func (s *IdsecIdentityWebappsService) ListTemplates() (<-chan *IdsecIdentityWebappsTemplatePage, error) {
	return s.listAppsTemplates(defaultPageSize, defaultLimit, 1, -1, "")
}

// ListTemplatesBy fetches a list of webapp templates based on the provided filters and returns a channel of IdsecIdentityWebappsTemplatePage.
func (s *IdsecIdentityWebappsService) ListTemplatesBy(filters *webappsmodels.IdsecIdentityWebappsTemplatesFilters) (<-chan *IdsecIdentityWebappsTemplatePage, error) {
	return s.listAppsTemplates(filters.PageSize, filters.Limit, filters.PageNumber, filters.MaxPageCount, filters.Search)
}

// ListCustomTemplates fetches the list of custom webapp templates available in the system and returns a channel of IdsecIdentityWebappsTemplatePage.
func (s *IdsecIdentityWebappsService) ListCustomTemplates() (*webappsmodels.IdsecIdentityWebappCustomTemplates, error) {
	s.Logger.Info("Listing custom webapp templates")
	response, err := s.postOperation()(context.Background(), getApplicationsCustomTemplatesURL, map[string]interface{}{})
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
		return nil, fmt.Errorf("failed to list custom webapp templates - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to list custom webapp templates - [%v]", result)
	}
	if _, ok := result["Result"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve custom webapp templates - [%v]", result)
	}
	customTemplatesData := result["Result"].(map[string]interface{})
	if _, ok := customTemplatesData["Results"].([]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve custom webapp templates data - [%v]", result)
	}
	customTemplates := &webappsmodels.IdsecIdentityWebappCustomTemplates{
		Templates: []*webappsmodels.IdsecIdentityWebappTemplate{},
	}
	for _, item := range customTemplatesData["Results"].([]interface{}) {
		templateMap := item.(map[string]interface{})
		templateRow, ok := templateMap["Row"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to parse custom webapp template data - [%v]", result)
		}
		webappTemplate := webappsmodels.IdsecIdentityWebappTemplate{
			WebappTemplateID:      templateRow["ID"].(string),
			WebappTemplateName:    templateRow["Name"].(string),
			DisplayName:           templateRow["DisplayName"].(string),
			AppTypeDisplayName:    templateRow["AppTypeDisplayName"].(string),
			Description:           templateRow["Description"].(string),
			AppType:               templateRow["AppType"].(string),
			WebappTypeDisplayName: templateRow["WebAppTypeDisplayName"].(string),
		}
		if value, ok := templateRow["Category"]; ok && value != nil {
			strVal := value.(string)
			webappTemplate.Category = &strVal
		}
		if value, ok := templateRow["UserNameStrategy"]; ok && value != nil {
			strVal := value.(string)
			webappTemplate.UserNameStrategy = &strVal
		}
		if value, ok := templateRow["Version"]; ok && value != nil {
			strVal := value.(string)
			webappTemplate.Version = &strVal
		}
		if value, ok := templateRow["WebAppLoginType"]; ok && value != nil {
			strVal := value.(string)
			webappTemplate.WebappLoginType = &strVal
		}
		if value, ok := templateRow["ServiceName"]; ok && value != nil {
			strVal := value.(string)
			webappTemplate.ServiceName = &strVal
		}
		if value, ok := templateRow["TemplateName"]; ok && value != nil {
			strVal := value.(string)
			webappTemplate.TemplateName = &strVal
		}
		if value, ok := templateRow["IsSwsEnabled"]; ok && value != nil {
			boolVal := value.(bool)
			webappTemplate.IsSwsEnabled = &boolVal
		}
		if value, ok := templateRow["IsScaEnabled"]; ok && value != nil {
			boolVal := value.(bool)
			webappTemplate.IsScaEnabled = &boolVal
		}
		if value, ok := templateRow["Generic"]; ok && value != nil {
			boolVal := value.(bool)
			webappTemplate.Generic = &boolVal
		}
		customTemplates.Templates = append(customTemplates.Templates, &webappTemplate)
	}
	return customTemplates, nil
}

// ListCustomTemplatesBy fetches the list of custom webapp templates available in the system based on the provided filters and returns a channel of IdsecIdentityWebappsTemplatePage.
func (s *IdsecIdentityWebappsService) ListCustomTemplatesBy(filters *webappsmodels.IdsecIdentityWebappsCustomTemplatesFilters) (*webappsmodels.IdsecIdentityWebappCustomTemplates, error) {
	s.Logger.Info("Listing custom webapp templates with filters")
	customTemplates, err := s.ListCustomTemplates()
	if err != nil {
		return nil, err
	}
	filteredTemplates := &webappsmodels.IdsecIdentityWebappCustomTemplates{
		Templates: []*webappsmodels.IdsecIdentityWebappTemplate{},
	}
	for _, template := range customTemplates.Templates {
		if filters.Search != "" && !strings.Contains(template.WebappTemplateName, filters.Search) && !strings.Contains(template.DisplayName, filters.Search) {
			continue
		}
		filteredTemplates.Templates = append(filteredTemplates.Templates, template)
	}
	return filteredTemplates, nil
}

// ListTemplatesCategories fetches the list of webapp template categories available in the system.
func (s *IdsecIdentityWebappsService) ListTemplatesCategories() (*webappsmodels.IdsecIdentityWebappTemplatesCategories, error) {
	s.Logger.Info("Listing webapp template categories")
	response, err := s.postOperation()(context.Background(), getApplicationsTemplatesCategoriesURL, map[string]interface{}{})
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
		return nil, fmt.Errorf("failed to list webapp template categories - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to list webapp template categories - [%v]", result)
	}
	if _, ok := result["Result"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve webapp template categories - [%v]", result)
	}
	categoriesData := result["Result"].(map[string]interface{})
	if _, ok := categoriesData["Categories"].([]interface{}); !ok {
		return nil, fmt.Errorf("failed to retrieve webapp template categories data - [%v]", result)
	}
	categories := &webappsmodels.IdsecIdentityWebappTemplatesCategories{
		Categories: []string{},
	}
	for _, item := range categoriesData["Categories"].([]interface{}) {
		category := item.(string)
		categories.Categories = append(categories.Categories, category)
	}
	return categories, nil
}

// GetTemplate fetches the details of a specific webapp template by its ID.
func (s *IdsecIdentityWebappsService) GetTemplate(getTemplate *webappsmodels.IdsecIdentityGetWebappTemplate) (*webappsmodels.IdsecIdentityWebappTemplate, error) {
	searchString := getTemplate.WebappTemplateID
	if searchString == "" && getTemplate.WebappTemplateName != "" {
		searchString = getTemplate.WebappTemplateName
	}
	if searchString == "" {
		return nil, fmt.Errorf("either webapp template ID or name must be provided for fetching details")
	}
	s.Logger.Info("Getting webapp template details by: [%s]", searchString)
	pages, err := s.ListTemplatesBy(&webappsmodels.IdsecIdentityWebappsTemplatesFilters{
		PageSize:   1,
		PageNumber: 1,
		Search:     searchString,
	})
	if err != nil {
		return nil, err
	}
	for page := range pages {
		for _, template := range page.Items {
			if template.WebappTemplateID == getTemplate.WebappTemplateID || template.WebappTemplateName == getTemplate.WebappTemplateName {
				return template, nil
			}
		}
	}
	return nil, fmt.Errorf("webapp template not found with ID or name: [%s]", searchString)
}

// GetCustomTemplate fetches the details of a specific custom webapp template by its ID.
func (s *IdsecIdentityWebappsService) GetCustomTemplate(getCustomTemplate *webappsmodels.IdsecIdentityGetWebappCustomTemplate) (*webappsmodels.IdsecIdentityWebappTemplate, error) {
	searchString := getCustomTemplate.WebappTemplateID
	if searchString == "" && getCustomTemplate.WebappTemplateName != "" {
		searchString = getCustomTemplate.WebappTemplateName
	}
	if searchString == "" {
		return nil, fmt.Errorf("either custom webapp template ID or name must be provided for fetching details")
	}
	s.Logger.Info("Getting custom webapp template details by: [%s]", searchString)
	customTemplates, err := s.ListCustomTemplates()
	if err != nil {
		return nil, err
	}
	for _, template := range customTemplates.Templates {
		if template.WebappTemplateID == getCustomTemplate.WebappTemplateID || template.WebappTemplateName == getCustomTemplate.WebappTemplateName {
			return template, nil
		}
	}
	return nil, fmt.Errorf("custom webapp template not found with ID or name: [%s]", searchString)
}

// Stats fetches statistics about the webapps in the system, such as total count and count by type.
func (s *IdsecIdentityWebappsService) Stats() (*webappsmodels.IdsecIdentityWebappsStats, error) {
	s.Logger.Info("Getting webapps stats")
	pages, err := s.List()
	if err != nil {
		return nil, err
	}
	stats := &webappsmodels.IdsecIdentityWebappsStats{
		AppsCount:           0,
		AppsCountByType:     make(map[string]int),
		AppsCountByCategory: make(map[string]int),
	}
	for page := range pages {
		for _, webapp := range page.Items {
			stats.AppsCount++
			if _, ok := stats.AppsCountByType[webapp.WebappType]; !ok {
				stats.AppsCountByType[webapp.WebappType] = 0
			}
			if webapp.Category != nil {
				if _, ok := stats.AppsCountByCategory[*webapp.Category]; !ok {
					stats.AppsCountByCategory[*webapp.Category] = 0
				}
				stats.AppsCountByCategory[*webapp.Category]++
			}
			stats.AppsCountByType[webapp.WebappType]++
		}
	}
	return stats, nil
}

// ServiceConfig returns the service configuration for the IdsecIdentityWebappsService.
func (s *IdsecIdentityWebappsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
