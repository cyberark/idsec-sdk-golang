// Package federations provides the IDSEC Identity federations service, which manages SAML 2.0
// and OIDC identity provider federations and their global group mappings.
package federations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	identitycommon "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/common"
	federationsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/federations/models"
)

// samlSettingsTTL is how long the SAML service provider settings are cached. They derive from the
// tenant's host name, so they change only when its CNAME configuration does; the TTL bounds how
// long a long-lived service, such as a Terraform provider, keeps reporting the old URLs.
const samlSettingsTTL = 5 * time.Minute

// Endpoint paths, relative to the api/idadmin base.
const (
	createFederationURL         = "Federation/CreateFederation"
	deleteFederationURL         = "Federation/DeleteFederation"
	listFederationURL           = "Federation/GetFederations"
	readFederationURL           = "Federation/GetFederation"
	updateFederationURL         = "Federation/UpdateFederation"
	globalFederationSettingsURL = "Federation/GetGlobalFederationSettings"
	listGlobalMappingsURL       = "Federation/GetGlobalGroupAssertionMappings"
	addGlobalMappingURL         = "Federation/AddGlobalGroupAssertionMapping"
	removeGlobalMappingURL      = "Federation/DeleteGlobalGroupAssertionMapping"
	formContentType             = "application/x-www-form-urlencoded"
	federationTypeOIDC          = "OIDC"
	federationTypeSAML          = "SAML 2.0"
	defaultOIDCGrantType        = "AuthorizationCode"
	federationUUIDColumn        = "FederationUuid"
	federationNameColumn        = "FederationName"
	federationTypeColumn        = "FederationType"
	activeColumn                = "Active"
	domainsColumn               = "Domains"
	configColumn                = "Config"
	mappingsColumn              = "Mappings"
	attributeMappingsColumn     = "AttributeMappings"
	logoutCallBackURIConfigKey  = "LogoutCallBackURI"
	mapUsersColumn              = "MapUsers"
	mapUserAttributeColumn      = "MapUserAttribute"
	mapUserByColumn             = "MapUserBy"
	mapUserDirectoryColumn      = "MapUserDirectoryService"
	syncWithFedUserColumn       = "MapUserSyncWithFedUser"
	deviceTypesColumn           = "DeviceTypes"
	userAgentsColumn            = "UserAgents"
)

// SAML inbound configuration keys. The server keeps them in Config; the first three only select
// the mode of the request and are not stored.
const (
	isMetadataConfigKey        = "IsMetaData"
	metadataIsURLConfigKey     = "MetaDataIsUrl"
	idpMetadataURLConfigKey    = "IDPMetadataUrl"
	idpSignInURLConfigKey      = "IDPSignInUrl"
	idpLogoutURLConfigKey      = "IDPLogoutUrl"
	idpThumbprintConfigKey     = "IDPSigningCertificateThumbprint"
	idpSubjectConfigKey        = "IDPSigningCertificateSubject"
	idpExpiresConfigKey        = "IDPSigningCertificateExpires"
	idpMetadataFileField       = "IDPMetadataFileContents"
	idpSigningCertificateField = "IDPSigningCert"
	samlSignAlgorithmColumn    = "SAMLSignAlgorithm"
	defaultSAMLSignAlgorithm   = "SHA256"
)

// samlInboundConfigKeys are the Config entries the inbound configuration of a SAML federation
// derives. They are never echoed: every SAML create and update sends a complete inbound mode
// instead (see samlInbound), and the server derives the rest from it.
var samlInboundConfigKeys = []string{
	isMetadataConfigKey,
	metadataIsURLConfigKey,
	idpMetadataURLConfigKey,
	idpSignInURLConfigKey,
	idpLogoutURLConfigKey,
	idpThumbprintConfigKey,
	idpSubjectConfigKey,
	idpExpiresConfigKey,
	"IDPSigningCertificateCollection",
}

// Portal defaults for a new federation (partneredit.js). The server applies the same values at
// sign-in when a column is absent, so they are also what a read reports for an absent column.
const (
	defaultMapUsers         = "Disabled"
	defaultMapUserAttribute = "UserPrincipalName"
	defaultMapUserBy        = "Name"
	defaultSyncWithFedUser  = true
)

// mapUsersNames are the MapUserMode names by value. The server stores the name, but a value
// posted as a number is stored as that number.
var mapUsersNames = []string{"Disabled", "Optional", "Required"}

// mappingsLocks holds one lock per tenant, keyed by the tenant's identity service URL, that
// serializes every write touching group mappings. The server keeps the mappings of all
// federations, and the global mappings, in one tenant file that it reads, modifies and rewrites
// without a lock (FederatedDirectoryService.UpdateGroupAssertionMappings), so two concurrent
// writes from a parallel Terraform apply could lose one another's mappings. The lock is shared by
// every service instance of the tenant, such as two provider aliases for the same tenant, and
// writes to different tenants do not wait on each other.
var mappingsLocks sync.Map

// tenantMappingsLock returns the mappings lock of the tenant at baseURL.
func tenantMappingsLock(baseURL string) *sync.Mutex {
	lock, _ := mappingsLocks.LoadOrStore(strings.TrimRight(strings.ToLower(baseURL), "/"), &sync.Mutex{})
	return lock.(*sync.Mutex)
}

// supportedFederationTypes are the protocols this service manages. Social and shadow federations
// are listed by the server too, but are out of scope and are never returned.
var supportedFederationTypes = []string{federationTypeSAML, federationTypeOIDC}

// echoedColumns are the writable top-level federation columns that UpdateFederation resets when
// they are not sent: the server rebuilds Usage, Active, Domains, the routing lists and the
// attribute mappings from the request alone (FederatedDirectoryService.UpdateFederation). Update
// therefore reads the federation first and resends every one of these that the read returned,
// managed or not, so that a field set in the portal or behind an early-access flag survives a
// Terraform apply.
//
// Deliberately absent: FederationUuid, FederationName and FederationType (always sent from the
// request), Config and Mappings (sent separately), NormalizedFederationName, PartnerManageable,
// IsSystemManaged and DirectLoginSupported (server-owned), OIDCAccessTokenUrl, OIDCAuthCodeUrl and
// OIDCIDTokenUrl (derived from the metadata URL), and both secrets (an omitted secret is kept).
var echoedColumns = []string{
	activeColumn,
	"Usage",
	"SAMLSignAlgorithm",
	domainsColumn,
	"MapUsers",
	"MapUserAttribute",
	"MapUserBy",
	"MapUserDirectoryService",
	"MapUserSyncWithCloudUser",
	"MapUserSyncWithFedUser",
	"UpdateNameAttributeOnFederation",
	"MapUserByCustomAttribute",
	"MapUserUsesGroups",
	"MapUserCreateIfNotFound",
	"EnableUrlRedirecting",
	"UrlPattern",
	"OAuthClientId",
	"OAuthAccessTokenUrl",
	"OIDCClientId",
	"OIDCMetaDataUrl",
	"OIDCGrantType",
	"PKCEEnabled",
	"OIDCScopes",
	"MapUserAllowFederations",
	"DeviceTypes",
	"Apps",
	"UserAgents",
	"CyberarkServices",
	"ServiceCondition",
	attributeMappingsColumn,
	"ExcludedAttributes",
	"Role",
}

// readOnlyConfigKeys are Config entries that GetFederation injects from the tenant's signing
// certificate rather than from storage. Echoing them would persist a snapshot of the certificate.
var readOnlyConfigKeys = []string{
	"SPSigningCertificateExpires",
	"SPSigningCertificateSubject",
	"SPSigningCertificateThumbprint",
}

// IdsecIdentityFederationsService is the service for managing federation.
//
// CreateFederation and UpdateFederation read Request.Form, and GetGlobalFederationSettings reads
// Request.Params, so those calls go through formClient, a second ISP client whose session sends
// application/x-www-form-urlencoded. The other endpoints read a JSON body and use the default
// client. Keeping two clients avoids switching the Content-Type of a shared session.
type IdsecIdentityFederationsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService

	formClient *isp.IdsecISPServiceClient

	DoPost     func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	DoFormPost func(ctx context.Context, path string, form map[string]string) (*http.Response, error)
	// DoMultipartPost sends a form with file parts, for the SAML uploads.
	DoMultipartPost func(ctx context.Context, path string, body *common.IdsecMultipartBody) (*http.Response, error)

	// samlSettings caches the SAML service provider settings for samlSettingsTTL: they are
	// tenant-wide, where the OIDC ones depend on the federation.
	samlSettingsLock sync.Mutex
	samlSettings     map[string]interface{}
	samlSettingsRead time.Time

	// mappingsLock is the tenant's lock from mappingsLocks.
	mappingsLock *sync.Mutex
}

// NewIdsecIdentityFederationsService creates a new instance of IdsecIdentityFederationsService.
func NewIdsecIdentityFederationsService(authenticators ...auth.IdsecAuth) (*IdsecIdentityFederationsService, error) {
	service := &IdsecIdentityFederationsService{}
	var serviceInterface services.IdsecService = service
	baseService, err := services.NewIdsecBaseService(serviceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "", "", "api/idadmin", service.refreshIdentityFederationsAuth)
	if err != nil {
		return nil, err
	}

	ispBaseService.ISPClient().UpdateHeaders(map[string]string{
		"X-IDAP-NATIVE-CLIENT": "true",
	})

	baseURL, err := identitycommon.ResolveIdentityServiceURL(ispAuth, ispBaseService.ISPClient().BaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve identity service URL: %w", err)
	}
	ispBaseService.ISPClient().BaseURL = baseURL

	formClient, err := isp.FromISPAuth(ispAuth, "", "", "api/idadmin", service.refreshIdentityFederationsAuth, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create form client: %w", err)
	}
	formClient.UpdateHeaders(map[string]string{
		"X-IDAP-NATIVE-CLIENT": "true",
		"Content-Type":         formContentType,
	})
	formClient.BaseURL = baseURL

	service.IdsecBaseService = baseService
	service.IdsecISPBaseService = ispBaseService
	service.formClient = formClient
	service.mappingsLock = tenantMappingsLock(baseURL)
	return service, nil
}

func (s *IdsecIdentityFederationsService) postOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.DoPost != nil {
		return s.DoPost
	}
	return s.ISPClient().Post
}

func (s *IdsecIdentityFederationsService) postFormOperation() func(ctx context.Context, path string, form map[string]string) (*http.Response, error) {
	if s.DoFormPost != nil {
		return s.DoFormPost
	}
	return func(ctx context.Context, path string, form map[string]string) (*http.Response, error) {
		return s.formClient.Post(ctx, path, form)
	}
}

func (s *IdsecIdentityFederationsService) postMultipartOperation() func(ctx context.Context, path string, body *common.IdsecMultipartBody) (*http.Response, error) {
	if s.DoMultipartPost != nil {
		return s.DoMultipartPost
	}
	return func(ctx context.Context, path string, body *common.IdsecMultipartBody) (*http.Response, error) {
		return s.formClient.Post(ctx, path, body)
	}
}

func (s *IdsecIdentityFederationsService) refreshIdentityFederationsAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// ServiceConfig returns the service configuration for the IdsecIdentityFederationsService.
//
// Required, not optional: services.IdsecService includes ServiceConfig(), and the constructor
// assigns the service to that interface, so omitting this does not compile. The returned value is
// the package-level var from the service_config file.
func (s *IdsecIdentityFederationsService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}

// decodeResult checks the status and the success flag of a response and returns its Result.
func decodeResult(response *http.Response, action string) (interface{}, error) {
	defer func(body io.ReadCloser) {
		err := body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to %s - [%d] - [%s]", action, response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to %s - [%v]", action, result)
	}
	return result["Result"], nil
}

func (s *IdsecIdentityFederationsService) post(path string, body interface{}, action string) (interface{}, error) {
	response, err := s.postOperation()(context.Background(), path, body)
	if err != nil {
		s.Logger.Error("Error trying to %s: %s", action, err.Error())
		return nil, err
	}
	return decodeResult(response, action)
}

// postForm posts a form. With files it is sent as multipart/form-data, which CreateFederation and
// UpdateFederation read the same way, plus Request.Files.
func (s *IdsecIdentityFederationsService) postForm(path string, form map[string]string, action string, files ...common.IdsecMultipartFile) (interface{}, error) {
	var response *http.Response
	var err error
	if files != nil {
		response, err = s.postMultipartOperation()(context.Background(), path, &common.IdsecMultipartBody{Fields: form, Files: files})
	} else {
		response, err = s.postFormOperation()(context.Background(), path, form)
	}
	if err != nil {
		s.Logger.Error("Error trying to %s: %s", action, err.Error())
		return nil, err
	}
	return decodeResult(response, action)
}

// formString encodes a value read back from the server the way the parser on the server expects
// it: lists comma-joined (Domains, OIDCScopes, Apps, UserAgents and so on are split on commas),
// bools as true/false, numbers (enum columns such as Usage and MapUsers come back numeric and go
// through Enum.TryParse) in their shortest form, and anything else as JSON. The second return
// value is false when there is nothing worth sending.
func formString(value interface{}) (string, bool) {
	switch v := value.(type) {
	case nil:
		return "", false
	case string:
		return v, v != ""
	case bool:
		return strconv.FormatBool(v), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case []interface{}:
		items := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := formString(item); ok {
				items = append(items, str)
			}
		}
		return strings.Join(items, ","), len(items) > 0
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return "", false
		}
		return string(encoded), true
	}
}

// echoForm builds the form for UpdateFederation from the federation as the server returned it.
func echoForm(existing map[string]interface{}) map[string]string {
	form := map[string]string{}
	for _, column := range echoedColumns {
		value, ok := existing[column]
		if !ok {
			continue
		}
		if column == attributeMappingsColumn {
			// GetFederation already normalizes AttributeMappings to the [{Target, Source}] list
			// that ValidateAndPrepareAttributeMapping parses, so it is resent as JSON, not joined.
			if list, isList := value.([]interface{}); isList {
				if len(list) > 0 {
					encoded, err := json.Marshal(list)
					if err == nil {
						form[column] = string(encoded)
					}
				}
				continue
			}
		}
		if str, send := formString(value); send {
			form[column] = str
		}
	}
	if config, ok := existing[configColumn].(map[string]interface{}); ok {
		for key, value := range config {
			if slices.Contains(readOnlyConfigKeys, key) || slices.Contains(samlInboundConfigKeys, key) {
				continue
			}
			if _, isMap := value.(map[string]interface{}); isMap {
				// Config entries are posted as flat form fields; a nested value cannot have come
				// from a form post, so it is server-owned and left alone.
				continue
			}
			if str, send := formString(value); send {
				form[key] = str
			}
		}
	}
	// ParseCreateUpdateFederationParameters deserializes Mappings even when it is absent and fails
	// on null, so it is always sent, and UpdateFederation replaces the group mappings with it.
	form[mappingsColumn] = "[]"
	if mappings, ok := existing[mappingsColumn].([]interface{}); ok && len(mappings) > 0 {
		encoded, err := json.Marshal(mappings)
		if err == nil {
			form[mappingsColumn] = string(encoded)
		}
	}
	return form
}

// createOIDCFields adds the OIDC fields of a new federation. Grant type and PKCE fall back to the
// portal defaults when unset. The secret is only sent when supplied.
func createOIDCFields(form map[string]string, arg *federationsmodels.IdsecIdentityCreateFederation) {
	form["OIDCMetaDataUrl"] = arg.OIDCMetadataURL
	form["OIDCClientId"] = arg.OIDCClientID
	if arg.OIDCClientSecret != nil && *arg.OIDCClientSecret != "" {
		form["OIDCClientSecret"] = *arg.OIDCClientSecret
	}
	grantType := arg.OIDCGrantType
	if grantType == "" {
		grantType = defaultOIDCGrantType
	}
	form["OIDCGrantType"] = grantType
	pkce := true
	if arg.PKCEEnabled != nil {
		pkce = *arg.PKCEEnabled
	}
	form["PKCEEnabled"] = strconv.FormatBool(pkce)
	form["OIDCScopes"] = strings.Join(arg.OIDCScopes, ",")
	form[logoutCallBackURIConfigKey] = arg.LogoutCallBackURI
}

// updateOIDCFields lays the OIDC fields that are set over an echoed form. Unset fields keep the
// echoed value. The secret is only sent when rotated: the server keeps the stored one otherwise.
func updateOIDCFields(form map[string]string, arg *federationsmodels.IdsecIdentityUpdateFederation) {
	setString(form, "OIDCMetaDataUrl", arg.OIDCMetadataURL)
	setString(form, "OIDCClientId", arg.OIDCClientID)
	if arg.OIDCClientSecret != nil && *arg.OIDCClientSecret != "" {
		form["OIDCClientSecret"] = *arg.OIDCClientSecret
	}
	setString(form, "OIDCGrantType", arg.OIDCGrantType)
	setBool(form, "PKCEEnabled", arg.PKCEEnabled)
	setList(form, "OIDCScopes", arg.OIDCScopes)
	setString(form, logoutCallBackURIConfigKey, arg.LogoutCallBackURI)
}

// createMappingFields adds the user mapping, group mapping, attribute mapping and routing fields
// of a new federation, with the portal defaults for those left unset.
func createMappingFields(form map[string]string, arg *federationsmodels.IdsecIdentityCreateFederation) {
	form[mapUsersColumn] = valueOr(arg.MapUsers, defaultMapUsers)
	form[mapUserAttributeColumn] = valueOr(arg.MapUserAttribute, defaultMapUserAttribute)
	form[mapUserByColumn] = valueOr(arg.MapUserBy, defaultMapUserBy)
	form[mapUserDirectoryColumn] = arg.MapUserDirectoryService
	syncWithFedUser := defaultSyncWithFedUser
	if arg.MapUserSyncWithFedUser != nil {
		syncWithFedUser = *arg.MapUserSyncWithFedUser
	}
	form[syncWithFedUserColumn] = strconv.FormatBool(syncWithFedUser)
	setBool(form, "MapUserSyncWithCloudUser", arg.MapUserSyncWithCloudUser)
	setBool(form, "MapUserUsesGroups", arg.MapUserUsesGroups)
	setBool(form, "MapUserAllowFederations", arg.MapUserAllowFederations)
	setBool(form, "MapUserCreateIfNotFound", arg.MapUserCreateIfNotFound)
	setGroupMappings(form, arg.GroupMappings)
	setAttributeMappings(form, arg.AttributeMappings)
	if arg.DeviceTypes != nil {
		form[deviceTypesColumn] = strings.Join(arg.DeviceTypes, ",")
	}
	if arg.UserAgents != nil {
		form[userAgentsColumn] = strings.Join(arg.UserAgents, ",")
	}
}

// updateMappingFields lays the user mapping, group mapping, attribute mapping and routing fields
// that are set over an echoed form.
func updateMappingFields(form map[string]string, arg *federationsmodels.IdsecIdentityUpdateFederation) {
	setString(form, mapUsersColumn, arg.MapUsers)
	setString(form, mapUserAttributeColumn, arg.MapUserAttribute)
	setString(form, mapUserByColumn, arg.MapUserBy)
	setString(form, mapUserDirectoryColumn, arg.MapUserDirectoryService)
	setBool(form, syncWithFedUserColumn, arg.MapUserSyncWithFedUser)
	setBool(form, "MapUserSyncWithCloudUser", arg.MapUserSyncWithCloudUser)
	setBool(form, "MapUserUsesGroups", arg.MapUserUsesGroups)
	setBool(form, "MapUserAllowFederations", arg.MapUserAllowFederations)
	setBool(form, "MapUserCreateIfNotFound", arg.MapUserCreateIfNotFound)
	if arg.GroupMappings != nil {
		setGroupMappings(form, *arg.GroupMappings)
	}
	if arg.AttributeMappings != nil {
		setAttributeMappings(form, *arg.AttributeMappings)
	}
	setList(form, deviceTypesColumn, arg.DeviceTypes)
	setList(form, userAgentsColumn, arg.UserAgents)
}

// setGroupMappings sends the group mappings in the [{AttributeValue, GroupName}] shape that
// ParseCreateUpdateFederationParameters reads. An empty list clears them. Encoding a list of
// string maps cannot fail.
func setGroupMappings(form map[string]string, mappings []federationsmodels.IdsecIdentityFederationGroupMapping) {
	wire := []map[string]string{}
	for _, mapping := range mappings {
		wire = append(wire, map[string]string{"AttributeValue": mapping.AttributeValue, "GroupName": mapping.GroupName})
	}
	encoded, _ := json.Marshal(wire)
	form[mappingsColumn] = string(encoded)
}

// setAttributeMappings sends the attribute mappings in the [{Target, Source}] shape that
// ValidateAndPrepareAttributeMapping reads. An empty list clears them.
func setAttributeMappings(form map[string]string, mappings []federationsmodels.IdsecIdentityFederationAttributeMapping) {
	wire := []map[string]string{}
	for _, mapping := range mappings {
		wire = append(wire, map[string]string{"Target": mapping.Target, "Source": mapping.Source})
	}
	encoded, _ := json.Marshal(wire)
	form[attributeMappingsColumn] = string(encoded)
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func setString(form map[string]string, key, value string) {
	if value != "" {
		form[key] = value
	}
}

func setBool(form map[string]string, key string, value *bool) {
	if value != nil {
		form[key] = strconv.FormatBool(*value)
	}
}

func setList(form map[string]string, key string, value *[]string) {
	if value != nil {
		form[key] = strings.Join(*value, ",")
	}
}

// samlInbound is the inbound configuration of a SAML federation: how the server learns the
// identity provider's sign-in URL and signing certificate. The server reads one of three modes from
// the request (SAML20FederationHelper):
//
//   - metadata URL: the server fetches the metadata on every create and update;
//   - metadata upload: the metadata document is sent as a file part;
//   - manual: the sign-in URL, an optional logout URL, and the signing certificate, sent as a file
//     part or, to keep the stored certificate, as its thumbprint.
//
// Manual mode always needs a multipart request, even with a thumbprint: the server reads its file
// parts without checking that the request has any, so an empty certificate part is sent.
type samlInbound struct {
	metadataURL string
	metadataXML string
	signInURL   string
	logoutURL   string
	certificate string
	thumbprint  string
}

// apply adds the mode to the form and returns the file parts to send, nil for a plain form.
func (in samlInbound) apply(form map[string]string) ([]common.IdsecMultipartFile, error) {
	switch {
	case in.metadataURL != "":
		form[isMetadataConfigKey] = "true"
		form[metadataIsURLConfigKey] = "true"
		form[idpMetadataURLConfigKey] = in.metadataURL
		return nil, nil
	case in.metadataXML != "":
		form[isMetadataConfigKey] = "true"
		form[metadataIsURLConfigKey] = "false"
		return []common.IdsecMultipartFile{{FieldName: idpMetadataFileField, FileName: "metadata.xml", Content: []byte(in.metadataXML)}}, nil
	}
	if in.signInURL == "" {
		return nil, fmt.Errorf("a SAML federation needs a metadata URL, a metadata document, or a sign-in URL and signing certificate")
	}
	form[idpSignInURLConfigKey] = in.signInURL
	form[idpLogoutURLConfigKey] = in.logoutURL
	if in.certificate != "" {
		return []common.IdsecMultipartFile{{FieldName: idpSigningCertificateField, FileName: "certificate.cer", Content: []byte(in.certificate)}}, nil
	}
	if in.thumbprint == "" {
		return nil, fmt.Errorf("a SAML federation configured without metadata needs a signing certificate")
	}
	form[idpThumbprintConfigKey] = in.thumbprint
	return []common.IdsecMultipartFile{{FieldName: idpSigningCertificateField}}, nil
}

// createSAMLFields adds the SAML fields of a new federation and returns its file parts.
func createSAMLFields(form map[string]string, arg *federationsmodels.IdsecIdentityCreateFederation) ([]common.IdsecMultipartFile, error) {
	form[samlSignAlgorithmColumn] = valueOr(arg.SAMLSignAlgorithm, defaultSAMLSignAlgorithm)
	setBool(form, "EnableUrlRedirecting", arg.SAMLURLRedirectEnabled)
	setString(form, "UrlPattern", arg.SAMLURLRedirectPattern)
	setSAMLOAuth(form, arg.SAMLOAuthClientID, arg.SAMLOAuthClientSecret, arg.SAMLOAuthAccessTokenURL)
	return samlInbound{
		metadataURL: arg.SAMLMetadataURL,
		metadataXML: stringOrEmpty(arg.SAMLMetadataXML),
		signInURL:   arg.SAMLSignInURL,
		logoutURL:   arg.SAMLLogoutURL,
		certificate: stringOrEmpty(arg.SAMLSigningCertificate),
	}.apply(form)
}

// setSAMLOAuth sets the OAuth credentials used to sign the identity provider's users in with a
// password. Unset values are left out: on update the echo already carries the stored client ID and
// token URL, and the server keeps the stored secret when none is sent.
func setSAMLOAuth(form map[string]string, clientID string, clientSecret *string, accessTokenURL string) {
	setString(form, "OAuthClientId", clientID)
	setString(form, "OAuthClientSecret", stringOrEmpty(clientSecret))
	setString(form, "OAuthAccessTokenUrl", accessTokenURL)
}

// updateSAMLFields lays the SAML fields that are set over an echoed form and returns its file parts.
//
// The inbound mode is always resent. A new metadata URL or document selects its mode; a new sign-in
// URL or certificate selects manual mode. Otherwise the stored mode is kept: the stored metadata URL
// is fetched again, and a federation without one, including one created from an uploaded document,
// is resent in manual mode with its stored URLs and certificate thumbprint, as the portal does.
func updateSAMLFields(form map[string]string, arg *federationsmodels.IdsecIdentityUpdateFederation, existing map[string]interface{}) ([]common.IdsecMultipartFile, error) {
	setString(form, samlSignAlgorithmColumn, arg.SAMLSignAlgorithm)
	setBool(form, "EnableUrlRedirecting", arg.SAMLURLRedirectEnabled)
	setString(form, "UrlPattern", arg.SAMLURLRedirectPattern)
	setSAMLOAuth(form, arg.SAMLOAuthClientID, arg.SAMLOAuthClientSecret, arg.SAMLOAuthAccessTokenURL)
	config, _ := existing[configColumn].(map[string]interface{})
	in := samlInbound{
		metadataURL: arg.SAMLMetadataURL,
		metadataXML: stringOrEmpty(arg.SAMLMetadataXML),
		signInURL:   valueOr(arg.SAMLSignInURL, stringValue(config, idpSignInURLConfigKey)),
		logoutURL:   valueOr(arg.SAMLLogoutURL, stringValue(config, idpLogoutURLConfigKey)),
		certificate: stringOrEmpty(arg.SAMLSigningCertificate),
		thumbprint:  stringValue(config, idpThumbprintConfigKey),
	}
	manual := arg.SAMLSignInURL != "" || in.certificate != ""
	if in.metadataURL == "" && in.metadataXML == "" && !manual {
		in.metadataURL = stringValue(config, idpMetadataURLConfigKey)
	}
	return in.apply(form)
}

func stringOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func validateFederationType(federationType string) error {
	if !slices.Contains(supportedFederationTypes, federationType) {
		return fmt.Errorf("unsupported federation type [%s], expected one of %v", federationType, supportedFederationTypes)
	}
	return nil
}

func stringValue(raw map[string]interface{}, key string) string {
	if value, ok := raw[key].(string); ok {
		return value
	}
	return ""
}

// boolValue reads a flag that the server stores either as a bool or, when it came straight from a
// form post, as the string "true"/"false".
func boolValue(raw map[string]interface{}, key string, fallback bool) bool {
	switch v := raw[key].(type) {
	case bool:
		return v
	case string:
		parsed, err := strconv.ParseBool(v)
		if err == nil {
			return parsed
		}
	}
	return fallback
}

// listValue reads a list column. Domains and OIDCScopes are stored as lists, but a value that
// bypassed parsing (an empty scopes field is never split) comes back as a comma string.
func listValue(raw map[string]interface{}, key string) []string {
	values := []string{}
	switch v := raw[key].(type) {
	case []interface{}:
		for _, item := range v {
			if str, ok := item.(string); ok && str != "" {
				values = append(values, str)
			}
		}
	case string:
		for _, item := range strings.Split(v, ",") {
			if item = strings.TrimSpace(item); item != "" {
				values = append(values, item)
			}
		}
	}
	return values
}

func parseFederation(raw map[string]interface{}) *federationsmodels.IdsecIdentityFederation {
	federation := &federationsmodels.IdsecIdentityFederation{
		FederationUUID: stringValue(raw, federationUUIDColumn),
		FederationName: stringValue(raw, federationNameColumn),
		FederationType: stringValue(raw, federationTypeColumn),
		Active:         boolValue(raw, activeColumn, true),
		Domains:        listValue(raw, domainsColumn),
		OIDCScopes:     []string{},
	}
	parseMappingFields(raw, federation)
	if federation.FederationType == federationTypeSAML {
		parseSAMLFields(raw, federation)
	}
	if federation.FederationType == federationTypeOIDC {
		federation.OIDCMetadataURL = stringValue(raw, "OIDCMetaDataUrl")
		federation.OIDCClientID = stringValue(raw, "OIDCClientId")
		federation.OIDCGrantType = stringValue(raw, "OIDCGrantType")
		federation.PKCEEnabled = boolValue(raw, "PKCEEnabled", false)
		federation.OIDCScopes = listValue(raw, "OIDCScopes")
		if config, ok := raw[configColumn].(map[string]interface{}); ok {
			federation.LogoutCallBackURI = stringValue(config, logoutCallBackURIConfigKey)
		}
	}
	return federation
}

// parseSAMLFields reads the SAML fields. The uploaded metadata document and certificate are not
// returned; the certificate is described by its thumbprint, subject and expiry instead.
func parseSAMLFields(raw map[string]interface{}, federation *federationsmodels.IdsecIdentityFederation) {
	config, _ := raw[configColumn].(map[string]interface{})
	federation.SAMLMetadataURL = stringValue(config, idpMetadataURLConfigKey)
	federation.SAMLSignInURL = stringValue(config, idpSignInURLConfigKey)
	federation.SAMLLogoutURL = stringValue(config, idpLogoutURLConfigKey)
	federation.SAMLCertificateThumbprint = stringValue(config, idpThumbprintConfigKey)
	federation.SAMLCertificateSubject = stringValue(config, idpSubjectConfigKey)
	federation.SAMLCertificateExpires = stringValue(config, idpExpiresConfigKey)
	// The server signs with SHA1 when no algorithm is stored.
	federation.SAMLSignAlgorithm = valueOr(stringValue(raw, samlSignAlgorithmColumn), "SHA1")
	federation.SAMLURLRedirectEnabled = boolValue(raw, "EnableUrlRedirecting", false)
	federation.SAMLURLRedirectPattern = stringValue(raw, "UrlPattern")
	federation.SAMLOAuthClientID = stringValue(raw, "OAuthClientId")
	federation.SAMLOAuthAccessTokenURL = stringValue(raw, "OAuthAccessTokenUrl")
	federation.SAMLSPMetadataURL = stringValue(raw, "SPMetadataUrl")
}

// parseMappingFields reads the user mapping, group mapping, attribute mapping and routing fields.
// Absent columns read as the defaults the server applies at sign-in.
func parseMappingFields(raw map[string]interface{}, federation *federationsmodels.IdsecIdentityFederation) {
	federation.MapUsers = defaultMapUsers
	switch v := raw[mapUsersColumn].(type) {
	case string:
		if index, err := strconv.Atoi(v); err == nil && index >= 0 && index < len(mapUsersNames) {
			federation.MapUsers = mapUsersNames[index]
		} else if v != "" {
			federation.MapUsers = v
		}
	case float64:
		if index := int(v); index >= 0 && index < len(mapUsersNames) {
			federation.MapUsers = mapUsersNames[index]
		}
	}
	federation.MapUserAttribute = valueOr(stringValue(raw, mapUserAttributeColumn), defaultMapUserAttribute)
	federation.MapUserBy = valueOr(stringValue(raw, mapUserByColumn), defaultMapUserBy)
	federation.MapUserDirectoryService = stringValue(raw, mapUserDirectoryColumn)
	federation.MapUserSyncWithCloudUser = boolValue(raw, "MapUserSyncWithCloudUser", false)
	federation.MapUserSyncWithFedUser = boolValue(raw, syncWithFedUserColumn, defaultSyncWithFedUser)
	federation.MapUserUsesGroups = boolValue(raw, "MapUserUsesGroups", false)
	federation.MapUserAllowFederations = boolValue(raw, "MapUserAllowFederations", false)
	federation.MapUserCreateIfNotFound = boolValue(raw, "MapUserCreateIfNotFound", false)

	federation.GroupMappings = []federationsmodels.IdsecIdentityFederationGroupMapping{}
	if mappings, ok := raw[mappingsColumn].([]interface{}); ok {
		for _, item := range mappings {
			if entry, ok := item.(map[string]interface{}); ok {
				federation.GroupMappings = append(federation.GroupMappings, federationsmodels.IdsecIdentityFederationGroupMapping{
					AttributeValue: stringValue(entry, "AttributeValue"),
					GroupName:      stringValue(entry, "GroupName"),
				})
			}
		}
	}
	federation.AttributeMappings = []federationsmodels.IdsecIdentityFederationAttributeMapping{}
	if mappings, ok := raw[attributeMappingsColumn].([]interface{}); ok {
		for _, item := range mappings {
			if entry, ok := item.(map[string]interface{}); ok {
				federation.AttributeMappings = append(federation.AttributeMappings, federationsmodels.IdsecIdentityFederationAttributeMapping{
					Target: stringValue(entry, "Target"),
					Source: stringValue(entry, "Source"),
				})
			}
		}
	}
	// DeviceTypes is stored as a comma string, with "" for every device type.
	federation.DeviceTypes = listValue(raw, deviceTypesColumn)
	// UserAgents is stored as a list, and the server stores ["Any"] when none is sent.
	federation.UserAgents = listValue(raw, userAgentsColumn)
	if len(federation.UserAgents) == 0 {
		federation.UserAgents = []string{"Any"}
	}
}

// getRaw returns the federation exactly as GetFederation reports it.
func (s *IdsecIdentityFederationsService) getRaw(federationUUID string) (map[string]interface{}, error) {
	result, err := s.post(readFederationURL, map[string]interface{}{federationUUIDColumn: federationUUID}, "retrieve identity federation")
	if err != nil {
		// GetFederation reports a missing federation only through a localized message, so the
		// listing decides whether the failure means "gone".
		exists, listErr := s.exists(federationUUID)
		if listErr == nil && !exists {
			return nil, fmt.Errorf("identity federation [%s] not found: %w", federationUUID, common.ErrNotFound)
		}
		return nil, err
	}
	raw, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse identity federation - [%v]", result)
	}
	return raw, nil
}

func (s *IdsecIdentityFederationsService) exists(federationUUID string) (bool, error) {
	all, err := s.listRaw()
	if err != nil {
		return false, err
	}
	for _, raw := range all {
		if stringValue(raw, federationUUIDColumn) == federationUUID {
			return true, nil
		}
	}
	return false, nil
}

// fillServiceProviderURLs adds the URLs the administrator registers at the OIDC identity
// provider. They are tenant-wide and are not stored on the federation.
func (s *IdsecIdentityFederationsService) fillServiceProviderURLs(federation *federationsmodels.IdsecIdentityFederation) error {
	settings, err := s.serviceProviderSettings(federation)
	if err != nil {
		return err
	}
	if federation.FederationType == federationTypeOIDC {
		federation.SPRedirectURL = stringValue(settings, "SPRedirectUrl")
		federation.SPInitiateLoginURL = stringValue(settings, "SPInitiateLoginUrl")
		return nil
	}
	// The response spells the ACS URL "SPAutnenticationResponseUrl".
	federation.SAMLSPACSURL = stringValue(settings, "SPAutnenticationResponseUrl")
	federation.SAMLSPSigningCertificateURL = stringValue(settings, "SPSigningCertificateUrl")
	if federation.SAMLSPMetadataURL == "" {
		federation.SAMLSPMetadataURL = stringValue(settings, "SPMetadataUrl")
	}
	return nil
}

// serviceProviderSettings reads the service provider settings for a federation. The SAML ones are
// cached for samlSettingsTTL; a failed read is not cached.
func (s *IdsecIdentityFederationsService) serviceProviderSettings(federation *federationsmodels.IdsecIdentityFederation) (map[string]interface{}, error) {
	isSAML := federation.FederationType != federationTypeOIDC
	if isSAML {
		s.samlSettingsLock.Lock()
		defer s.samlSettingsLock.Unlock()
		if s.samlSettings != nil && time.Since(s.samlSettingsRead) < samlSettingsTTL {
			return s.samlSettings, nil
		}
	}
	form := map[string]string{federationTypeColumn: federation.FederationType}
	if !isSAML {
		form[federationUUIDColumn] = federation.FederationUUID
	}
	result, err := s.postForm(globalFederationSettingsURL, form, "retrieve global federation settings")
	if err != nil {
		return nil, err
	}
	settings, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse global federation settings - [%v]", result)
	}
	if isSAML {
		s.samlSettings = settings
		s.samlSettingsRead = time.Now()
	}
	return settings, nil
}

func (s *IdsecIdentityFederationsService) parseWithURLs(result interface{}, action string) (*federationsmodels.IdsecIdentityFederation, error) {
	raw, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to %s - [%v]", action, result)
	}
	federation := parseFederation(raw)
	if err := s.fillServiceProviderURLs(federation); err != nil {
		return nil, err
	}
	return federation, nil
}

// parseWritten parses the federation a create or update returned. The write has already happened,
// so a failure to read the service provider URLs is only logged and they are left empty: an error
// would make the caller retry a create that succeeded, which the server rejects for a SAML
// federation (its certificate is already in use). The next Get fills them.
func (s *IdsecIdentityFederationsService) parseWritten(result interface{}, action string) (*federationsmodels.IdsecIdentityFederation, error) {
	raw, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to %s - [%v]", action, result)
	}
	federation := parseFederation(raw)
	if err := s.fillServiceProviderURLs(federation); err != nil {
		s.Logger.Warning("Identity federation [%s] was written, but its service provider URLs could not be read: %s", federation.FederationUUID, err.Error())
	}
	return federation, nil
}

// Create creates a new federation. The settings it would store are checked first, by
// ValidateFederationSettings.
//
// Usage is never sent: the server defaults it to SSO, and choosing another usage is an
// early-access feature.
func (s *IdsecIdentityFederationsService) Create(arg *federationsmodels.IdsecIdentityCreateFederation) (*federationsmodels.IdsecIdentityFederation, error) {
	s.Logger.Debug("Creating identity federation [%s]", arg.FederationName)
	if err := validateFederationType(arg.FederationType); err != nil {
		return nil, err
	}
	if err := ValidateCreateFederationSettings(arg); err != nil {
		return nil, err
	}
	form := map[string]string{
		federationNameColumn: arg.FederationName,
		federationTypeColumn: arg.FederationType,
		activeColumn:         strconv.FormatBool(arg.Active),
		domainsColumn:        strings.Join(arg.Domains, ","),
	}
	createMappingFields(form, arg)
	var files []common.IdsecMultipartFile
	if arg.FederationType == federationTypeOIDC {
		createOIDCFields(form, arg)
	} else {
		var err error
		if files, err = createSAMLFields(form, arg); err != nil {
			return nil, err
		}
	}
	result, err := s.create(form, files)
	if err != nil {
		return nil, err
	}
	return s.parseWritten(result, "retrieve created identity federation")
}

// create posts a new federation under mappingsLock: its group mappings go into the shared file.
func (s *IdsecIdentityFederationsService) create(form map[string]string, files []common.IdsecMultipartFile) (interface{}, error) {
	s.mappingsLock.Lock()
	defer s.mappingsLock.Unlock()
	return s.postForm(createFederationURL, form, "create identity federation", files...)
}

// Get returns a single federation.
func (s *IdsecIdentityFederationsService) Get(arg *federationsmodels.IdsecIdentityGetFederation) (*federationsmodels.IdsecIdentityFederation, error) {
	s.Logger.Debug("Retrieving identity federation [%s]", arg.FederationUUID)
	raw, err := s.getRaw(arg.FederationUUID)
	if err != nil {
		return nil, err
	}
	if err := validateFederationType(stringValue(raw, federationTypeColumn)); err != nil {
		return nil, fmt.Errorf("identity federation [%s]: %w", arg.FederationUUID, err)
	}
	return s.parseWithURLs(raw, "retrieve identity federation")
}

// Update updates an existing federation.
//
// UpdateFederation rebuilds the federation from the request, so Update first reads it and
// resends every writable field it returned (see echoedColumns), then lays the managed fields over
// that. The settings that would result are checked first, by ValidateFederationSettings.
func (s *IdsecIdentityFederationsService) Update(arg *federationsmodels.IdsecIdentityUpdateFederation) (*federationsmodels.IdsecIdentityFederation, error) {
	s.Logger.Debug("Updating identity federation [%s]", arg.FederationUUID)
	result, err := s.update(arg)
	if err != nil {
		return nil, err
	}
	return s.parseWritten(result, "retrieve updated identity federation")
}

// update reads the federation and posts the update, under mappingsLock. The lock covers the read
// too: the echoed group mappings must be the ones being replaced.
func (s *IdsecIdentityFederationsService) update(arg *federationsmodels.IdsecIdentityUpdateFederation) (interface{}, error) {
	s.mappingsLock.Lock()
	defer s.mappingsLock.Unlock()
	existing, err := s.getRaw(arg.FederationUUID)
	if err != nil {
		return nil, err
	}
	existingType := stringValue(existing, federationTypeColumn)
	if err := validateFederationType(existingType); err != nil {
		return nil, fmt.Errorf("identity federation [%s]: %w", arg.FederationUUID, err)
	}
	if arg.FederationType != "" && arg.FederationType != existingType {
		return nil, fmt.Errorf("identity federation [%s] is of type [%s] and cannot be changed to [%s]", arg.FederationUUID, existingType, arg.FederationType)
	}
	if err := ValidateUpdateFederationSettings(parseFederation(existing), arg); err != nil {
		return nil, err
	}
	form := echoForm(existing)
	form[federationUUIDColumn] = arg.FederationUUID
	form[federationNameColumn] = arg.FederationName
	form[federationTypeColumn] = existingType
	form[activeColumn] = strconv.FormatBool(arg.Active)
	setList(form, domainsColumn, arg.Domains)
	updateMappingFields(form, arg)
	var files []common.IdsecMultipartFile
	if existingType == federationTypeOIDC {
		updateOIDCFields(form, arg)
	} else if files, err = updateSAMLFields(form, arg, existing); err != nil {
		return nil, err
	}
	return s.postForm(updateFederationURL, form, "update identity federation", files...)
}

// Delete removes a federation. A federation that is already gone counts as deleted.
func (s *IdsecIdentityFederationsService) Delete(arg *federationsmodels.IdsecIdentityDeleteFederation) error {
	s.Logger.Debug("Deleting identity federation [%s]", arg.FederationUUID)
	// DeleteFederation also removes the federation's rows from the shared mappings file.
	s.mappingsLock.Lock()
	defer s.mappingsLock.Unlock()
	_, err := s.post(deleteFederationURL, map[string]interface{}{federationUUIDColumn: arg.FederationUUID}, "delete identity federation")
	if err != nil {
		exists, listErr := s.exists(arg.FederationUUID)
		if listErr == nil && !exists {
			return nil
		}
		return err
	}
	return nil
}

func (s *IdsecIdentityFederationsService) listRaw() ([]map[string]interface{}, error) {
	result, err := s.post(listFederationURL, map[string]interface{}{}, "list identity federations")
	if err != nil {
		return nil, err
	}
	rows, ok := result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse identity federations - [%v]", result)
	}
	all := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		raw, ok := row.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to parse identity federation - [%v]", row)
		}
		all = append(all, raw)
	}
	return all, nil
}

// List returns every SAML 2.0 and OIDC federation.
//
// The service provider URLs cost a call per federation and are not filled here; Get returns
// them.
func (s *IdsecIdentityFederationsService) List() ([]federationsmodels.IdsecIdentityFederation, error) {
	s.Logger.Debug("Listing identity federations")
	all, err := s.listRaw()
	if err != nil {
		return nil, err
	}
	federations := []federationsmodels.IdsecIdentityFederation{}
	for _, raw := range all {
		if validateFederationType(stringValue(raw, federationTypeColumn)) != nil {
			continue
		}
		federations = append(federations, *parseFederation(raw))
	}
	return federations, nil
}

// ListBy returns the federations matching the supplied filters.
func (s *IdsecIdentityFederationsService) ListBy(arg *federationsmodels.IdsecIdentityFederationFilters) ([]federationsmodels.IdsecIdentityFederation, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	filtered := []federationsmodels.IdsecIdentityFederation{}
	for _, federation := range all {
		if arg.FederationName != "" && !strings.EqualFold(federation.FederationName, arg.FederationName) {
			continue
		}
		if arg.FederationType != "" && federation.FederationType != arg.FederationType {
			continue
		}
		filtered = append(filtered, federation)
	}
	return filtered, nil
}

func parseGlobalMappings(result interface{}) ([]federationsmodels.IdsecIdentityFederationGlobalGroupMapping, error) {
	body, ok := result.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse global group mappings - [%v]", result)
	}
	mappings := []federationsmodels.IdsecIdentityFederationGlobalGroupMapping{}
	rows, _ := body[mappingsColumn].([]interface{})
	for _, row := range rows {
		entry, ok := row.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to parse global group mapping - [%v]", row)
		}
		mappings = append(mappings, federationsmodels.IdsecIdentityFederationGlobalGroupMapping{
			AttributeValue: stringValue(entry, "AttributeValue"),
			GroupName:      stringValue(entry, "GroupName"),
		})
	}
	return mappings, nil
}

// ListGlobalGroupMappings returns the group mappings that apply to every federation.
func (s *IdsecIdentityFederationsService) ListGlobalGroupMappings() ([]federationsmodels.IdsecIdentityFederationGlobalGroupMapping, error) {
	s.Logger.Debug("Listing identity federation global group mappings")
	result, err := s.post(listGlobalMappingsURL, map[string]interface{}{}, "list identity federation global group mappings")
	if err != nil {
		return nil, err
	}
	return parseGlobalMappings(result)
}

// GetGlobalGroupMapping returns a global group mapping. The server compares mappings without
// regard to case, so the match does too, and the result carries the stored spelling.
func (s *IdsecIdentityFederationsService) GetGlobalGroupMapping(arg *federationsmodels.IdsecIdentityGetFederationGlobalGroupMapping) (*federationsmodels.IdsecIdentityFederationGlobalGroupMapping, error) {
	mappings, err := s.ListGlobalGroupMappings()
	if err != nil {
		return nil, err
	}
	for _, mapping := range mappings {
		if strings.EqualFold(mapping.AttributeValue, arg.AttributeValue) && strings.EqualFold(mapping.GroupName, arg.GroupName) {
			return &mapping, nil
		}
	}
	return nil, fmt.Errorf("identity federation global group mapping [%s -> %s] not found: %w", arg.AttributeValue, arg.GroupName, common.ErrNotFound)
}

// globalMappingValues trims a global group mapping's values: the server stores them trimmed. It
// silently ignores a blank value, so a blank one is rejected here.
func globalMappingValues(attributeValue, groupName string) (string, string, error) {
	attributeValue = strings.TrimSpace(attributeValue)
	groupName = strings.TrimSpace(groupName)
	if attributeValue == "" || groupName == "" {
		return "", "", fmt.Errorf("a global group mapping needs both an attribute value and a group name")
	}
	return attributeValue, groupName, nil
}

// AddGlobalGroupMapping adds a group mapping that applies to every federation.
//
// The endpoint takes a single {"<AttributeValue>": "<GroupName>"} pair and returns nothing. It
// silently ignores a mapping that already exists, so that is checked first and is an error: the
// caller would otherwise take over a mapping it did not create. The result is read back.
func (s *IdsecIdentityFederationsService) AddGlobalGroupMapping(arg *federationsmodels.IdsecIdentityAddFederationGlobalGroupMapping) (*federationsmodels.IdsecIdentityFederationGlobalGroupMapping, error) {
	s.Logger.Debug("Adding identity federation global group mapping [%s -> %s]", arg.AttributeValue, arg.GroupName)
	attributeValue, groupName, err := globalMappingValues(arg.AttributeValue, arg.GroupName)
	if err != nil {
		return nil, err
	}
	s.mappingsLock.Lock()
	defer s.mappingsLock.Unlock()
	existing, err := s.GetGlobalGroupMapping(&federationsmodels.IdsecIdentityGetFederationGlobalGroupMapping{AttributeValue: attributeValue, GroupName: groupName})
	if err == nil {
		return nil, fmt.Errorf("identity federation global group mapping [%s -> %s] already exists", existing.AttributeValue, existing.GroupName)
	}
	if !errors.Is(err, common.ErrNotFound) {
		return nil, err
	}
	if _, err := s.post(addGlobalMappingURL, map[string]interface{}{attributeValue: groupName}, "add identity federation global group mapping"); err != nil {
		return nil, err
	}
	added, err := s.GetGlobalGroupMapping(&federationsmodels.IdsecIdentityGetFederationGlobalGroupMapping{AttributeValue: attributeValue, GroupName: groupName})
	if errors.Is(err, common.ErrNotFound) {
		return nil, fmt.Errorf("identity federation global group mapping [%s -> %s] was added but not stored: %w", attributeValue, groupName, common.ErrNotFound)
	}
	return added, err
}

// RemoveGlobalGroupMapping removes a global group mapping. A mapping that is already gone counts
// as removed: the server reports success for it. The server matches the mapping without regard to
// case, and the result is read back.
func (s *IdsecIdentityFederationsService) RemoveGlobalGroupMapping(arg *federationsmodels.IdsecIdentityRemoveFederationGlobalGroupMapping) error {
	s.Logger.Debug("Removing identity federation global group mapping [%s -> %s]", arg.AttributeValue, arg.GroupName)
	attributeValue, groupName, err := globalMappingValues(arg.AttributeValue, arg.GroupName)
	if err != nil {
		return err
	}
	s.mappingsLock.Lock()
	defer s.mappingsLock.Unlock()
	if _, err := s.post(removeGlobalMappingURL, map[string]interface{}{attributeValue: groupName}, "remove identity federation global group mapping"); err != nil {
		return err
	}
	remaining, err := s.GetGlobalGroupMapping(&federationsmodels.IdsecIdentityGetFederationGlobalGroupMapping{AttributeValue: attributeValue, GroupName: groupName})
	if err == nil {
		return fmt.Errorf("identity federation global group mapping [%s -> %s] was removed but is still stored", remaining.AttributeValue, remaining.GroupName)
	}
	if errors.Is(err, common.ErrNotFound) {
		return nil
	}
	return err
}
