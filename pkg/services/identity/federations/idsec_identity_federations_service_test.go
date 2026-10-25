// Package federations provides the IDSEC Identity federations service, which manages SAML 2.0
// and OIDC identity provider federations and their global group mappings.
package federations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	svcactions "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/federations/actions"
	federationsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/federations/models"
)

func mockISPAuth() *auth.IdsecISPAuth {
	return &auth.IdsecISPAuth{
		IdsecAuthBase: &auth.IdsecAuthBase{
			Token: &authmodels.IdsecToken{
				Token:      "",
				TokenType:  authmodels.JWT,
				Username:   "mock-username@mock-domain.cyberark.cloud",
				Endpoint:   "https://mock-endpoint",
				AuthMethod: authmodels.Identity,
				Metadata: map[string]interface{}{
					"env": "dev",
				},
			},
		},
	}
}

func jsonResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

// fakeServer routes requests by path, counts them and records what the last one to each path
// sent. A path in sequences answers with its responses in order, then repeats the last one.
type fakeServer struct {
	responses map[string]string
	sequences map[string][]string
	calls     map[string]int
	jsonCalls map[string]interface{}
	formCalls map[string]map[string]string
	fileCalls map[string][]common.IdsecMultipartFile
}

func newFakeServer(responses map[string]string) *fakeServer {
	return &fakeServer{
		responses: responses,
		sequences: map[string][]string{},
		calls:     map[string]int{},
		jsonCalls: map[string]interface{}{},
		formCalls: map[string]map[string]string{},
		fileCalls: map[string][]common.IdsecMultipartFile{},
	}
}

func (f *fakeServer) respond(path string) (*http.Response, error) {
	f.calls[path]++
	if sequence := f.sequences[path]; len(sequence) > 0 {
		body := sequence[0]
		if len(sequence) > 1 {
			f.sequences[path] = sequence[1:]
		}
		return jsonResponse(http.StatusOK, body), nil
	}
	body, ok := f.responses[path]
	if !ok {
		return nil, errors.New("unexpected call to " + path)
	}
	return jsonResponse(http.StatusOK, body), nil
}

func newTestService(t *testing.T, server *fakeServer) *IdsecIdentityFederationsService {
	t.Helper()
	service, err := NewIdsecIdentityFederationsService(mockISPAuth())
	if err != nil {
		t.Fatalf("NewIdsecIdentityFederationsService() error = %v", err)
	}
	service.DoPost = func(_ context.Context, path string, body interface{}) (*http.Response, error) {
		server.jsonCalls[path] = body
		return server.respond(path)
	}
	service.DoFormPost = func(_ context.Context, path string, form map[string]string) (*http.Response, error) {
		server.formCalls[path] = form
		return server.respond(path)
	}
	service.DoMultipartPost = func(_ context.Context, path string, body *common.IdsecMultipartBody) (*http.Response, error) {
		server.formCalls[path] = body.Fields
		server.fileCalls[path] = body.Files
		return server.respond(path)
	}
	return service
}

const (
	oidcFederationJSON = `{
		"FederationUuid": "fed-1",
		"FederationName": "Okta",
		"FederationType": "OIDC",
		"Active": true,
		"Domains": ["example.com", "example.org"],
		"OIDCMetaDataUrl": "https://idp.example.com/.well-known/openid-configuration",
		"OIDCClientId": "client-1",
		"OIDCClientSecret": "plaintext-secret",
		"OIDCGrantType": "AuthorizationCode",
		"PKCEEnabled": "true",
		"OIDCScopes": ["openid", "email"],
		"OIDCAuthCodeUrl": "https://idp.example.com/authorize",
		"Usage": 2,
		"MapUsers": 1,
		"AttributeMappings": [{"Target": "DisplayName", "Source": "name"}],
		"PartnerManageable": true,
		"NormalizedFederationName": "OKTA",
		"Config": {
			"LogoutCallBackURI": "https://tenant.example.com/logout",
			"Thumbprint": "ABC",
			"SPSigningCertificateThumbprint": "DEF"
		},
		"Mappings": [{"AttributeValue": "admins", "GroupName": "Admins"}]
	}`
	globalSettingsJSON = `{"success": true, "Result": {
		"SPRedirectUrl": "https://tenant.example.com/OIDCFederation/CallBack",
		"SPInitiateLoginUrl": "https://tenant.example.com/OIDCFederation/Initiate"
	}}`
)

func TestCreateOIDCSendsFormWithDefaults(t *testing.T) {
	server := newFakeServer(map[string]string{
		createFederationURL:         `{"success": true, "Result": ` + oidcFederationJSON + `}`,
		globalFederationSettingsURL: globalSettingsJSON,
	})
	service := newTestService(t, server)
	secret := "s3cret"
	federation, err := service.Create(&federationsmodels.IdsecIdentityCreateFederation{
		FederationName:   "Okta",
		FederationType:   "OIDC",
		Active:           true,
		Domains:          []string{"example.com", "example.org"},
		OIDCMetadataURL:  "https://idp.example.com/.well-known/openid-configuration",
		OIDCClientID:     "client-1",
		OIDCClientSecret: &secret,
		OIDCScopes:       []string{"openid", "email"},
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	form := server.formCalls[createFederationURL]
	want := map[string]string{
		"FederationName":    "Okta",
		"FederationType":    "OIDC",
		"Active":            "true",
		"Domains":           "example.com,example.org",
		"Mappings":          "[]",
		"AttributeMappings": "[]",
		// User mapping defaults, as the portal sends them.
		"MapUsers":                "Disabled",
		"MapUserAttribute":        "UserPrincipalName",
		"MapUserBy":               "Name",
		"MapUserDirectoryService": "",
		"MapUserSyncWithFedUser":  "true",
		"OIDCMetaDataUrl":         "https://idp.example.com/.well-known/openid-configuration",
		"OIDCClientId":            "client-1",
		"OIDCClientSecret":        "s3cret",
		"OIDCGrantType":           "AuthorizationCode",
		"PKCEEnabled":             "true",
		"OIDCScopes":              "openid,email",
		"LogoutCallBackURI":       "",
	}
	if !reflect.DeepEqual(form, want) {
		t.Errorf("Create() form = %v, want %v", form, want)
	}
	if _, sent := form["Usage"]; sent {
		t.Error("Create() must not send Usage")
	}
	if federation.SPRedirectURL != "https://tenant.example.com/OIDCFederation/CallBack" {
		t.Errorf("SPRedirectUrl = %q", federation.SPRedirectURL)
	}
	if got := server.formCalls[globalFederationSettingsURL]; got["FederationType"] != "OIDC" || got["FederationUuid"] != "fed-1" {
		t.Errorf("global settings form = %v", got)
	}
}

const (
	samlFederationJSON = `{
		"FederationUuid": "fed-2",
		"FederationName": "ADFS",
		"FederationType": "SAML 2.0",
		"Active": true,
		"Domains": ["example.com"],
		"SAMLSignAlgorithm": "SHA256",
		"SPMetadataUrl": "https://tenant.example.com/Federation/federationmetadata?FederationType=SAML%202.0",
		"OAuthClientSecret": "***************",
		"Config": {
			"IDPMetadataUrl": "https://adfs.example.com/metadata.xml",
			"IDPSignInUrl": "https://adfs.example.com/sso",
			"IDPLogoutUrl": "https://adfs.example.com/slo",
			"IDPSigningCertificateThumbprint": "AB12",
			"IDPSigningCertificateSubject": "CN=adfs",
			"IDPSigningCertificateExpires": "2030-01-01",
			"IDPSigningCertificateCollection": [{"IDPSigningCertificateThumbprint": "AB12"}],
			"SPSigningCertificateThumbprint": "DEF"
		},
		"Mappings": []
	}`
	samlGlobalSettingsJSON = `{"success": true, "Result": {
		"SPAutnenticationResponseUrl": "https://tenant.example.com/my",
		"SPSigningCertificateUrl": "https://tenant.example.com/Federation/SPSigningCertificate"
	}}`
)

func samlServer(federation string) *fakeServer {
	return newFakeServer(map[string]string{
		createFederationURL:         `{"success": true, "Result": ` + federation + `}`,
		readFederationURL:           `{"success": true, "Result": ` + federation + `}`,
		updateFederationURL:         `{"success": true, "Result": ` + federation + `}`,
		globalFederationSettingsURL: samlGlobalSettingsJSON,
	})
}

func TestCreateSAMLFromMetadataURL(t *testing.T) {
	server := samlServer(samlFederationJSON)
	service := newTestService(t, server)
	federation, err := service.Create(&federationsmodels.IdsecIdentityCreateFederation{
		FederationName:  "ADFS",
		FederationType:  "SAML 2.0",
		Active:          true,
		SAMLMetadataURL: "https://adfs.example.com/metadata.xml",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	form := server.formCalls[createFederationURL]
	for key, want := range map[string]string{
		"IsMetaData":        "true",
		"MetaDataIsUrl":     "true",
		"IDPMetadataUrl":    "https://adfs.example.com/metadata.xml",
		"SAMLSignAlgorithm": "SHA256",
	} {
		if form[key] != want {
			t.Errorf("Create() %s = %q, want %q", key, form[key], want)
		}
	}
	for _, key := range []string{"OIDCGrantType", "PKCEEnabled", "OIDCClientId", "IDPSignInUrl"} {
		if _, sent := form[key]; sent {
			t.Errorf("Create() sent %s for a SAML metadata URL federation", key)
		}
	}
	if _, multipart := server.fileCalls[createFederationURL]; multipart {
		t.Error("Create() sent a metadata URL federation as multipart")
	}
	if got := server.formCalls[globalFederationSettingsURL]; !reflect.DeepEqual(got, map[string]string{"FederationType": "SAML 2.0"}) {
		t.Errorf("global settings form = %v", got)
	}
	want := &federationsmodels.IdsecIdentityFederation{
		FederationUUID:              "fed-2",
		FederationName:              "ADFS",
		FederationType:              "SAML 2.0",
		Active:                      true,
		Domains:                     []string{"example.com"},
		OIDCScopes:                  []string{},
		MapUsers:                    "Disabled",
		MapUserAttribute:            "UserPrincipalName",
		MapUserBy:                   "Name",
		MapUserSyncWithFedUser:      true,
		GroupMappings:               []federationsmodels.IdsecIdentityFederationGroupMapping{},
		AttributeMappings:           []federationsmodels.IdsecIdentityFederationAttributeMapping{},
		DeviceTypes:                 []string{},
		UserAgents:                  []string{"Any"},
		SAMLMetadataURL:             "https://adfs.example.com/metadata.xml",
		SAMLSignInURL:               "https://adfs.example.com/sso",
		SAMLLogoutURL:               "https://adfs.example.com/slo",
		SAMLSignAlgorithm:           "SHA256",
		SAMLCertificateThumbprint:   "AB12",
		SAMLCertificateSubject:      "CN=adfs",
		SAMLCertificateExpires:      "2030-01-01",
		SAMLSPMetadataURL:           "https://tenant.example.com/Federation/federationmetadata?FederationType=SAML%202.0",
		SAMLSPACSURL:                "https://tenant.example.com/my",
		SAMLSPSigningCertificateURL: "https://tenant.example.com/Federation/SPSigningCertificate",
	}
	if !reflect.DeepEqual(federation, want) {
		t.Errorf("Create() = %+v, want %+v", federation, want)
	}
}

func TestCreateSAMLUploadsMetadataDocument(t *testing.T) {
	server := samlServer(samlFederationJSON)
	service := newTestService(t, server)
	metadata := "<EntityDescriptor/>"
	_, err := service.Create(&federationsmodels.IdsecIdentityCreateFederation{
		FederationName:  "ADFS",
		FederationType:  "SAML 2.0",
		SAMLMetadataXML: &metadata,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	form := server.formCalls[createFederationURL]
	if form["IsMetaData"] != "true" || form["MetaDataIsUrl"] != "false" {
		t.Errorf("Create() mode = %q/%q, want true/false", form["IsMetaData"], form["MetaDataIsUrl"])
	}
	files := server.fileCalls[createFederationURL]
	if len(files) != 1 || files[0].FieldName != "IDPMetadataFileContents" || string(files[0].Content) != metadata {
		t.Errorf("Create() files = %+v", files)
	}
}

func TestCreateSAMLManualUploadsCertificate(t *testing.T) {
	server := samlServer(samlFederationJSON)
	service := newTestService(t, server)
	certificate := "-----BEGIN CERTIFICATE-----"
	_, err := service.Create(&federationsmodels.IdsecIdentityCreateFederation{
		FederationName:         "ADFS",
		FederationType:         "SAML 2.0",
		SAMLSignInURL:          "https://idp.example.com/sso",
		SAMLSigningCertificate: &certificate,
		SAMLSignAlgorithm:      "SHA1",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	form := server.formCalls[createFederationURL]
	if _, sent := form["IsMetaData"]; sent {
		t.Error("Create() sent IsMetaData for a manual federation")
	}
	if form["IDPSignInUrl"] != "https://idp.example.com/sso" || form["IDPLogoutUrl"] != "" || form["SAMLSignAlgorithm"] != "SHA1" {
		t.Errorf("Create() form = %v", form)
	}
	files := server.fileCalls[createFederationURL]
	if len(files) != 1 || files[0].FieldName != "IDPSigningCert" || string(files[0].Content) != certificate {
		t.Errorf("Create() files = %+v", files)
	}
}

func TestCreateRejectsInvalidInput(t *testing.T) {
	certificate := "-----BEGIN CERTIFICATE-----"
	tests := []struct {
		name string
		arg  *federationsmodels.IdsecIdentityCreateFederation
	}{
		{
			name: "social federation type",
			arg:  &federationsmodels.IdsecIdentityCreateFederation{FederationName: "G", FederationType: "Google"},
		},
		{
			name: "SAML without an inbound mode",
			arg:  &federationsmodels.IdsecIdentityCreateFederation{FederationName: "ADFS", FederationType: "SAML 2.0"},
		},
		{
			name: "manual SAML without a signing certificate",
			arg:  &federationsmodels.IdsecIdentityCreateFederation{FederationName: "ADFS", FederationType: "SAML 2.0", SAMLSignInURL: "https://idp.example.com/sso"},
		},
		{
			name: "manual SAML without a sign-in URL",
			arg:  &federationsmodels.IdsecIdentityCreateFederation{FederationName: "ADFS", FederationType: "SAML 2.0", SAMLSigningCertificate: &certificate},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newFakeServer(map[string]string{})
			service := newTestService(t, server)
			if _, err := service.Create(tt.arg); err == nil {
				t.Fatal("Create() error = nil, want an error")
			}
			if server.calls[createFederationURL] != 0 {
				t.Error("Create() posted an invalid federation")
			}
		})
	}
}

func TestCreateKeepsFederationWhenServiceProviderURLsFail(t *testing.T) {
	// No response for the global settings: reading them fails after the create succeeded.
	server := newFakeServer(map[string]string{
		createFederationURL: `{"success": true, "Result": ` + oidcFederationJSON + `}`,
	})
	service := newTestService(t, server)
	federation, err := service.Create(&federationsmodels.IdsecIdentityCreateFederation{FederationName: "Okta", FederationType: "OIDC"})
	if err != nil {
		t.Fatalf("Create() error = %v, want the created federation", err)
	}
	if federation.FederationUUID != "fed-1" || federation.SPRedirectURL != "" {
		t.Errorf("Create() = %+v, want fed-1 without service provider URLs", federation)
	}

	// A read still fails: nothing was written, so the caller can retry.
	server.responses[readFederationURL] = `{"success": true, "Result": ` + oidcFederationJSON + `}`
	if _, err := service.Get(&federationsmodels.IdsecIdentityGetFederation{FederationUUID: "fed-1"}); err == nil {
		t.Error("Get() error = nil, want the global settings failure")
	}
}

func TestUpdateKeepsFederationWhenServiceProviderURLsFail(t *testing.T) {
	server := newFakeServer(map[string]string{
		readFederationURL:   `{"success": true, "Result": ` + oidcFederationJSON + `}`,
		updateFederationURL: `{"success": true, "Result": ` + oidcFederationJSON + `}`,
	})
	service := newTestService(t, server)
	federation, err := service.Update(&federationsmodels.IdsecIdentityUpdateFederation{FederationUUID: "fed-1", FederationName: "Okta", Active: true})
	if err != nil {
		t.Fatalf("Update() error = %v, want the updated federation", err)
	}
	if federation.FederationUUID != "fed-1" {
		t.Errorf("Update() = %+v", federation)
	}
}

func TestSAMLServiceProviderSettingsAreCached(t *testing.T) {
	server := samlServer(samlFederationJSON)
	// The first read fails and must not be cached.
	server.sequences[globalFederationSettingsURL] = []string{`{"success": false, "Message": "busy"}`, samlGlobalSettingsJSON}
	service := newTestService(t, server)
	get := &federationsmodels.IdsecIdentityGetFederation{FederationUUID: "fed-2"}
	if _, err := service.Get(get); err == nil {
		t.Fatal("Get() error = nil, want the global settings failure")
	}
	for i := 0; i < 2; i++ {
		federation, err := service.Get(get)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if federation.SAMLSPACSURL != "https://tenant.example.com/my" {
			t.Errorf("Get() SAMLSPACSURL = %q", federation.SAMLSPACSURL)
		}
	}
	if got := server.calls[globalFederationSettingsURL]; got != 2 {
		t.Errorf("global settings read %d times, want 2: the failure, then once for both reads", got)
	}
}

func TestSAMLServiceProviderSettingsExpire(t *testing.T) {
	server := samlServer(samlFederationJSON)
	service := newTestService(t, server)
	get := &federationsmodels.IdsecIdentityGetFederation{FederationUUID: "fed-2"}
	if _, err := service.Get(get); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	service.samlSettingsRead = time.Now().Add(-samlSettingsTTL)
	if _, err := service.Get(get); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got := server.calls[globalFederationSettingsURL]; got != 2 {
		t.Errorf("global settings read %d times, want 2: the cached settings had expired", got)
	}
}

func TestOIDCServiceProviderSettingsAreNotCached(t *testing.T) {
	server := newFakeServer(map[string]string{
		readFederationURL:           `{"success": true, "Result": ` + oidcFederationJSON + `}`,
		globalFederationSettingsURL: globalSettingsJSON,
	})
	service := newTestService(t, server)
	for i := 0; i < 2; i++ {
		if _, err := service.Get(&federationsmodels.IdsecIdentityGetFederation{FederationUUID: "fed-1"}); err != nil {
			t.Fatalf("Get() error = %v", err)
		}
	}
	if got := server.calls[globalFederationSettingsURL]; got != 2 {
		t.Errorf("global settings read %d times, want 2: the OIDC URLs depend on the federation", got)
	}
}

func TestUpdateSAMLRefetchesStoredMetadataURL(t *testing.T) {
	server := samlServer(samlFederationJSON)
	service := newTestService(t, server)
	// The provider plan carries the stored sign-in URL, which the metadata mode must not override.
	_, err := service.Update(&federationsmodels.IdsecIdentityUpdateFederation{
		FederationUUID:  "fed-2",
		FederationName:  "ADFS renamed",
		Active:          true,
		SAMLMetadataURL: "https://adfs.example.com/metadata.xml",
		SAMLSignInURL:   "https://adfs.example.com/sso",
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	form := server.formCalls[updateFederationURL]
	if form["IsMetaData"] != "true" || form["MetaDataIsUrl"] != "true" || form["IDPMetadataUrl"] != "https://adfs.example.com/metadata.xml" {
		t.Errorf("Update() mode = %v", form)
	}
	for _, key := range []string{"IDPSignInUrl", "IDPSigningCertificateThumbprint", "IDPSigningCertificateCollection", "OAuthClientSecret", "SPSigningCertificateThumbprint"} {
		if _, sent := form[key]; sent {
			t.Errorf("Update() echoed %s", key)
		}
	}
	if form["SAMLSignAlgorithm"] != "SHA256" {
		t.Errorf("Update() SAMLSignAlgorithm = %q, want the echoed SHA256", form["SAMLSignAlgorithm"])
	}
	if _, multipart := server.fileCalls[updateFederationURL]; multipart {
		t.Error("Update() sent a metadata URL federation as multipart")
	}

	// With nothing set, the stored metadata URL is fetched again.
	if _, err := service.Update(&federationsmodels.IdsecIdentityUpdateFederation{FederationUUID: "fed-2", FederationName: "ADFS", Active: true}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if got := server.formCalls[updateFederationURL]["IDPMetadataUrl"]; got != "https://adfs.example.com/metadata.xml" {
		t.Errorf("Update() IDPMetadataUrl = %q, want the stored URL", got)
	}
}

func TestUpdateSAMLWithoutMetadataKeepsCertificate(t *testing.T) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(samlFederationJSON), &raw); err != nil {
		t.Fatal(err)
	}
	delete(raw["Config"].(map[string]interface{}), "IDPMetadataUrl")
	encoded, _ := json.Marshal(raw)
	server := samlServer(string(encoded))
	service := newTestService(t, server)
	_, err := service.Update(&federationsmodels.IdsecIdentityUpdateFederation{
		FederationUUID: "fed-2",
		FederationName: "ADFS",
		Active:         true,
		SAMLLogoutURL:  "https://adfs.example.com/slo2",
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	form := server.formCalls[updateFederationURL]
	for key, want := range map[string]string{
		"IDPSignInUrl":                    "https://adfs.example.com/sso",
		"IDPLogoutUrl":                    "https://adfs.example.com/slo2",
		"IDPSigningCertificateThumbprint": "AB12",
	} {
		if form[key] != want {
			t.Errorf("Update() %s = %q, want %q", key, form[key], want)
		}
	}
	if _, sent := form["IsMetaData"]; sent {
		t.Error("Update() sent IsMetaData for a manual federation")
	}
	files := server.fileCalls[updateFederationURL]
	if len(files) != 1 || files[0].FieldName != "IDPSigningCert" || len(files[0].Content) != 0 {
		t.Errorf("Update() files = %+v, want one empty certificate part", files)
	}
}

func TestGetParsesFederationWithoutSecret(t *testing.T) {
	server := newFakeServer(map[string]string{
		readFederationURL:           `{"success": true, "Result": ` + oidcFederationJSON + `}`,
		globalFederationSettingsURL: globalSettingsJSON,
	})
	service := newTestService(t, server)
	federation, err := service.Get(&federationsmodels.IdsecIdentityGetFederation{FederationUUID: "fed-1"})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	want := &federationsmodels.IdsecIdentityFederation{
		FederationUUID:     "fed-1",
		FederationName:     "Okta",
		FederationType:     "OIDC",
		Active:             true,
		Domains:            []string{"example.com", "example.org"},
		OIDCMetadataURL:    "https://idp.example.com/.well-known/openid-configuration",
		OIDCClientID:       "client-1",
		OIDCGrantType:      "AuthorizationCode",
		PKCEEnabled:        true,
		OIDCScopes:         []string{"openid", "email"},
		LogoutCallBackURI:  "https://tenant.example.com/logout",
		SPRedirectURL:      "https://tenant.example.com/OIDCFederation/CallBack",
		SPInitiateLoginURL: "https://tenant.example.com/OIDCFederation/Initiate",
		// MapUsers was stored as a number; absent columns read as the sign-in defaults.
		MapUsers:               "Optional",
		MapUserAttribute:       "UserPrincipalName",
		MapUserBy:              "Name",
		MapUserSyncWithFedUser: true,
		GroupMappings:          []federationsmodels.IdsecIdentityFederationGroupMapping{{AttributeValue: "admins", GroupName: "Admins"}},
		AttributeMappings:      []federationsmodels.IdsecIdentityFederationAttributeMapping{{Target: "DisplayName", Source: "name"}},
		DeviceTypes:            []string{},
		UserAgents:             []string{"Any"},
	}
	if !reflect.DeepEqual(federation, want) {
		t.Errorf("Get() = %+v, want %+v", federation, want)
	}
	if body := server.jsonCalls[readFederationURL]; !reflect.DeepEqual(body, map[string]interface{}{"FederationUuid": "fed-1"}) {
		t.Errorf("Get() body = %v", body)
	}
}

func TestGetFailures(t *testing.T) {
	listed := `{"success": true, "Result": [{"FederationUuid": "fed-1", "FederationType": "OIDC"}]}`
	tests := []struct {
		name         string
		id           string
		read         string
		wantNotFound bool
	}{
		{
			name:         "missing federation",
			id:           "fed-9",
			read:         `{"success": false, "Message": "Federation fed-9 does not exist"}`,
			wantNotFound: true,
		},
		{
			name: "other failure of an existing federation",
			id:   "fed-1",
			read: `{"success": false, "Message": "Access denied"}`,
		},
		{
			name: "shadow federation",
			id:   "fed-3",
			read: `{"success": true, "Result": {"FederationUuid": "fed-3", "FederationType": "SAML 2.0 Shadow"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := newTestService(t, newFakeServer(map[string]string{readFederationURL: tt.read, listFederationURL: listed}))
			_, err := service.Get(&federationsmodels.IdsecIdentityGetFederation{FederationUUID: tt.id})
			if err == nil {
				t.Fatal("Get() error = nil, want an error")
			}
			if got := errors.Is(err, common.ErrNotFound); got != tt.wantNotFound {
				t.Errorf("Get() error = %v, ErrNotFound = %t, want %t", err, got, tt.wantNotFound)
			}
		})
	}
}

func TestUpdateEchoesUnmanagedFields(t *testing.T) {
	server := newFakeServer(map[string]string{
		readFederationURL:           `{"success": true, "Result": ` + oidcFederationJSON + `}`,
		updateFederationURL:         `{"success": true, "Result": ` + oidcFederationJSON + `}`,
		globalFederationSettingsURL: globalSettingsJSON,
	})
	service := newTestService(t, server)
	pkce := false
	_, err := service.Update(&federationsmodels.IdsecIdentityUpdateFederation{
		FederationUUID:    "fed-1",
		FederationName:    "Okta renamed",
		FederationType:    "OIDC",
		Active:            false,
		Domains:           &[]string{"example.com"},
		OIDCMetadataURL:   "https://idp.example.com/.well-known/openid-configuration",
		OIDCClientID:      "client-1",
		OIDCGrantType:     "AuthorizationCode",
		PKCEEnabled:       &pkce,
		OIDCScopes:        &[]string{"openid"},
		LogoutCallBackURI: "https://tenant.example.com/logout2",
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	form := server.formCalls[updateFederationURL]
	want := map[string]string{
		// Managed fields, from the request.
		"FederationUuid":    "fed-1",
		"FederationName":    "Okta renamed",
		"FederationType":    "OIDC",
		"Active":            "false",
		"Domains":           "example.com",
		"OIDCMetaDataUrl":   "https://idp.example.com/.well-known/openid-configuration",
		"OIDCClientId":      "client-1",
		"OIDCGrantType":     "AuthorizationCode",
		"PKCEEnabled":       "false",
		"OIDCScopes":        "openid",
		"LogoutCallBackURI": "https://tenant.example.com/logout2",
		// Unmanaged fields, echoed from the read.
		"Usage":             "2",
		"MapUsers":          "1",
		"AttributeMappings": `[{"Source":"name","Target":"DisplayName"}]`,
		"Thumbprint":        "ABC",
		"Mappings":          `[{"AttributeValue":"admins","GroupName":"Admins"}]`,
	}
	if !reflect.DeepEqual(form, want) {
		got, _ := json.MarshalIndent(form, "", "  ")
		t.Errorf("Update() form = %s", got)
	}
}

func TestUpdateKeepsUnsetFields(t *testing.T) {
	server := newFakeServer(map[string]string{
		readFederationURL:           `{"success": true, "Result": ` + oidcFederationJSON + `}`,
		updateFederationURL:         `{"success": true, "Result": ` + oidcFederationJSON + `}`,
		globalFederationSettingsURL: globalSettingsJSON,
	})
	service := newTestService(t, server)
	_, err := service.Update(&federationsmodels.IdsecIdentityUpdateFederation{
		FederationUUID: "fed-1",
		FederationName: "Okta",
		FederationType: "OIDC",
		Active:         true,
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	form := server.formCalls[updateFederationURL]
	for key, want := range map[string]string{
		"Domains":           "example.com,example.org",
		"OIDCScopes":        "openid,email",
		"PKCEEnabled":       "true",
		"LogoutCallBackURI": "https://tenant.example.com/logout",
		"MapUsers":          "1",
		"Mappings":          `[{"AttributeValue":"admins","GroupName":"Admins"}]`,
	} {
		if form[key] != want {
			t.Errorf("Update() %s = %q, want %q", key, form[key], want)
		}
	}
	if _, sent := form["OIDCClientSecret"]; sent {
		t.Error("Update() sent a secret it was not given")
	}
}

func TestUpdateRotatesOIDCSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret *string
		want   string
		sent   bool
	}{
		{name: "new secret", secret: stringPointer("rotated"), want: "rotated", sent: true},
		{name: "empty secret keeps the stored one", secret: stringPointer("")},
		{name: "no secret keeps the stored one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newFakeServer(map[string]string{
				readFederationURL:           `{"success": true, "Result": ` + oidcFederationJSON + `}`,
				updateFederationURL:         `{"success": true, "Result": ` + oidcFederationJSON + `}`,
				globalFederationSettingsURL: globalSettingsJSON,
			})
			service := newTestService(t, server)
			_, err := service.Update(&federationsmodels.IdsecIdentityUpdateFederation{FederationUUID: "fed-1", FederationName: "Okta", Active: true, OIDCClientSecret: tt.secret})
			if err != nil {
				t.Fatalf("Update() error = %v", err)
			}
			got, sent := server.formCalls[updateFederationURL]["OIDCClientSecret"]
			if sent != tt.sent || got != tt.want {
				t.Errorf("Update() OIDCClientSecret = %q (sent %t), want %q (sent %t)", got, sent, tt.want, tt.sent)
			}
		})
	}
}

func stringPointer(value string) *string {
	return &value
}

// samlOAuthFederationJSON is a SAML federation with OAuth credentials stored. The read masks the
// secret.
var samlOAuthFederationJSON = strings.Replace(samlFederationJSON, `"OAuthClientSecret": "***************",`,
	`"OAuthClientSecret": "***************", "OAuthClientId": "oauth-client", "OAuthAccessTokenUrl": "https://adfs.example.com/token",`, 1)

func TestSAMLOAuthCredentials(t *testing.T) {
	server := samlServer(samlOAuthFederationJSON)
	service := newTestService(t, server)
	federation, err := service.Create(&federationsmodels.IdsecIdentityCreateFederation{
		FederationName:          "ADFS",
		FederationType:          "SAML 2.0",
		SAMLMetadataURL:         "https://adfs.example.com/metadata.xml",
		SAMLOAuthClientID:       "oauth-client",
		SAMLOAuthClientSecret:   stringPointer("oauth-secret"),
		SAMLOAuthAccessTokenURL: "https://adfs.example.com/token",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	created := server.formCalls[createFederationURL]
	for key, want := range map[string]string{"OAuthClientId": "oauth-client", "OAuthClientSecret": "oauth-secret", "OAuthAccessTokenUrl": "https://adfs.example.com/token"} {
		if created[key] != want {
			t.Errorf("Create() %s = %q, want %q", key, created[key], want)
		}
	}
	if federation.SAMLOAuthClientID != "oauth-client" || federation.SAMLOAuthAccessTokenURL != "https://adfs.example.com/token" {
		t.Errorf("Create() read OAuth client ID %q and token URL %q", federation.SAMLOAuthClientID, federation.SAMLOAuthAccessTokenURL)
	}

	// An update that sets none of them echoes the stored client ID and token URL, and sends no
	// secret, so the server keeps the stored one rather than storing the read's mask.
	if _, err := service.Update(&federationsmodels.IdsecIdentityUpdateFederation{FederationUUID: "fed-2", FederationName: "ADFS", Active: true}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	kept := server.formCalls[updateFederationURL]
	if kept["OAuthClientId"] != "oauth-client" || kept["OAuthAccessTokenUrl"] != "https://adfs.example.com/token" {
		t.Errorf("Update() did not echo the stored OAuth client ID and token URL: %v", kept)
	}
	if _, sent := kept["OAuthClientSecret"]; sent {
		t.Error("Update() sent OAuthClientSecret without a new secret")
	}

	// Set values replace the echoed ones.
	if _, err := service.Update(&federationsmodels.IdsecIdentityUpdateFederation{
		FederationUUID: "fed-2", FederationName: "ADFS", Active: true,
		SAMLOAuthClientID: "rotated-client", SAMLOAuthClientSecret: stringPointer("rotated-secret"), SAMLOAuthAccessTokenURL: "https://adfs.example.com/token2",
	}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	changed := server.formCalls[updateFederationURL]
	for key, want := range map[string]string{"OAuthClientId": "rotated-client", "OAuthClientSecret": "rotated-secret", "OAuthAccessTokenUrl": "https://adfs.example.com/token2"} {
		if changed[key] != want {
			t.Errorf("Update() %s = %q, want %q", key, changed[key], want)
		}
	}
}

func TestParseMappingFieldsMapUsers(t *testing.T) {
	tests := []struct {
		name   string
		stored interface{}
		want   string
	}{
		{name: "absent", stored: nil, want: "Disabled"},
		{name: "number", stored: float64(2), want: "Required"},
		{name: "number out of range", stored: float64(7), want: "Disabled"},
		{name: "negative number", stored: float64(-1), want: "Disabled"},
		{name: "numeric string", stored: "1", want: "Optional"},
		{name: "numeric string out of range", stored: "7", want: "7"},
		{name: "name", stored: "Required", want: "Required"},
		{name: "empty string", stored: "", want: "Disabled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := map[string]interface{}{}
			if tt.stored != nil {
				raw["MapUsers"] = tt.stored
			}
			federation := &federationsmodels.IdsecIdentityFederation{}
			parseMappingFields(raw, federation)
			if federation.MapUsers != tt.want {
				t.Errorf("MapUsers = %q, want %q", federation.MapUsers, tt.want)
			}
		})
	}
}

func TestUpdateSendsMappingFields(t *testing.T) {
	server := newFakeServer(map[string]string{
		readFederationURL:           `{"success": true, "Result": ` + oidcFederationJSON + `}`,
		updateFederationURL:         `{"success": true, "Result": ` + oidcFederationJSON + `}`,
		globalFederationSettingsURL: globalSettingsJSON,
	})
	service := newTestService(t, server)
	create := true
	_, err := service.Update(&federationsmodels.IdsecIdentityUpdateFederation{
		FederationUUID:          "fed-1",
		FederationName:          "Okta",
		FederationType:          "OIDC",
		Active:                  true,
		MapUsers:                "Required",
		MapUserDirectoryService: "09B9A9B0-6CE8-465F-AB03-65766D33B05E",
		MapUserCreateIfNotFound: &create,
		GroupMappings:           &[]federationsmodels.IdsecIdentityFederationGroupMapping{},
		AttributeMappings:       &[]federationsmodels.IdsecIdentityFederationAttributeMapping{{Target: "Mail", Source: "email"}},
		DeviceTypes:             &[]string{"iOS", "Android"},
		UserAgents:              &[]string{"Browser"},
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	form := server.formCalls[updateFederationURL]
	for key, want := range map[string]string{
		"MapUsers":                "Required",
		"MapUserDirectoryService": "09B9A9B0-6CE8-465F-AB03-65766D33B05E",
		"MapUserCreateIfNotFound": "true",
		"Mappings":                "[]",
		"AttributeMappings":       `[{"Source":"email","Target":"Mail"}]`,
		"DeviceTypes":             "iOS,Android",
		"UserAgents":              "Browser",
	} {
		if form[key] != want {
			t.Errorf("Update() %s = %q, want %q", key, form[key], want)
		}
	}
}

const storedGlobalMappingsJSON = `{"success": true, "Result": {"Mappings": [{"AttributeValue": "Admins", "GroupName": "Cloud Admins"}]}}`

func TestGlobalGroupMappings(t *testing.T) {
	server := newFakeServer(map[string]string{
		addGlobalMappingURL:    `{"success": true, "Result": null}`,
		removeGlobalMappingURL: `{"success": true, "Result": null}`,
	})
	// The mapping does not exist before the add, and is gone after the remove.
	emptyMappingsJSON := `{"success": true, "Result": {"Mappings": []}}`
	server.sequences[listGlobalMappingsURL] = []string{emptyMappingsJSON, storedGlobalMappingsJSON, storedGlobalMappingsJSON, emptyMappingsJSON}
	service := newTestService(t, server)
	mapping, err := service.AddGlobalGroupMapping(&federationsmodels.IdsecIdentityAddFederationGlobalGroupMapping{AttributeValue: " admins ", GroupName: "cloud admins"})
	if err != nil {
		t.Fatalf("AddGlobalGroupMapping() error = %v", err)
	}
	if body := server.jsonCalls[addGlobalMappingURL]; !reflect.DeepEqual(body, map[string]interface{}{"admins": "cloud admins"}) {
		t.Errorf("AddGlobalGroupMapping() body = %v", body)
	}
	if mapping.AttributeValue != "Admins" || mapping.GroupName != "Cloud Admins" {
		t.Errorf("AddGlobalGroupMapping() = %+v, want the stored spelling", mapping)
	}
	_, err = service.GetGlobalGroupMapping(&federationsmodels.IdsecIdentityGetFederationGlobalGroupMapping{AttributeValue: "Admins", GroupName: "Other"})
	if !errors.Is(err, common.ErrNotFound) {
		t.Errorf("GetGlobalGroupMapping() error = %v, want ErrNotFound", err)
	}
	if err := service.RemoveGlobalGroupMapping(&federationsmodels.IdsecIdentityRemoveFederationGlobalGroupMapping{AttributeValue: " Admins ", GroupName: "Cloud Admins"}); err != nil {
		t.Errorf("RemoveGlobalGroupMapping() error = %v", err)
	}
	if body := server.jsonCalls[removeGlobalMappingURL]; !reflect.DeepEqual(body, map[string]interface{}{"Admins": "Cloud Admins"}) {
		t.Errorf("RemoveGlobalGroupMapping() body = %v", body)
	}
}

func TestAddGlobalGroupMappingRejectsExistingMapping(t *testing.T) {
	server := newFakeServer(map[string]string{listGlobalMappingsURL: storedGlobalMappingsJSON})
	service := newTestService(t, server)
	_, err := service.AddGlobalGroupMapping(&federationsmodels.IdsecIdentityAddFederationGlobalGroupMapping{AttributeValue: "admins", GroupName: "cloud admins"})
	if err == nil || !strings.Contains(err.Error(), "[Admins -> Cloud Admins] already exists") {
		t.Errorf("AddGlobalGroupMapping() error = %v, want already exists", err)
	}
	if server.calls[addGlobalMappingURL] != 0 {
		t.Error("AddGlobalGroupMapping() posted a mapping that already exists")
	}
}

func TestAddGlobalGroupMappingNotStored(t *testing.T) {
	server := newFakeServer(map[string]string{
		addGlobalMappingURL:   `{"success": true, "Result": null}`,
		listGlobalMappingsURL: `{"success": true, "Result": {"Mappings": []}}`,
	})
	service := newTestService(t, server)
	_, err := service.AddGlobalGroupMapping(&federationsmodels.IdsecIdentityAddFederationGlobalGroupMapping{AttributeValue: "admins", GroupName: "Admins"})
	want := "identity federation global group mapping [admins -> Admins] was added but not stored: resource not found"
	if !errors.Is(err, common.ErrNotFound) || err.Error() != want {
		t.Errorf("AddGlobalGroupMapping() error = %v, want %q", err, want)
	}
}

func TestAddGlobalGroupMappingPostFailure(t *testing.T) {
	server := newFakeServer(map[string]string{
		addGlobalMappingURL:   `{"success": false, "Message": "Access denied"}`,
		listGlobalMappingsURL: `{"success": true, "Result": {"Mappings": []}}`,
	})
	service := newTestService(t, server)
	if _, err := service.AddGlobalGroupMapping(&federationsmodels.IdsecIdentityAddFederationGlobalGroupMapping{AttributeValue: "admins", GroupName: "Admins"}); err == nil {
		t.Error("AddGlobalGroupMapping() error = nil, want the post failure")
	}
	if server.calls[listGlobalMappingsURL] != 1 {
		t.Errorf("list called %d times, want only the existence check", server.calls[listGlobalMappingsURL])
	}
}

func TestAddGlobalGroupMappingListFailure(t *testing.T) {
	server := newFakeServer(map[string]string{listGlobalMappingsURL: `{"success": false, "Message": "Access denied"}`})
	service := newTestService(t, server)
	_, err := service.AddGlobalGroupMapping(&federationsmodels.IdsecIdentityAddFederationGlobalGroupMapping{AttributeValue: "admins", GroupName: "Admins"})
	if err == nil || errors.Is(err, common.ErrNotFound) {
		t.Errorf("AddGlobalGroupMapping() error = %v, want the list failure", err)
	}
	if server.calls[addGlobalMappingURL] != 0 {
		t.Error("AddGlobalGroupMapping() posted without knowing whether the mapping exists")
	}
}

func TestRemoveGlobalGroupMappingStillStored(t *testing.T) {
	server := newFakeServer(map[string]string{
		removeGlobalMappingURL: `{"success": true, "Result": null}`,
		listGlobalMappingsURL:  storedGlobalMappingsJSON,
	})
	service := newTestService(t, server)
	err := service.RemoveGlobalGroupMapping(&federationsmodels.IdsecIdentityRemoveFederationGlobalGroupMapping{AttributeValue: "admins", GroupName: "cloud admins"})
	want := "identity federation global group mapping [Admins -> Cloud Admins] was removed but is still stored"
	if err == nil || err.Error() != want {
		t.Errorf("RemoveGlobalGroupMapping() error = %v, want %q", err, want)
	}
}

func TestRemoveGlobalGroupMappingFailures(t *testing.T) {
	tests := []struct {
		name      string
		responses map[string]string
		wantLists int
	}{
		{"post", map[string]string{removeGlobalMappingURL: `{"success": false, "Message": "Access denied"}`}, 0},
		{"read back", map[string]string{
			removeGlobalMappingURL: `{"success": true, "Result": null}`,
			listGlobalMappingsURL:  `{"success": false, "Message": "Access denied"}`,
		}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newFakeServer(tt.responses)
			service := newTestService(t, server)
			err := service.RemoveGlobalGroupMapping(&federationsmodels.IdsecIdentityRemoveFederationGlobalGroupMapping{AttributeValue: "admins", GroupName: "Admins"})
			if err == nil || errors.Is(err, common.ErrNotFound) {
				t.Errorf("RemoveGlobalGroupMapping() error = %v, want the %s failure", err, tt.name)
			}
			if server.calls[listGlobalMappingsURL] != tt.wantLists {
				t.Errorf("list called %d times, want %d", server.calls[listGlobalMappingsURL], tt.wantLists)
			}
		})
	}
}

func TestGlobalGroupMappingsRejectBlankValues(t *testing.T) {
	tests := []struct {
		name           string
		attributeValue string
		groupName      string
	}{
		{name: "blank attribute value", attributeValue: " ", groupName: "Admins"},
		{name: "blank group name", attributeValue: "admins", groupName: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newFakeServer(map[string]string{})
			service := newTestService(t, server)
			if _, err := service.AddGlobalGroupMapping(&federationsmodels.IdsecIdentityAddFederationGlobalGroupMapping{AttributeValue: tt.attributeValue, GroupName: tt.groupName}); err == nil {
				t.Error("AddGlobalGroupMapping() error = nil, want an error")
			}
			if err := service.RemoveGlobalGroupMapping(&federationsmodels.IdsecIdentityRemoveFederationGlobalGroupMapping{AttributeValue: tt.attributeValue, GroupName: tt.groupName}); err == nil {
				t.Error("RemoveGlobalGroupMapping() error = nil, want an error")
			}
			if len(server.calls) != 0 {
				t.Errorf("calls = %v, want none", server.calls)
			}
		})
	}
}

func TestUpdateRejectsTypeChange(t *testing.T) {
	server := newFakeServer(map[string]string{
		readFederationURL: `{"success": true, "Result": ` + oidcFederationJSON + `}`,
	})
	service := newTestService(t, server)
	_, err := service.Update(&federationsmodels.IdsecIdentityUpdateFederation{FederationUUID: "fed-1", FederationName: "Okta", FederationType: "SAML 2.0"})
	if err == nil {
		t.Fatal("Update() allowed a protocol change")
	}
	if _, called := server.formCalls[updateFederationURL]; called {
		t.Error("Update() posted despite the protocol change")
	}
}

func TestEchoFormAlwaysSendsMappings(t *testing.T) {
	form := echoForm(map[string]interface{}{"FederationType": "OIDC"})
	if form["Mappings"] != "[]" {
		t.Errorf("Mappings = %q, want []", form["Mappings"])
	}
}

func TestDeleteFailures(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		delete  string
		list    string
		wantErr bool
	}{
		{
			name:   "missing federation counts as deleted",
			id:     "fed-9",
			delete: `{"success": false, "Message": "Federation fed-9 does not exist"}`,
			list:   `{"success": true, "Result": []}`,
		},
		{
			name:    "failure of an existing federation",
			id:      "fed-1",
			delete:  `{"success": false, "Message": "Access denied"}`,
			list:    `{"success": true, "Result": [{"FederationUuid": "fed-1", "FederationType": "OIDC"}]}`,
			wantErr: true,
		},
		{
			name:    "failure when the list fails too",
			id:      "fed-1",
			delete:  `{"success": false, "Message": "Access denied"}`,
			list:    `{"success": false, "Message": "Access denied"}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := newTestService(t, newFakeServer(map[string]string{deleteFederationURL: tt.delete, listFederationURL: tt.list}))
			err := service.Delete(&federationsmodels.IdsecIdentityDeleteFederation{FederationUUID: tt.id})
			if (err != nil) != tt.wantErr {
				t.Errorf("Delete() error = %v, want error %t", err, tt.wantErr)
			}
		})
	}
}

// TestMappingWritesAreSerialized runs every write that touches the shared mappings file at once
// and checks that no two are in flight together. Update holds the lock from its read to its post.
// A write fails the check when its lock is removed: each one has a goroutine here.
func TestMappingWritesAreSerialized(t *testing.T) {
	var (
		inFlight    atomic.Int32
		maxInFlight atomic.Int32
	)
	enter := func() {
		current := inFlight.Add(1)
		for {
			seen := maxInFlight.Load()
			if current <= seen || maxInFlight.CompareAndSwap(seen, current) {
				break
			}
		}
		// Widen the window for an overlap.
		time.Sleep(2 * time.Millisecond)
	}
	exit := func() { inFlight.Add(-1) }
	responses := map[string]string{
		createFederationURL:         `{"success": true, "Result": ` + oidcFederationJSON + `}`,
		readFederationURL:           `{"success": true, "Result": ` + oidcFederationJSON + `}`,
		updateFederationURL:         `{"success": true, "Result": ` + oidcFederationJSON + `}`,
		deleteFederationURL:         `{"success": true, "Result": null}`,
		addGlobalMappingURL:         `{"success": true, "Result": null}`,
		removeGlobalMappingURL:      `{"success": true, "Result": null}`,
		listGlobalMappingsURL:       storedGlobalMappingsJSON,
		globalFederationSettingsURL: globalSettingsJSON,
	}
	handle := func(path string) (*http.Response, error) {
		switch path {
		case readFederationURL:
			// Only Update reads here, and it holds the lock until its post.
			enter()
		case updateFederationURL:
			exit()
		case createFederationURL, deleteFederationURL, addGlobalMappingURL, removeGlobalMappingURL:
			enter()
			exit()
		}
		return jsonResponse(http.StatusOK, responses[path]), nil
	}
	service := newTestService(t, newFakeServer(nil))
	service.DoPost = func(_ context.Context, path string, _ interface{}) (*http.Response, error) { return handle(path) }
	service.DoFormPost = func(_ context.Context, path string, _ map[string]string) (*http.Response, error) { return handle(path) }

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(5)
		go func() {
			defer wg.Done()
			_, _ = service.Create(&federationsmodels.IdsecIdentityCreateFederation{FederationName: "Okta", FederationType: "OIDC"})
		}()
		go func() {
			defer wg.Done()
			_, _ = service.Update(&federationsmodels.IdsecIdentityUpdateFederation{FederationUUID: "fed-1", FederationName: "Okta", Active: true})
		}()
		go func() {
			defer wg.Done()
			// The read back after the post finds no such mapping in the fake; only the locking matters.
			_, _ = service.AddGlobalGroupMapping(&federationsmodels.IdsecIdentityAddFederationGlobalGroupMapping{AttributeValue: "new", GroupName: "Cloud Admins"})
		}()
		go func() {
			defer wg.Done()
			_ = service.RemoveGlobalGroupMapping(&federationsmodels.IdsecIdentityRemoveFederationGlobalGroupMapping{AttributeValue: "Admins", GroupName: "Cloud Admins"})
		}()
		go func() {
			defer wg.Done()
			_ = service.Delete(&federationsmodels.IdsecIdentityDeleteFederation{FederationUUID: "fed-2"})
		}()
	}
	wg.Wait()
	if got := maxInFlight.Load(); got != 1 {
		t.Errorf("%d mapping writes were in flight at once, want 1", got)
	}
}

func TestMappingsLockIsPerTenant(t *testing.T) {
	tenantA := tenantMappingsLock("https://tenant-a.example.com/")
	if tenantMappingsLock("https://TENANT-A.example.com") != tenantA {
		t.Error("the same tenant URL in another case or without the trailing slash got another lock")
	}
	if tenantMappingsLock("https://tenant-b.example.com/") == tenantA {
		t.Error("two tenants share a mappings lock")
	}
	first := newTestService(t, newFakeServer(nil))
	second := newTestService(t, newFakeServer(nil))
	if first.mappingsLock == nil || first.mappingsLock != second.mappingsLock {
		t.Error("two services for the same tenant do not share a mappings lock")
	}
}

func TestListFiltersUnsupportedTypes(t *testing.T) {
	server := newFakeServer(map[string]string{
		listFederationURL: `{"success": true, "Result": [
			{"FederationUuid": "fed-1", "FederationName": "Okta", "FederationType": "OIDC"},
			{"FederationUuid": "fed-2", "FederationName": "ADFS", "FederationType": "SAML 2.0"},
			{"FederationUuid": "fed-3", "FederationName": "Google", "FederationType": "Google"},
			{"FederationUuid": "fed-4", "FederationName": "ADFS shadow", "FederationType": "SAML 2.0 Shadow"}
		]}`,
	})
	service := newTestService(t, server)
	all, err := service.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("List() returned %d federations, want 2: %+v", len(all), all)
	}
	filtered, err := service.ListBy(&federationsmodels.IdsecIdentityFederationFilters{FederationType: "SAML 2.0"})
	if err != nil {
		t.Fatalf("ListBy() error = %v", err)
	}
	if len(filtered) != 1 || filtered[0].FederationUUID != "fed-2" {
		t.Errorf("ListBy() = %+v", filtered)
	}
}

// TestServiceIsCallableByActionName verifies that the service is registered and that every action
// name in ActionToSchemaMap maps to a method that takes the action's schema. A schema and a method
// that disagree otherwise only fail when the action is invoked.
func TestServiceIsCallableByActionName(t *testing.T) {
	config, err := services.GetServiceConfig("identity-federations")
	if err != nil {
		t.Fatalf("GetServiceConfig() error = %v: the package's init() must register the service", err)
	}
	if !reflect.DeepEqual(config.ActionSchemas, svcactions.ActionToSchemaMap) {
		t.Fatal("the registered action schemas are not ActionToSchemaMap")
	}
	actionMethods := map[string]string{
		"create":                      "Create",
		"update":                      "Update",
		"delete":                      "Delete",
		"get":                         "Get",
		"list":                        "List",
		"list-by":                     "ListBy",
		"add-global-group-mapping":    "AddGlobalGroupMapping",
		"get-global-group-mapping":    "GetGlobalGroupMapping",
		"remove-global-group-mapping": "RemoveGlobalGroupMapping",
		"list-global-group-mappings":  "ListGlobalGroupMappings",
	}
	if len(actionMethods) != len(config.ActionSchemas) {
		t.Fatalf("%d actions are registered, %d are accounted for here", len(config.ActionSchemas), len(actionMethods))
	}
	serviceValue := reflect.ValueOf((*IdsecIdentityFederationsService)(nil))
	for action, methodName := range actionMethods {
		schema, registered := config.ActionSchemas[action]
		if !registered {
			t.Errorf("action %q is not registered", action)
			continue
		}
		method := serviceValue.MethodByName(methodName)
		if !method.IsValid() {
			t.Errorf("action %q names method %s, which the service does not have", action, methodName)
			continue
		}
		if schema == nil {
			if method.Type().NumIn() != 0 {
				t.Errorf("action %q registers no schema, so %s must take no argument", action, methodName)
			}
			continue
		}
		if method.Type().NumIn() != 1 || method.Type().In(0) != reflect.TypeOf(schema) {
			t.Errorf("%s must take exactly %T, the schema of action %q", methodName, schema, action)
		}
	}
}
