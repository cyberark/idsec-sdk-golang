package models

import (
	"errors"
	"slices"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/validation"
)

// failedRules validates input and returns each failure as "<field path>: <rule>", sorted.
func failedRules(t *testing.T, input interface{}) []string {
	t.Helper()
	err := validation.ValidateStruct(input)
	if err == nil {
		return nil
	}
	var verr *validation.Error
	if !errors.As(err, &verr) {
		t.Fatalf("unexpected error type %T: %v", err, err)
	}
	var got []string
	for _, field := range verr.Fields() {
		got = append(got, validation.FieldPath(field)+": "+field.Tag())
	}
	slices.Sort(got)
	return got
}

func str(s string) *string { return &s }
func flag(b bool) *bool    { return &b }

func oidcCreate() IdsecIdentityCreateFederation {
	return IdsecIdentityCreateFederation{
		FederationName:   "oidc",
		FederationType:   "OIDC",
		OIDCMetadataURL:  "https://idp.example.com/.well-known/openid-configuration",
		OIDCClientID:     "client",
		OIDCClientSecret: str("secret"),
	}
}

func samlCreate() IdsecIdentityCreateFederation {
	return IdsecIdentityCreateFederation{FederationName: "saml", FederationType: "SAML 2.0"}
}

func TestCreateFederationValidation(t *testing.T) {
	tests := []struct {
		name  string
		input func() IdsecIdentityCreateFederation
		want  []string
	}{
		{name: "complete OIDC", input: oidcCreate},
		{name: "OIDC without metadata URL or client ID", input: func() IdsecIdentityCreateFederation {
			f := oidcCreate()
			f.OIDCMetadataURL, f.OIDCClientID = "", ""
			return f
		}, want: []string{"oidc_client_id: required_if", "oidc_metadata_url: required_if"}},
		{name: "OIDC base metadata URL", input: func() IdsecIdentityCreateFederation {
			f := oidcCreate()
			f.OIDCMetadataURL = "https://idp.example.com"
			return f
		}, want: []string{"oidc_metadata_url: regexp"}},
		{name: "OIDC discovery URL with trailing slash", input: func() IdsecIdentityCreateFederation {
			f := oidcCreate()
			f.OIDCMetadataURL = "https://idp.example.com/.well-known/openid-configuration/"
			return f
		}},
		{name: "OIDC federation discovery URL", input: func() IdsecIdentityCreateFederation {
			f := oidcCreate()
			f.OIDCMetadataURL = "https://idp.example.com/.well-known/openid-federation"
			return f
		}},
		{name: "OIDC with SAML attributes", input: func() IdsecIdentityCreateFederation {
			f := oidcCreate()
			f.SAMLMetadataURL, f.SAMLURLRedirectEnabled = "https://idp.example.com/metadata", flag(false)
			return f
		}, want: []string{"saml_metadata_url: excluded_if", "saml_url_redirect_enabled: excluded_if"}},
		{name: "SAML with OIDC attributes", input: func() IdsecIdentityCreateFederation {
			f := samlCreate()
			f.SAMLMetadataURL = "https://idp.example.com/metadata"
			f.OIDCClientID, f.PKCEEnabled, f.OIDCScopes = "client", flag(false), []string{"openid"}
			return f
		}, want: []string{"oidc_client_id: excluded_unless", "oidc_pkce_enabled: excluded_unless", "oidc_scopes: excluded_unless"}},
		{name: "SAML metadata URL", input: func() IdsecIdentityCreateFederation {
			f := samlCreate()
			f.SAMLMetadataURL = "https://idp.example.com/metadata"
			return f
		}},
		{name: "SAML manual", input: func() IdsecIdentityCreateFederation {
			f := samlCreate()
			f.SAMLSignInURL, f.SAMLLogoutURL, f.SAMLSigningCertificate = "https://idp.example.com/sso", "https://idp.example.com/logout", str("cert")
			return f
		}},
		{name: "SAML metadata URL and document", input: func() IdsecIdentityCreateFederation {
			f := samlCreate()
			f.SAMLMetadataURL, f.SAMLMetadataXML = "https://idp.example.com/metadata", str("<EntityDescriptor/>")
			return f
		}, want: []string{"saml_metadata_url: excluded_with"}},
		{name: "SAML metadata URL with manual attributes", input: func() IdsecIdentityCreateFederation {
			f := samlCreate()
			f.SAMLMetadataURL, f.SAMLSignInURL, f.SAMLSigningCertificate = "https://idp.example.com/metadata", "https://idp.example.com/sso", str("cert")
			return f
		}, want: []string{"saml_metadata_url: excluded_with"}},
		{name: "SAML metadata document with sign-in URL", input: func() IdsecIdentityCreateFederation {
			f := samlCreate()
			f.SAMLMetadataXML, f.SAMLSignInURL = str("<EntityDescriptor/>"), "https://idp.example.com/sso"
			return f
		}, want: []string{"saml_metadata_xml: excluded_with"}},
		{name: "SAML certificate without sign-in URL", input: func() IdsecIdentityCreateFederation {
			f := samlCreate()
			f.SAMLSigningCertificate = str("cert")
			return f
		}, want: []string{"saml_sign_in_url: required_with"}},
		{name: "SAML logout URL and certificate without sign-in URL", input: func() IdsecIdentityCreateFederation {
			f := samlCreate()
			f.SAMLLogoutURL, f.SAMLSigningCertificate = "https://idp.example.com/logout", str("cert")
			return f
		}, want: []string{"saml_sign_in_url: required_with"}},
		{name: "SAML OAuth credentials", input: func() IdsecIdentityCreateFederation {
			f := samlCreate()
			f.SAMLMetadataURL = "https://idp.example.com/metadata"
			f.SAMLOAuthClientID, f.SAMLOAuthClientSecret, f.SAMLOAuthAccessTokenURL = "client", str("secret"), "HTTPS://idp.example.com/token"
			return f
		}},
		{name: "SAML OAuth token URL that is not https", input: func() IdsecIdentityCreateFederation {
			f := samlCreate()
			f.SAMLMetadataURL, f.SAMLOAuthAccessTokenURL = "https://idp.example.com/metadata", "http://idp.example.com/token"
			return f
		}, want: []string{"saml_oauth_access_token_url: regexp"}},
		{name: "OIDC with SAML OAuth credentials", input: func() IdsecIdentityCreateFederation {
			f := oidcCreate()
			f.SAMLOAuthClientID, f.SAMLOAuthClientSecret, f.SAMLOAuthAccessTokenURL = "client", str("secret"), "https://idp.example.com/token"
			return f
		}, want: []string{"saml_oauth_access_token_url: excluded_if", "saml_oauth_client_id: excluded_if", "saml_oauth_client_secret: excluded_if"}},
		{name: "untrimmed and blank group mapping", input: func() IdsecIdentityCreateFederation {
			f := oidcCreate()
			f.GroupMappings = []IdsecIdentityFederationGroupMapping{{AttributeValue: " a", GroupName: "A"}, {AttributeValue: "b", GroupName: "   "}}
			return f
		}, want: []string{"group_mappings[0].attribute_value: regexp", "group_mappings[1].group_name: regexp"}},
		{name: "blank attribute mapping target and markup source", input: func() IdsecIdentityCreateFederation {
			f := oidcCreate()
			f.AttributeMappings = []IdsecIdentityFederationAttributeMapping{{Target: "  ", Source: "a"}, {Target: "b", Source: "a<b>"}}
			return f
		}, want: []string{"attribute_mappings[0].target: regexp", "attribute_mappings[1].source: regexp"}},
		{name: "attribute mapping source with a lone angle bracket", input: func() IdsecIdentityCreateFederation {
			f := oidcCreate()
			f.AttributeMappings = []IdsecIdentityFederationAttributeMapping{{Target: "a", Source: "x < y"}, {Target: "b", Source: "x<"}}
			return f
		}},
		{name: "every device type", input: func() IdsecIdentityCreateFederation {
			f := oidcCreate()
			f.DeviceTypes = []string{"Android", "iOS", "Others"}
			return f
		}, want: []string{"device_types: max"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := tt.input()
			if got := failedRules(t, &input); !slices.Equal(got, tt.want) {
				t.Errorf("failures = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestUpdateFederationValidation keeps the federation_type and SAML identity provider rules off the
// update model. An update is built from the plan, which carries the values stored by earlier reads:
// the sign-in and logout URLs the server read from a metadata URL or document, and false or empty
// values for the other federation_type's attributes. Those must not be rejected; the create model,
// which the provider also validates every plan's configuration against, enforces the rules.
func TestUpdateFederationValidation(t *testing.T) {
	tests := []struct {
		name  string
		input IdsecIdentityUpdateFederation
		want  []string
	}{
		{name: "SAML metadata URL with the URLs read from it", input: IdsecIdentityUpdateFederation{
			FederationUUID: "id", FederationName: "saml", FederationType: "SAML 2.0",
			SAMLMetadataURL: "https://idp.example.com/metadata", SAMLSignInURL: "https://idp.example.com/sso", SAMLLogoutURL: "https://idp.example.com/logout",
		}},
		{name: "OIDC with the stored values of the SAML attributes", input: IdsecIdentityUpdateFederation{
			FederationUUID: "id", FederationName: "oidc", FederationType: "OIDC",
			OIDCMetadataURL: "https://idp.example.com/.well-known/openid-configuration", OIDCClientID: "client",
			SAMLURLRedirectEnabled: flag(false),
		}},
		{name: "SAML with the stored values of the OIDC attributes", input: IdsecIdentityUpdateFederation{
			FederationUUID: "id", FederationName: "saml", FederationType: "SAML 2.0", SAMLMetadataURL: "https://idp.example.com/metadata",
			PKCEEnabled: flag(false), OIDCScopes: &[]string{},
		}},
		{name: "OIDC without a client ID", input: IdsecIdentityUpdateFederation{
			FederationUUID: "id", FederationName: "oidc", FederationType: "OIDC",
			OIDCMetadataURL: "https://idp.example.com/.well-known/openid-configuration",
		}, want: []string{"oidc_client_id: required_if"}},
		{name: "SAML OAuth token URL that is not https", input: IdsecIdentityUpdateFederation{
			FederationUUID: "id", FederationName: "saml", FederationType: "SAML 2.0", SAMLMetadataURL: "https://idp.example.com/metadata",
			SAMLOAuthAccessTokenURL: "http://idp.example.com/token",
		}, want: []string{"saml_oauth_access_token_url: regexp"}},
		{name: "SAML with every device type", input: IdsecIdentityUpdateFederation{
			FederationUUID: "id", FederationName: "saml", FederationType: "SAML 2.0", SAMLMetadataURL: "https://idp.example.com/metadata",
			DeviceTypes: &[]string{"Android", "iOS", "Others"},
		}, want: []string{"device_types: max"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := failedRules(t, &tt.input); !slices.Equal(got, tt.want) {
				t.Errorf("failures = %q, want %q", got, tt.want)
			}
		})
	}
}
