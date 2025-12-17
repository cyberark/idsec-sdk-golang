package auth

// IdsecAuthMethod is a string type that represents the authentication method used in the Idsec SDK.
type IdsecAuthMethod string

// Authentication methods supported by the Idsec SDK.
const (
	Identity            IdsecAuthMethod = "identity"
	IdentityServiceUser IdsecAuthMethod = "identity_service_user"
	Direct              IdsecAuthMethod = "direct"
	Default             IdsecAuthMethod = "default"
	Other               IdsecAuthMethod = "other"
)

// IdsecAuthMethodSettings is an interface that defines the settings for different authentication methods.
type IdsecAuthMethodSettings interface{}

// IdentityIdsecAuthMethodSettings is a struct that represents the settings for the Identity authentication method.
type IdentityIdsecAuthMethodSettings struct {
	IdentityMFAMethod       string `json:"identity_mfa_method" mapstructure:"identity_mfa_method" validate:"oneof=pf sms email otp" flag:"identity-mfa-method" desc:"MFA Method to use by default [pf, sms, email, otp]"`
	IdentityMFAInteractive  bool   `json:"identity_mfa_interactive" mapstructure:"identity_mfa_interactive" validate:"required" flag:"identity-mfa-interactive" desc:"Allow Interactive MFA"`
	IdentityURL             string `json:"identity_url" mapstructure:"identity_url" flag:"identity-url" desc:"Identity Url"`
	IdentityTenantSubdomain string `json:"identity_tenant_subdomain" mapstructure:"identity_tenant_subdomain" flag:"identity-tenant-subdomain" desc:"Identity Tenant Subdomain"`
}

// IdentityServiceUserIdsecAuthMethodSettings is a struct that represents the settings for the Identity Service User authentication method.
type IdentityServiceUserIdsecAuthMethodSettings struct {
	IdentityURL                      string `json:"identity_url" mapstructure:"identity_url" flag:"identity-url" desc:"Identity Url"`
	IdentityTenantSubdomain          string `json:"identity_tenant_subdomain" mapstructure:"identity_tenant_subdomain" flag:"identity-tenant-subdomain" desc:"Identity Tenant Subdomain"`
	IdentityAuthorizationApplication string `json:"identity_authorization_application" mapstructure:"identity_authorization_application" validate:"required" flag:"identity-authorization-application" desc:"Identity Authorization Application" default:"__idaptive_cybr_user_oidc"`
}

// DirectIdsecAuthMethodSettings is a struct that represents the settings for the Direct authentication method.
type DirectIdsecAuthMethodSettings struct {
	Endpoint    string `json:"endpoint" mapstructure:"endpoint" flag:"endpoint" desc:"Authentication Endpoint"`
	Interactive bool   `json:"interactive" mapstructure:"interactive" flag:"interactive" desc:"Allow interactiveness"`
}

// DefaultIdsecAuthMethodSettings is a struct that represents the default settings for the authentication method.
type DefaultIdsecAuthMethodSettings struct{}

// IdsecAuthMethodSettingsMap is a map that associates each IdsecAuthMethod with its corresponding settings struct.
var IdsecAuthMethodSettingsMap = map[IdsecAuthMethod]interface{}{
	Identity:            &IdentityIdsecAuthMethodSettings{},
	IdentityServiceUser: &IdentityServiceUserIdsecAuthMethodSettings{},
	Direct:              &DirectIdsecAuthMethodSettings{},
	Default:             &DefaultIdsecAuthMethodSettings{},
}

// IdsecAuthMethodsDescriptionMap is a map that provides descriptions for each IdsecAuthMethod.
var IdsecAuthMethodsDescriptionMap = map[IdsecAuthMethod]string{
	Identity:            "Identity Personal User",
	IdentityServiceUser: "Identity Service User",
	Direct:              "Direct Endpoint Access",
	Default:             "Default Authenticator Method",
}

// IdsecAuthMethodsRequireCredentials is a slice of IdsecAuthMethod that require credentials.
var IdsecAuthMethodsRequireCredentials = []IdsecAuthMethod{
	Identity, IdentityServiceUser, Direct,
}

// IdsecAuthMethodSharableCredentials is a slice of IdsecAuthMethod that can share credentials.
var IdsecAuthMethodSharableCredentials = []IdsecAuthMethod{
	Identity,
}
