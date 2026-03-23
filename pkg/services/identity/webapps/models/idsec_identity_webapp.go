package models

// Possible values for AllowedAuth in IdsecIdentityWebappOAuthProfile
const (
	AllowedAuthTypeClientCreds       = "ClientCreds"
	AllowedAuthTypeAuthorizationCode = "AuthorizationCode"
	AllowedAuthTypeImplicit          = "Implicit"
	AllowedAuthTypeResourceCreds     = "ResourceCreds"
)

// Default values for IdsecIdentityWebappOAuthProfile
const (
	DefaultOAuthTokenLifetimeString = "0.05:00:00"
	DefaultOAuthTokenType           = "JwtRS256"
)

// Default values for IdsecIdentityWebappPolicyAuthRule
const (
	DefaultWebappPolicyAuthRuleType      = "RowSet"
	DefaultWebappPolicyAuthRuleUniqueKey = "Condition"
)

// IdsecIdentityWebappOAuthScope represents an OAuth scope in the context of a webapp.
type IdsecIdentityWebappOAuthScope struct {
	Scope       string  `json:"scope" mapstructure:"scope" flag:"scope" desc:"OAuth scope" validate:"required,min=1"`
	Description string  `json:"description" mapstructure:"description" flag:"description" desc:"Description of the scope"`
	Type        *string `json:"type,omitempty" mapstructure:"type,omitempty" flag:"type" desc:"Type of the scope"`
}

// IdsecIdentityWebappOAuthProfile represents the OAuth profile configuration for a webapp.
type IdsecIdentityWebappOAuthProfile struct {
	TokenType           string                          `json:"token_type" mapstructure:"token_type" flag:"token-type" desc:"OAuth token type" default:"JwtRS256"`
	TokenLifetimeString string                          `json:"token_lifetime_string" mapstructure:"token_lifetime_string" flag:"token-lifetime-string" desc:"Token lifetime as string" default:"0.05:00:00"`
	AllowedAuth         []string                        `json:"allowed_auth,omitempty" mapstructure:"allowed_auth,omitempty" flag:"allowed-auth" desc:"Allowed authentication methods" choices:"ClientCreds,AuthorizationCode,Implicit,ResourceCreds"`
	KnownScopes         []IdsecIdentityWebappOAuthScope `json:"known_scopes,omitempty" mapstructure:"known_scopes,omitempty" flag:"known-scopes" desc:"Known scopes"`
	Audience            *string                         `json:"audience,omitempty" mapstructure:"audience,omitempty" flag:"audience" desc:"OAuth audience"`
	Issuer              *string                         `json:"issuer,omitempty" mapstructure:"issuer,omitempty" flag:"issuer" desc:"OAuth issuer"`
	ClientIDType        *int                            `json:"client_id_type,omitempty" mapstructure:"client_id_type,omitempty" flag:"client-id-type" desc:"Client ID type"`
	MustBeOauthClient   *bool                           `json:"must_be_oauth_client,omitempty" mapstructure:"must_be_oauth_client,omitempty" flag:"must-be-oauth-client" desc:"Whether the client must be an OAuth client"`
	AllowRefresh        *bool                           `json:"allow_refresh,omitempty" mapstructure:"allow_refresh,omitempty" flag:"allow-refresh" desc:"Whether to allow refresh tokens"`
}

// IdsecIdentityWebappAppsConfiguration represents the configuration details specific to webapps, which can be used in various webapp-related operations.
type IdsecIdentityWebappAppsConfiguration struct {
	// WebApp Specific Fields
	Url                       *string                          `json:"url,omitempty" mapstructure:"url,omitempty" flag:"url" desc:"URL of the webapp"`
	MobileUrl                 *string                          `json:"mobile_url,omitempty" mapstructure:"mobile_url,omitempty" flag:"mobile-url" desc:"Mobile URL of the webapp"`
	ADAttribute               *string                          `json:"ad_attribute,omitempty" mapstructure:"ad_attribute,omitempty" flag:"ad-attribute" desc:"Active Directory attribute used for user assignment"`
	UserMapScript             *string                          `json:"user_map_script,omitempty" mapstructure:"user_map_script,omitempty" flag:"user-map-script" desc:"User map script for the webapp"`
	UserNameStrategy          *string                          `json:"user_name_strategy,omitempty" mapstructure:"user_name_strategy,omitempty" flag:"user-name-strategy" desc:"User name strategy"`
	UserPassScript            *string                          `json:"user_pass_script,omitempty" mapstructure:"user_pass_script,omitempty" flag:"user-pass-script" desc:"User password script for the webapp"`
	Username                  *string                          `json:"username,omitempty" mapstructure:"username,omitempty" flag:"username" desc:"Username for the webapp"`
	Password                  *string                          `json:"password,omitempty" mapstructure:"password,omitempty" flag:"password" desc:"Password for the webapp"`
	OAuthProfile              *IdsecIdentityWebappOAuthProfile `json:"oauth_profile,omitempty" mapstructure:"oauth_profile,omitempty" flag:"oauth-profile" desc:"OAuth profile (optional)"`
	OpenIDConnectScript       *string                          `json:"open_id_connect_script,omitempty" mapstructure:"open_id_connect_script,omitempty" flag:"open-id-connect-script" desc:"OpenID Connect script"`
	AdditionalIdentifierValue *string                          `json:"additional_identifier_value,omitempty" mapstructure:"additional_identifier_value,omitempty" flag:"additional-identifier-value" desc:"Additional identifier value for the webapp"`
	CorpIdentifier            *string                          `json:"corp_identifier,omitempty" mapstructure:"corp_identifier,omitempty" flag:"corp-identifier" desc:"Corp identifier for the webapp"`
	Safe                      *string                          `json:"safe,omitempty" mapstructure:"safe,omitempty" flag:"safe" desc:"Safe that the webapp belongs to"`
	AccountName               *string                          `json:"account_name,omitempty" mapstructure:"account_name,omitempty" flag:"account-name" desc:"Account name for the webapp"`
	ExtAccountId              *string                          `json:"ext_account_id,omitempty" mapstructure:"ext_account_id,omitempty" flag:"ext-account-id" desc:"External account ID for the webapp"`
	IsPrivilegedApp           *bool                            `json:"is_privileged_app,omitempty" mapstructure:"is_privileged_app,omitempty" flag:"is-privileged-app" desc:"Whether the webapp is privileged"`
	AllowViewFixedCredentials *bool                            `json:"allow_view_fixed_credentials,omitempty" mapstructure:"allow_view_fixed_credentials,omitempty" flag:"allow-view-fixed-credentials" desc:"Whether to allow viewing fixed credentials"`
	IsScaEnabled              *bool                            `json:"is_sca_enabled,omitempty" mapstructure:"is_sca_enabled,omitempty" flag:"is-sca-enabled" desc:"Whether SCA is enabled"`
}

// IdsecIdentityWebappPolicyAuthRuleCondition represents a single condition in an authentication rule for a webapp policy configuration.
type IdsecIdentityWebappPolicyAuthRuleCondition struct {
	Op   *string `json:"op,omitempty" mapstructure:"op,omitempty" flag:"op" desc:"Operator for the auth rule condition"`
	Prop *string `json:"prop,omitempty" mapstructure:"prop,omitempty" flag:"prop" desc:"Property for the auth rule condition"`
	Val  *string `json:"val,omitempty" mapstructure:"val,omitempty" flag:"val" desc:"Value for the auth rule condition"`
}

// IdsecIdentityWebappPolicyAuthRuleConditions represents a set of conditions for an authentication rule in the policy configuration for a webapp.
type IdsecIdentityWebappPolicyAuthRuleConditions struct {
	Conditions []IdsecIdentityWebappPolicyAuthRuleCondition `json:"conditions" mapstructure:"conditions" flag:"conditions" desc:"List of conditions for the auth rule"`
	ProfileId  *string                                      `json:"profile_id,omitempty" mapstructure:"profile_id,omitempty" flag:"profile-id" desc:"Authentication profile ID to apply the conditions to"`
}

// IdsecIdentityWebappPolicyAuthRule represents an authentication rule in the policy configuration for a webapp.
type IdsecIdentityWebappPolicyAuthRule struct {
	Enabled   bool                                          `json:"enabled" mapstructure:"enabled" flag:"enabled" desc:"Whether the auth rule is enabled"`
	Type      string                                        `json:"type" mapstructure:"type" flag:"type" desc:"Type of the auth rule" default:"RowSet"`
	UniqueKey string                                        `json:"unique_key" mapstructure:"unique_key" flag:"unique-key" desc:"Unique key for the auth rule" default:"Condition"`
	Value     []IdsecIdentityWebappPolicyAuthRuleConditions `json:"value" mapstructure:"value" flag:"value" desc:"Value of the auth rule conditions"`
}

// IdsecIdentityWebappPolicyConfiguration represents the policy configuration for a webapp.
type IdsecIdentityWebappPolicyConfiguration struct {
	WebappLoginType    *string                            `json:"webapp_login_type,omitempty" mapstructure:"webapp_login_type,omitempty" flag:"webapp-login-type" desc:"Web app login type"`
	DefaultAuthProfile *string                            `json:"default_auth_profile,omitempty" mapstructure:"default_auth_profile,omitempty" flag:"default-auth-profile" desc:"Default authentication profile for the webapp"`
	BypassLoginMfa     *bool                              `json:"bypass_login_mfa,omitempty" mapstructure:"bypass_login_mfa,omitempty" flag:"bypass-login-mfa" desc:"Whether to bypass MFA at login for the webapp"`
	AuthRules          *IdsecIdentityWebappPolicyAuthRule `json:"auth_rules,omitempty" mapstructure:"auth_rules,omitempty" flag:"auth-rules" desc:"Authentication rules for the webapp"`
}

// IdsecIdentityWebapp represents the webapp app details.
type IdsecIdentityWebapp struct {
	IdsecIdentityWebappAppsConfiguration   `mapstructure:",squash"`
	IdsecIdentityWebappPolicyConfiguration `mapstructure:",squash"`
	WebappID                               string  `json:"webapp_id" mapstructure:"webapp_id" flag:"webapp-id" desc:"Row key identifier of the webapp"`
	WebappName                             string  `json:"webapp_name" mapstructure:"webapp_name" flag:"webapp-name" desc:"Name of the webapp"`
	ServiceName                            *string `json:"service_name,omitempty" mapstructure:"service_name,omitempty" flag:"service-name" desc:"Name of the service to which the webapp belongs"`
	DisplayName                            string  `json:"display_name" mapstructure:"display_name" flag:"display-name" desc:"Display name of the webapp"`
	Category                               *string `json:"category" mapstructure:"category" flag:"category" desc:"Category of the webapp"`
	Description                            string  `json:"description" mapstructure:"description" flag:"description" desc:"Description of the webapp" validate:"required,min=1"`
	WebappType                             string  `json:"webapp_type" mapstructure:"webapp_type" flag:"webapp-type" desc:"Type of the webapp" validate:"required,min=1"`
	WebappTypeDisplayName                  string  `json:"webapp_type_display_name" mapstructure:"webapp_type_display_name" flag:"webapp-type-display-name" desc:"Display name of the webapp type" validate:"required,min=1"`
	AppTypeDisplayName                     string  `json:"app_type_display_name" mapstructure:"app_type_display_name" flag:"app-type-display-name" desc:"Display name of the app type" validate:"required,min=1"`
	TemplateName                           string  `json:"template_name" mapstructure:"template_name" flag:"template-name" desc:"Name of the template" validate:"required,min=1"`
	State                                  string  `json:"state" mapstructure:"state" flag:"state" desc:"State of the webapp" validate:"required,min=1"`
	IsSwsEnabled                           *bool   `json:"is_sws_enabled,omitempty" mapstructure:"is_sws_enabled,omitempty" flag:"is-sws-enabled" desc:"Whether SWS is enabled"`
	IsScaEnabled                           *bool   `json:"is_sca_enabled,omitempty" mapstructure:"is_sca_enabled,omitempty" flag:"is-sca-enabled" desc:"Whether SCA is enabled"`
	Generic                                *bool   `json:"generic" mapstructure:"generic" flag:"generic" desc:"Whether the webapp is generic"`
}
