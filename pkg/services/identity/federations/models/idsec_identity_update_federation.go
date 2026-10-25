// Package models provides the data structures for IDSEC Identity federation operations.
package models

// IdsecIdentityUpdateFederation is the write model for the update operation.
//
// Every optional field is a pointer, a pointer to a slice, or a string where empty means unset.
// An unset field keeps the value on the tenant: the provider leaves an attribute the
// configuration does not set unknown, and the service then resends what it read instead. A
// pointer to an empty slice clears the list. OIDCClientSecret is nil when it was not rotated,
// and the server keeps the stored secret when none is sent.
//
// Active is not optional: it is always sent, and a Go caller that leaves it false deactivates
// the federation (the true default applies only where defaults are read, such as the CLI).
// FederationType cannot change: the update uses the stored type, and a different one is
// rejected. The service also accepts it empty, for a Go caller that does not know it.
type IdsecIdentityUpdateFederation struct {
	FederationUUID           string                                     `json:"federation_id" mapstructure:"federation_id" flag:"federation-id" desc:"The unique identifier of the federation." validate:"required"`
	FederationName           string                                     `json:"federation_name" mapstructure:"federation_name" flag:"federation-name" desc:"The display name of the external identity provider." validate:"required"`
	FederationType           string                                     `json:"federation_type" mapstructure:"federation_type" flag:"federation-type" desc:"The federation protocol." validate:"required" choices:"SAML 2.0,OIDC"`
	Active                   bool                                       `json:"active" mapstructure:"active" flag:"active" desc:"Whether the federation is active." default:"true"`
	Domains                  *[]string                                  `json:"domains,omitempty" mapstructure:"domains" flag:"domains" desc:"The federated domains routed to this identity provider."`
	OIDCMetadataURL          string                                     `json:"oidc_metadata_url,omitempty" mapstructure:"oidc_metadata_url" flag:"oidc-metadata-url" desc:"The OIDC discovery document URL." validate:"required_if=FederationType OIDC,regexp=\\.well-known/openid-(configuration0x7Cfederation)/?$"`
	OIDCClientID             string                                     `json:"oidc_client_id,omitempty" mapstructure:"oidc_client_id" flag:"oidc-client-id" desc:"The client ID registered at the OIDC identity provider." validate:"required_if=FederationType OIDC"`
	OIDCClientSecret         *string                                    `json:"oidc_client_secret,omitempty" mapstructure:"oidc_client_secret" flag:"oidc-client-secret" desc:"The client secret registered at the OIDC identity provider." secret:"true"`
	OIDCGrantType            string                                     `json:"oidc_grant_type,omitempty" mapstructure:"oidc_grant_type" flag:"oidc-grant-type" desc:"The OIDC grant type." choices:"AuthorizationCode"`
	PKCEEnabled              *bool                                      `json:"oidc_pkce_enabled,omitempty" mapstructure:"oidc_pkce_enabled" flag:"oidc-pkce-enabled" desc:"Whether PKCE is used."`
	OIDCScopes               *[]string                                  `json:"oidc_scopes,omitempty" mapstructure:"oidc_scopes" flag:"oidc-scopes" desc:"The scopes requested from the OIDC identity provider."`
	LogoutCallBackURI        string                                     `json:"oidc_post_logout_redirect_uri,omitempty" mapstructure:"oidc_post_logout_redirect_uri" flag:"oidc-post-logout-redirect-uri" desc:"The post logout redirect URI."`
	GroupMappings            *[]IdsecIdentityFederationGroupMapping     `json:"group_mappings,omitempty" mapstructure:"group_mappings" flag:"group-mappings" desc:"The identity provider group assertions mapped to federated groups, in order." validate:"omitnil,dive"`
	MapUsers                 string                                     `json:"map_users,omitempty" mapstructure:"map_users" flag:"map-users" desc:"Whether federated users are linked to existing directory users." choices:"Disabled,Optional,Required"`
	MapUserAttribute         string                                     `json:"map_user_attribute,omitempty" mapstructure:"map_user_attribute" flag:"map-user-attribute" desc:"The identity provider attribute used to find the directory user."`
	MapUserDirectoryService  string                                     `json:"map_user_directory_service,omitempty" mapstructure:"map_user_directory_service" flag:"map-user-directory-service" desc:"The directory service UUID searched for the user. Empty means any directory service."`
	MapUserBy                string                                     `json:"map_user_by,omitempty" mapstructure:"map_user_by" flag:"map-user-by" desc:"The directory user attribute matched against map_user_attribute."`
	MapUserSyncWithCloudUser *bool                                      `json:"map_user_sync_with_cloud_user,omitempty" mapstructure:"map_user_sync_with_cloud_user" flag:"map-user-sync-with-cloud-user" desc:"Whether the directory user is updated from the identity provider attributes."`
	MapUserSyncWithFedUser   *bool                                      `json:"map_user_sync_with_federated_user,omitempty" mapstructure:"map_user_sync_with_federated_user" flag:"map-user-sync-with-federated-user" desc:"Whether the federated user is updated from the identity provider attributes."`
	MapUserUsesGroups        *bool                                      `json:"map_user_uses_groups,omitempty" mapstructure:"map_user_uses_groups" flag:"map-user-uses-groups" desc:"Whether the mapped user also receives the federated group memberships."`
	MapUserAllowFederations  *bool                                      `json:"map_user_allow_other_federations,omitempty" mapstructure:"map_user_allow_other_federations" flag:"map-user-allow-other-federations" desc:"Whether the federated user may map to a user that belongs to another federation."`
	MapUserCreateIfNotFound  *bool                                      `json:"map_user_create_if_not_found,omitempty" mapstructure:"map_user_create_if_not_found" flag:"map-user-create-if-not-found" desc:"Whether a Cloud Directory user is created when none is found. Requires map_users Required."`
	AttributeMappings        *[]IdsecIdentityFederationAttributeMapping `json:"attribute_mappings,omitempty" mapstructure:"attribute_mappings" flag:"attribute-mappings" desc:"Identity provider attributes copied onto Cloud Directory user attributes. Stored only when map_user_directory_service is the Cloud Directory and a sync or create option is on." validate:"omitnil,dive"`
	DeviceTypes              *[]string                                  `json:"device_types,omitempty" mapstructure:"device_types" flag:"device-types" desc:"The device types routed to this identity provider. Empty means every device type. A partial selection requires map_users Required." choices:"Android,iOS,Others" validate:"omitnil,max=2"`
	UserAgents               *[]string                                  `json:"user_agents,omitempty" mapstructure:"user_agents" flag:"user-agents" desc:"The client types routed to this identity provider." choices:"Browser,NonBrowser,Any"`
	SAMLMetadataURL          string                                     `json:"saml_metadata_url,omitempty" mapstructure:"saml_metadata_url" flag:"saml-metadata-url" desc:"The SAML identity provider metadata URL. The server fetches the metadata on every create and update."`
	SAMLSignInURL            string                                     `json:"saml_sign_in_url,omitempty" mapstructure:"saml_sign_in_url" flag:"saml-sign-in-url" desc:"The SAML identity provider sign-in URL. Read from the metadata when it is supplied."`
	SAMLLogoutURL            string                                     `json:"saml_logout_url,omitempty" mapstructure:"saml_logout_url" flag:"saml-logout-url" desc:"The SAML identity provider logout URL. Read from the metadata when it is supplied."`
	SAMLSignAlgorithm        string                                     `json:"saml_sign_algorithm,omitempty" mapstructure:"saml_sign_algorithm" flag:"saml-sign-algorithm" desc:"The algorithm the SAML authentication request is signed with." choices:"SHA1,SHA256"`
	SAMLURLRedirectEnabled   *bool                                      `json:"saml_url_redirect_enabled,omitempty" mapstructure:"saml_url_redirect_enabled" flag:"saml-url-redirect-enabled" desc:"Whether users are redirected to a URL that matches saml_url_redirect_pattern after SAML sign-in."`
	SAMLURLRedirectPattern   string                                     `json:"saml_url_redirect_pattern,omitempty" mapstructure:"saml_url_redirect_pattern" flag:"saml-url-redirect-pattern" desc:"The https URL pattern, which may contain *, that redirection after SAML sign-in is allowed to."`
	SAMLOAuthClientID        string                                     `json:"saml_oauth_client_id,omitempty" mapstructure:"saml_oauth_client_id" flag:"saml-oauth-client-id" desc:"The OAuth client ID the tenant uses to sign the identity provider's users in with a password, through saml_oauth_access_token_url."`
	SAMLOAuthClientSecret    *string                                    `json:"saml_oauth_client_secret,omitempty" mapstructure:"saml_oauth_client_secret" flag:"saml-oauth-client-secret" desc:"The OAuth client secret for saml_oauth_client_id. The server keeps the stored secret when none is sent." secret:"true"`
	SAMLOAuthAccessTokenURL  string                                     `json:"saml_oauth_access_token_url,omitempty" mapstructure:"saml_oauth_access_token_url" flag:"saml-oauth-access-token-url" desc:"The identity provider's OAuth token URL, used for password sign-in. Must be an https URL." validate:"regexp=(?i)^https://"`
	SAMLMetadataXML          *string                                    `json:"saml_metadata_xml,omitempty" mapstructure:"saml_metadata_xml" flag:"saml-metadata-xml" desc:"The SAML identity provider metadata document, uploaded instead of fetching it from saml_metadata_url."`
	SAMLSigningCertificate   *string                                    `json:"saml_signing_certificate,omitempty" mapstructure:"saml_signing_certificate" flag:"saml-signing-certificate" desc:"The SAML identity provider signing certificate, PEM or base64 encoded, for a federation configured without metadata."`
}
