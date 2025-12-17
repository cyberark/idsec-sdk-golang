package actions

// Package actions provides constants and configuration settings for the Idsec CLI actions.
var (
	ConfigurationAuthenticatorIgnoredDefinitionKeys = map[string][]string{
		"isp": {"identity-application", "identity-tenant-url"},
	}

	ConfigurationAuthenticatorIgnoredInteractiveKeys = map[string][]string{
		"isp": {
			"identity-application",
			"identity-application-id",
			"identity-tenant-url",
			"identity-mfa-interactive",
		},
	}

	ConfigurationAllowedEmptyValues = map[string][]string{
		"isp": {
			"identity-url",
			"identity-tenant-subdomain",
			"identity-mfa-method",
		},
	}
	ConfigurationDefaultInteractiveValues = map[string]map[string]interface{}{
		"isp": {
			"identity-mfa-interactive": true,
		},
	}
)
