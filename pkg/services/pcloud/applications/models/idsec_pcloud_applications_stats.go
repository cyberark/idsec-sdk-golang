package models

// IdsecPCloudApplicationsStats represents statistical data about pCloud applications.
type IdsecPCloudApplicationsStats struct {
	ApplicationsCount           int                 `json:"applications_count" mapstructure:"applications_count" flag:"applications-count" desc:"The total number of pCloud applications"`
	DisabledApps                []string            `json:"disabled_apps" mapstructure:"disabled_apps" flag:"disabled-apps" desc:"List of disabled pCloud applications"`
	AuthTypeCount               map[string]int      `json:"auth_type_count" mapstructure:"auth_type_count" flag:"auth-type-count" desc:"Count of authentication methods by type"`
	ApplicationsAuthMethodTypes map[string][]string `json:"applications_auth_method_types" mapstructure:"applications_auth_method_types" flag:"applications-auth-method-types" desc:"Mapping of applications to their authentication method types"`
}
