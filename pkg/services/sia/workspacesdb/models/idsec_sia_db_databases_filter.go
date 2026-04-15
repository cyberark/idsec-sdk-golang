package models

// IdsecSIADBDatabasesFilter represents the filter criteria for retrieving databases in a workspace.
type IdsecSIADBDatabasesFilter struct {
	Name              string          `json:"name,omitempty" mapstructure:"name,omitempty" flag:"name" desc:"The name of the database by which to filter."`
	ProviderFamily    string          `json:"provider_family,omitempty" mapstructure:"provider_family,omitempty" flag:"provider-family" desc:"The family by which to filter the list." choices:"Postgres,Oracle,MSSQL,MySQL,MariaDB,DB2,Mongo,Cassandra,Unknown"`
	ProviderEngine    string          `json:"provider_engine,omitempty" mapstructure:"provider_engine,omitempty" flag:"provider-engine" desc:"The engine by which to filter the list."`
	ProviderWorkspace string          `json:"provider_workspace,omitempty" mapstructure:"provider_workspace,omitempty" flag:"provider-workspace" desc:"The workspace by which to filter the list." choices:"AWS,AZURE,GCP,ON-PREMISE,ATLAS"`
	AuthMethods       []string        `json:"auth_methods,omitempty" mapstructure:"auth_methods,omitempty" flag:"auth-methods" desc:"The auth method types by which to filter the list." choices:"ad_ephemeral_user,local_ephemeral_user,rds_iam_authentication,atlas_ephemeral_user"`
	Tags              []IdsecSIADBTag `json:"tags,omitempty" mapstructure:"tags,omitempty" flag:"tags" desc:"The tags by which to filter the list."`
	DBWarningsFilter  string          `json:"db_warnings_filter,omitempty" mapstructure:"db_warnings_filter,omitempty" flag:"db-warnings-filter" desc:"Filter by databases with warnings / incomplete." choices:"no_certificates,no_secrets,any_error"`
}

// IdsecSIADBDatabaseTargetsFilter represents the filter criteria for retrieving databases in a workspace, by the database-onboarding new API.
type IdsecSIADBDatabaseTargetsFilter struct {
	Name              string          `json:"name,omitempty" mapstructure:"name,omitempty" flag:"name" desc:"The name of the database by which to filter."`
	ProviderFamily    string          `json:"provider_family,omitempty" mapstructure:"provider_family,omitempty" flag:"provider-family" desc:"The family by which to filter the list." choices:"Postgres,Oracle,MSSQL,MySQL,MariaDB,DB2,Mongo,Cassandra,Unknown"`
	ProviderEngine    string          `json:"provider_engine,omitempty" mapstructure:"provider_engine,omitempty" flag:"provider-engine" desc:"The engine by which to filter the list."`
	ProviderWorkspace string          `json:"provider_workspace,omitempty" mapstructure:"provider_workspace,omitempty" flag:"provider-workspace" desc:"The workspace by which to filter the list." choices:"AWS,AZURE,GCP,ON-PREMISE,ATLAS"`
	AuthMethods       []string        `json:"auth_methods,omitempty" mapstructure:"auth_methods,omitempty" flag:"auth-methods" desc:"The auth method types by which to filter the list." choices:"ad_ephemeral_user,local_ephemeral_user,rds_iam_authentication,atlas_ephemeral_user"`
	Tags              []IdsecSIADBTag `json:"tags,omitempty" mapstructure:"tags,omitempty" flag:"tags" desc:"The tags by which to filter the list."`
	DBWarningsFilter  string          `json:"db_warnings_filter,omitempty" mapstructure:"db_warnings_filter,omitempty" flag:"db-warnings-filter" desc:"Filter by databases with warnings / incomplete." choices:"no_certificates,no_secrets,any_error"`
	Limit             int             `json:"limit,omitempty" mapstructure:"limit,omitempty" flag:"limit" desc:"Indicates whether to limit the number of results returned." validate:"omitempty,min=1,max=1000"`
	Cursor            string          `json:"cursor,omitempty" mapstructure:"cursor,omitempty" flag:"cursor" desc:"Cursor for pagination."`
}
