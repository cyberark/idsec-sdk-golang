package models

// DatabasesFamiliesToDefaultAuthMethod is a map of database family types to their default authentication methods.
var DatabasesFamiliesToDefaultAuthMethod = map[string]string{
	FamilyTypePostgres: LocalEphemeralUser,
	FamilyTypeOracle:   LocalEphemeralUser,
	FamilyTypeMSSQL:    ADEphemeralUser,
	FamilyTypeMySQL:    LocalEphemeralUser,
	FamilyTypeMariaDB:  LocalEphemeralUser,
	FamilyTypeDB2:      ADEphemeralUser,
	FamilyTypeMongo:    LocalEphemeralUser,
}

// Possible database authentication methods
const (
	ADEphemeralUser        string = "ad_ephemeral_user"
	LocalEphemeralUser     string = "local_ephemeral_user"
	RDSIAMAuthentication   string = "rds_iam_authentication"
	AtlasEphemeralUser     string = "atlas_ephemeral_user"
	CassandraEphemeralUser string = "cassandra_ephemeral_user"
)

// IdsecSIADBAuthMethod represents the authentication method used for a database target.
type IdsecSIADBAuthMethod struct {
	ID             int      `json:"id" mapstructure:"id" flag:"id" desc:"The ID of the authentication method on the database."`
	AuthMethodType string   `json:"auth_method_type" mapstructure:"auth_method_type" flag:"auth-method-type" desc:"The type / name of the authentication method." choices:"ad_ephemeral_user,local_ephemeral_user,rds_iam_authentication,atlas_ephemeral_user"`
	Description    string   `json:"description" mapstructure:"description" flag:"description" desc:"The description of the authentication method."`
	Workspaces     []string `json:"workspaces" mapstructure:"workspaces" flag:"workspaces" desc:"The workspaces in which this authentication method is used."`
}

// IdsecSIADBDatabaseAuthMethod represents the relation between a database type and an authentication method.
type IdsecSIADBDatabaseAuthMethod struct {
	ID             int                  `json:"id" mapstructure:"id" flag:"id" desc:"The ID of the relation between the authentication method and the database type."`
	ProviderFamily string               `json:"provider_family" mapstructure:"provider_family" flag:"provider-family" desc:"The name of the database family for which this authentication method is used." choices:"Postgres,Oracle,MSSQL,MySQL,MariaDB,DB2,Mongo,Cassandra,Unknown"`
	AuthMethod     IdsecSIADBAuthMethod `json:"auth_method" mapstructure:"auth_method" flag:"auth-method" desc:"The actual authentication method."`
	MethodEnabled  bool                 `json:"method_enabled" mapstructure:"method_enabled" flag:"method-enabled" desc:"Indicates whether this authentication method is enabled."`
}

// IdsecSIADBDatabaseTargetConfiguredAuthMethod represents the relation between a database target and a configured authentication method.
type IdsecSIADBDatabaseTargetConfiguredAuthMethod struct {
	DatabaseAuthMethod     IdsecSIADBDatabaseAuthMethod `json:"database_auth_method" mapstructure:"database_auth_method" flag:"database-auth-method" desc:"The identifier for the configured auth method."`
	DatabaseTargetID       int                          `json:"database_target_id" mapstructure:"database_target_id" flag:"database-target-id" desc:"The database target identifier."`
	ConfiguredAuthMethodID int                          `json:"configured_auth_method_id,omitempty" mapstructure:"configured_auth_method_id,omitempty" flag:"configured-auth-method-id" desc:"The configured auth method ID for the target."`
}
