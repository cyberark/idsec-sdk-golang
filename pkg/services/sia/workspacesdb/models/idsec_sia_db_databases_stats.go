package models

// IdsecSIADBDatabasesStats represents the statistics of database in a workspace.
type IdsecSIADBDatabasesStats struct {
	DatabasesCount                    int            `json:"databases_count" mapstructure:"databases_count" desc:"The overall number of databases."`
	DatabasesWithoutSecretCount       int            `json:"databases_without_secret_count" mapstructure:"databases_without_secret_count" desc:"The number of databases without any attached Secrets."`
	DatabasesWithoutCertificatesCount int            `json:"databases_without_certificates_count" mapstructure:"databases_without_certificates_count" desc:"The number of databases without any attached certificates."`
	DatabasesCountByEngine            map[string]int `json:"databases_count_by_engine" mapstructure:"databases_count_by_engine" desc:"The number of databases per engine type."`
	DatabasesCountByFamily            map[string]int `json:"databases_count_by_family" mapstructure:"databases_count_by_family" desc:"The number of databases per family type."`
	DatabasesCountByWorkspace         map[string]int `json:"databases_count_by_workspace" mapstructure:"databases_count_by_workspace" desc:"The number of databases per workspace type."`
	DatabasesCountByAuthMethod        map[string]int `json:"databases_count_by_auth_method" mapstructure:"databases_count_by_auth_method" desc:"The number of databases per auth type."`
	DatabasesCountByWarning           map[string]int `json:"databases_count_by_warning" mapstructure:"databases_count_by_warning" desc:"The number of databases per warning type."`
}
