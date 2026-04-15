package models

// IdsecSIADBStrongAccountsFilter represents client-side filter parameters for listing strong accounts.
type IdsecSIADBStrongAccountsFilter struct {
	StoreType string `json:"store_type,omitempty" mapstructure:"store_type" flag:"store-type" desc:"Filter by store type (pam or managed)." choices:"pam,managed"`
	Platform  string `json:"platform,omitempty" mapstructure:"platform" flag:"platform" desc:"Filter by platform." choices:"PostgreSQL,MySQL,MariaDB,MSSql,Oracle,MongoDB,DB2UnixSSH,WinDomain,AWSAccessKeys"`
	Name      string `json:"name,omitempty" mapstructure:"name" flag:"name" desc:"Filter by account name (regex pattern)."`
}
