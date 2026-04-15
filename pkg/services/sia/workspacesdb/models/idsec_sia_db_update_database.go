package models

// IdsecSIADBUpdateDatabase represents the request to update a database.
type IdsecSIADBUpdateDatabase struct {
	ID                                   int               `json:"id,omitempty" mapstructure:"id,omitempty" flag:"id" desc:"The database ID to update."`
	Name                                 string            `json:"name,omitempty" mapstructure:"name,omitempty" flag:"name" desc:"The database name to update."`
	NewName                              string            `json:"new_name,omitempty" mapstructure:"new_name,omitempty" flag:"new-name" desc:"The new name of the database."`
	NetworkName                          string            `json:"network_name,omitempty" mapstructure:"network_name,omitempty" flag:"network-name" desc:"The name of the network where the database resides." default:"ON-PREMISE"`
	Platform                             string            `json:"platform,omitempty" mapstructure:"platform,omitempty" flag:"platform" desc:"The platform where the database resides." choices:"AWS,AZURE,GCP,ON-PREMISE,ATLAS"`
	AuthDatabase                         string            `json:"auth_database" mapstructure:"auth_database" flag:"auth-database" desc:"The authentication database used, most commonly used with MongoDB." default:"admin"`
	Services                             []string          `json:"services,omitempty" mapstructure:"services,omitempty" flag:"services" desc:"The services related to the database, most commonly used with Oracle/SQL-server."`
	Domain                               string            `json:"domain,omitempty" mapstructure:"domain,omitempty" flag:"domain" desc:"The domain where the database resides."`
	DomainControllerName                 string            `json:"domain_controller_name,omitempty" mapstructure:"domain_controller_name,omitempty" flag:"domain-controller-name" desc:"The domain controller name associated with the database."`
	DomainControllerNetbios              string            `json:"domain_controller_netbios,omitempty" mapstructure:"domain_controller_netbios,omitempty" flag:"domain-controller-netbios" desc:"The domain controller netBIOS associated with the database."`
	DomainControllerUseLDAPS             bool              `json:"domain_controller_use_ldaps" mapstructure:"domain_controller_use_ldaps" flag:"domain-controller-use-ldaps" desc:"Indicates whether to work with LDAP secure." default:"false"`
	DomainControllerEnableCertValidation bool              `json:"domain_controller_enable_certificate_validation" mapstructure:"domain_controller_enable_certificate_validation" flag:"domain-controller-enable-certificate-validation" desc:"Indicates whether to enforce certificate validation on TLS comm to the DC." default:"true"`
	DomainControllerLDAPSCertificate     string            `json:"domain_controller_ldaps_certificate,omitempty" mapstructure:"domain_controller_ldaps_certificate,omitempty" flag:"domain-controller-ldaps-certificate" desc:"The certificate ID to use for the domain controller TLS comm."`
	Account                              string            `json:"account,omitempty" mapstructure:"account,omitempty" flag:"account" desc:"The account to use for provider-based databases, such as Atlas."`
	ProviderEngine                       string            `json:"provider_engine,omitempty" mapstructure:"provider_engine,omitempty" flag:"provider-engine" desc:"The provider engine, later deduced to the identifier of the provider."`
	EnableCertificateValidation          bool              `json:"enable_certificate_validation" mapstructure:"enable_certificate_validation" flag:"enable-certificate-validation" desc:"Indicates whether to enable and enforce certificate validation." default:"true"`
	Certificate                          string            `json:"certificate,omitempty" mapstructure:"certificate,omitempty" flag:"certificate" desc:"The certificate ID used for the database that resides in the certificates service."`
	ReadWriteEndpoint                    string            `json:"read_write_endpoint,omitempty" mapstructure:"read_write_endpoint,omitempty" flag:"read-write-endpoint" desc:"The read/write endpoint of the database."`
	ReadOnlyEndpoint                     string            `json:"read_only_endpoint,omitempty" mapstructure:"read_only_endpoint,omitempty" flag:"read-only-endpoint" desc:"An optional read-only endpoint of the database."`
	Port                                 int               `json:"port,omitempty" mapstructure:"port,omitempty" flag:"port" desc:"The port of the database. if not provided, the default is used."`
	SecretID                             string            `json:"secret_id,omitempty" mapstructure:"secret_id,omitempty" flag:"secret-id" desc:"The Secret identifier stored in the Secret Service related to the database."`
	Tags                                 map[string]string `json:"tags,omitempty" mapstructure:"tags,omitempty" flag:"tags" desc:"The tags of the database."`
	ConfiguredAuthMethodType             string            `json:"configured_auth_method_type,omitempty" mapstructure:"configured_auth_method_type,omitempty" flag:"configured-auth-method-type" desc:"The target configured auth method type." choices:"ad_ephemeral_user,local_ephemeral_user,rds_iam_authentication,atlas_ephemeral_user"`
	Region                               string            `json:"region,omitempty" mapstructure:"region,omitempty" flag:"region" desc:"The region of the database, most commonly used with IAM authentication."`
}

// IdsecSIADBUpdateDatabaseTarget represents the request to update a database by the database-onboarding new API.
type IdsecSIADBUpdateDatabaseTarget struct {
	ID                                   string   `json:"id,omitempty" mapstructure:"id,omitempty" flag:"id" desc:"Database id to update"`
	Name                                 string   `json:"name,omitempty" mapstructure:"name,omitempty" flag:"name" desc:"The name of the database, often referenced in policies and other APIs."`
	NewName                              string   `json:"new_name,omitempty" mapstructure:"new_name,omitempty" flag:"new-name" desc:"The new name for the database."`
	Platform                             string   `json:"platform,omitempty" mapstructure:"platform,omitempty" flag:"platform" desc:"The platform where database resides, defaulted to on-premises." default:"ON-PREMISE" choices:"AWS,AZURE,GCP,ON-PREMISE,ATLAS"`
	Region                               string   `json:"region,omitempty" mapstructure:"region,omitempty" flag:"region" desc:"The region of the database, most commonly used with IAM authentication."`
	AuthDatabase                         string   `json:"auth_database,omitempty" mapstructure:"auth_database,omitempty" flag:"auth-database" desc:"The authentication database, most commonly used with MongoDB."`
	Services                             []string `json:"services,omitempty" mapstructure:"services,omitempty" flag:"services" desc:"The services related to the database, most commonly used with Oracle/SQL Server."`
	Domain                               string   `json:"domain,omitempty" mapstructure:"domain,omitempty" flag:"domain" desc:"The domain where database resides."`
	DomainControllerName                 string   `json:"domain_controller_name,omitempty" mapstructure:"domain_controller_name,omitempty" flag:"domain-controller-name" desc:"The domain controller name associated to this database."`
	DomainControllerNetbios              string   `json:"domain_controller_netbios,omitempty" mapstructure:"domain_controller_netbios,omitempty" flag:"domain-controller-netbios" desc:"The domain controller netbios associated to this database."`
	DomainControllerUseLDAPS             bool     `json:"domain_controller_use_ldaps,omitempty" mapstructure:"domain_controller_use_ldaps,omitempty" flag:"domain-controller-use-ldaps" desc:"Indicates whether to work with secure LDAP."`
	DomainControllerEnableCertValidation bool     `json:"domain_controller_enable_certificate_validation,omitempty" mapstructure:"domain_controller_enable_certificate_validation,omitempty" flag:"domain-controller-enable-certificate-validation" desc:"Indicates whether to enforce certificate validation on TLS comm to the DC."`
	DomainControllerLDAPSCertificate     string   `json:"domain_controller_ldaps_certificate,omitempty" mapstructure:"domain_controller_ldaps_certificate,omitempty" flag:"domain-controller-ldaps-certificate" desc:"The certificate ID to use for the domain controller TLS comm."`
	Account                              string   `json:"account,omitempty" mapstructure:"account,omitempty" flag:"account" desc:"The account to be used for provider based databases such as Atlas."`
	ProviderEngine                       string   `json:"provider_engine,omitempty" mapstructure:"provider_engine,omitempty" flag:"provider-engine" desc:"The provider engine, will be later deduced to the identifier of the provider."`
	EnableCertificateValidation          bool     `json:"enable_certificate_validation,omitempty" mapstructure:"enable_certificate_validation,omitempty" flag:"enable-certificate-validation" desc:"Indicates whether to enable and enforce certificate validation."`
	Certificate                          string   `json:"certificate,omitempty" mapstructure:"certificate,omitempty" flag:"certificate" desc:"The certificate ID used for this database that resides in the certificates service."`
	ReadWriteEndpoint                    string   `json:"read_write_endpoint,omitempty" mapstructure:"read_write_endpoint,omitempty" flag:"read-write-endpoint" desc:"The read/write endpoint of the database."`
	ReadOnlyEndpoint                     string   `json:"read_only_endpoint,omitempty" mapstructure:"read_only_endpoint,omitempty" flag:"read-only-endpoint" desc:"The optional read-only endpoint of the database."`
	Port                                 int      `json:"port,omitempty" mapstructure:"port,omitempty" flag:"port" desc:"The port of the database, if not given, the default will be used." validate:"omitempty,min=1,max=65535"`
	SecretID                             string   `json:"secret_id,omitempty" mapstructure:"secret_id,omitempty" flag:"secret-id" desc:"The secret identifier stored in the secret service related to this database."`
	ConfiguredAuthMethodType             string   `json:"configured_auth_method_type,omitempty" mapstructure:"configured_auth_method_type,omitempty" flag:"configured-auth-method-type" desc:"The target configured auth method type." choices:"ad_ephemeral_user,local_ephemeral_user,rds_iam_authentication,atlas_ephemeral_user"`
}
