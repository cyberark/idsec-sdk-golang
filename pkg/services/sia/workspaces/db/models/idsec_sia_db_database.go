package models

// IdsecSIADBDatabase represents a response when adding / getting a database target.
type IdsecSIADBDatabase struct {
	ID                                          int                                          `json:"id,omitempty" mapstructure:"id,omitempty" flag:"id" desc:"The ID of the database target that can be referenced in operations."`
	Name                                        string                                       `json:"name" mapstructure:"name" flag:"name" desc:"The name of the database, often referenced in policies and other APIs."`
	NetworkName                                 string                                       `json:"network_name" mapstructure:"network_name" flag:"network-name" desc:"The name of the network where the database resides."`
	Platform                                    string                                       `json:"platform,omitempty" mapstructure:"platform,omitempty" flag:"platform" desc:"The platform where the database resides." choices:"AWS,AZURE,GCP,ON-PREMISE,ATLAS"`
	AuthDatabase                                string                                       `json:"auth_database" mapstructure:"auth_database" flag:"auth-database" desc:"The authentication database used, most commonly used with MongoDB."`
	Services                                    []string                                     `json:"services" mapstructure:"services" flag:"services" desc:"The services related to the database, most commonly used with Oracle/SQL-server."`
	Domain                                      string                                       `json:"domain,omitempty" mapstructure:"domain,omitempty" flag:"domain" desc:"The domain where the database resides."`
	DomainControllerName                        string                                       `json:"domain_controller_name,omitempty" mapstructure:"domain_controller_name,omitempty" flag:"domain-controller-name" desc:"The domain controller name associated with the database."`
	DomainControllerNetbios                     string                                       `json:"domain_controller_netbios,omitempty" mapstructure:"domain_controller_netbios,omitempty" flag:"domain-controller-netbios" desc:"The domain controller netBIOS associated with the database."`
	DomainControllerUseLdaps                    bool                                         `json:"domain_controller_use_ldaps" mapstructure:"domain_controller_use_ldaps" flag:"domain-controller-use-ldaps" desc:"Indicates whether to work with LDAP secure."`
	DomainControllerEnableCertificateValidation bool                                         `json:"domain_controller_enable_certificate_validation" mapstructure:"domain_controller_enable_certificate_validation" flag:"domain-controller-enable-certificate-validation" desc:"Indicates whether to enforce certificate validation on TLS comm to the DC."`
	DomainControllerLdapsCertificate            string                                       `json:"domain_controller_ldaps_certificate,omitempty" mapstructure:"domain_controller_ldaps_certificate,omitempty" flag:"domain-controller-ldaps-certificate" desc:"The certificate ID to use for the domain controller TLS comm."`
	Account                                     string                                       `json:"account,omitempty" mapstructure:"account,omitempty" flag:"account" desc:"The account to use for provider-based databases, such as Atlas."`
	EnableCertificateValidation                 bool                                         `json:"enable_certificate_validation" mapstructure:"enable_certificate_validation" flag:"enable-certificate-validation" desc:"Indicates whether to enable and enforce certificate validation."`
	ProviderDetails                             IdsecSIADBDatabaseProvider                   `json:"provider_details,omitempty" mapstructure:"provider_details,omitempty" flag:"provider-details" desc:"The provider details related to the database."`
	Certificate                                 string                                       `json:"certificate,omitempty" mapstructure:"certificate,omitempty" flag:"certificate" desc:"The certificate ID used for the database that resides in the certificates service."`
	ReadWriteEndpoint                           string                                       `json:"read_write_endpoint,omitempty" mapstructure:"read_write_endpoint,omitempty" flag:"read-write-endpoint" desc:"The read/write endpoint of the database."`
	ReadOnlyEndpoint                            string                                       `json:"read_only_endpoint,omitempty" mapstructure:"read_only_endpoint,omitempty" flag:"read-only-endpoint" desc:"An optional read-only endpoint of the database."`
	Port                                        int                                          `json:"port,omitempty" mapstructure:"port,omitempty" flag:"port" desc:"The port of the database. if not provided, the default is used."`
	SecretID                                    string                                       `json:"secret_id,omitempty" mapstructure:"secret_id,omitempty" flag:"secret-id" desc:"The Secret identifier stored in the Secret Service related to the database."`
	Tags                                        map[string]string                            `json:"tags,omitempty" mapstructure:"tags,omitempty" flag:"tags" desc:"The tags of the database."`
	ConfiguredAuthMethod                        IdsecSIADBDatabaseTargetConfiguredAuthMethod `json:"configured_auth_method,omitempty" mapstructure:"configured_auth_method,omitempty" flag:"configured-auth-method" desc:"The target configured auth method."`
	Region                                      string                                       `json:"region,omitempty" mapstructure:"region,omitempty" flag:"region" desc:"The region of the database, most commonly used with IAM authentication."`
}

// IdsecSIADBDatabaseTarget represents a response when adding / getting a database target by the database-onboarding new API.
type IdsecSIADBDatabaseTarget struct {
	ID                                   string   `json:"id,omitempty" mapstructure:"id,omitempty" flag:"id" desc:"The ID of the database target that can be referenced in operations."`
	Name                                 string   `json:"name" mapstructure:"name" flag:"name" desc:"The name of the database, often referenced in policies and other APIs."`
	Platform                             string   `json:"platform,omitempty" mapstructure:"platform,omitempty" flag:"platform" desc:"The platform where the database resides." choices:"AWS,AZURE,GCP,ON-PREMISE,ATLAS"`
	Region                               string   `json:"region,omitempty" mapstructure:"region,omitempty" flag:"region" desc:"Region of the database, most commonly used with IAM authentication"`
	AuthDatabase                         string   `json:"auth_database" mapstructure:"auth_database" flag:"auth-database" desc:"Authentication database used, most commonly used with mongodb"`
	Services                             []string `json:"services" mapstructure:"services" flag:"services" desc:"The services related to the database, most commonly used with Oracle/SQL Server."`
	Domain                               string   `json:"domain,omitempty" mapstructure:"domain,omitempty" flag:"domain" desc:"The domain the DB resides in"`
	DomainControllerName                 string   `json:"domain_controller_name,omitempty" mapstructure:"domain_controller_name,omitempty" flag:"domain-controller-name" desc:"Domain controller name associated to this database"`
	DomainControllerNetbios              string   `json:"domain_controller_netbios,omitempty" mapstructure:"domain_controller_netbios,omitempty" flag:"domain-controller-netbios" desc:"Domain controller netbios associated to this database"`
	DomainControllerUseLDAPS             bool     `json:"domain_controller_use_ldaps" mapstructure:"domain_controller_use_ldaps" flag:"domain-controller-use-ldaps" desc:"Whether to work with LDAP secure or not"`
	DomainControllerEnableCertValidation bool     `json:"domain_controller_enable_certificate_validation" mapstructure:"domain_controller_enable_certificate_validation" flag:"domain-controller-enable-certificate-validation" desc:"Whether to enforce certificate validation on TLS comm to the DC"`
	DomainControllerLDAPSCertificate     string   `json:"domain_controller_ldaps_certificate,omitempty" mapstructure:"domain_controller_ldaps_certificate,omitempty" flag:"domain-controller-ldaps-certificate" desc:"Certificate id to use for the domain controller TLS comm"`
	Account                              string   `json:"account,omitempty" mapstructure:"account,omitempty" flag:"account" desc:"Account to be used for provider based databases such as atlas"`
	ProviderEngine                       string   `json:"provider_engine,omitempty" mapstructure:"provider_engine,omitempty" flag:"provider-engine" desc:"The provider engine, will be later deduced to the identifier of the provider."`
	EnableCertificateValidation          bool     `json:"enable_certificate_validation" mapstructure:"enable_certificate_validation" flag:"enable-certificate-validation" desc:"Indicates whether to enable and enforce certificate validation."`
	Certificate                          string   `json:"certificate,omitempty" mapstructure:"certificate,omitempty" flag:"certificate" desc:"The certificate ID used for this database that resides in the certificates service."`
	ReadWriteEndpoint                    string   `json:"read_write_endpoint,omitempty" mapstructure:"read_write_endpoint,omitempty" flag:"read-write-endpoint" desc:"The read/write endpoint of the database."`
	ReadOnlyEndpoint                     string   `json:"read_only_endpoint,omitempty" mapstructure:"read_only_endpoint,omitempty" flag:"read-only-endpoint" desc:"The optional read-only endpoint of the database."`
	Port                                 int      `json:"port,omitempty" mapstructure:"port,omitempty" flag:"port" desc:"The port of the database, if not given, the default one will be used."`
	SecretID                             string   `json:"secret_id,omitempty" mapstructure:"secret_id,omitempty" flag:"secret-id" desc:"The secret identifier stored in the secret service related to this database."`
	ConfiguredAuthMethodType             string   `json:"configured_auth_method_type,omitempty" mapstructure:"configured_auth_method_type,omitempty" flag:"configured-auth-method-type" desc:"The target configured auth method type."`
	Family                               string   `json:"family,omitempty" mapstructure:"family,omitempty" flag:"family" desc:"The family of the database provider."`
}
