package models

// IdsecSIAVMChangeSecret represents the request to change a secret in a VM.
type IdsecSIAVMChangeSecret struct {
	SecretID                                    string `json:"secret_id" mapstructure:"secret_id" flag:"secret-id" desc:"The Secret ID to change." validate:"required"`
	SecretName                                  string `json:"secret_name,omitempty" mapstructure:"secret_name,omitempty" flag:"secret-name" desc:"The new name of the Secret."`
	IsActive                                    *bool  `json:"is_active,omitempty" mapstructure:"is_active,omitempty" flag:"is-active" desc:"Indicates whether the Secret is active."`
	ProvisionerUsername                         string `json:"provisioner_username,omitempty" mapstructure:"provisioner_username,omitempty" flag:"provisioner-username" desc:"If provisioner user type Secret, the new username."`
	ProvisionerPassword                         string `json:"provisioner_password,omitempty" mapstructure:"provisioner_password,omitempty" flag:"provisioner-password" desc:"If provisioner user type Secret, the new password."`
	PCloudAccountSafe                           string `json:"pcloud_account_safe,omitempty" mapstructure:"pcloud_account_safe,omitempty" flag:"pcloud-account-safe" desc:"If Priviledge Cloud account type Secret, the new account Safe."`
	PCloudAccountName                           string `json:"pcloud_account_name,omitempty" mapstructure:"pcloud_account_name,omitempty" flag:"pcloud-account-name" desc:"If Priviledge Cloud account type Secret, the new account name."`
	AccountDomain                               string `json:"account_domain,omitempty" mapstructure:"account_domain,omitempty" flag:"account-domain" desc:"Account domain of the secret (defaults to 'local')."`
	EnableEphemeralDomainUserCreation           *bool  `json:"enable_ephemeral_domain_user_creation,omitempty" mapstructure:"enable_ephemeral_domain_user_creation,omitempty" flag:"enable-ephemeral-domain-user-creation" desc:"Enable creation of ephemeral domain users. Requires account_domain to be set to a non-local domain. Default: false."`
	DomainControllerName                        string `json:"domain_controller_name,omitempty" mapstructure:"domain_controller_name,omitempty" flag:"domain-controller-name" desc:"Domain controller name for ephemeral domain user creation. Default: empty."`
	DomainControllerNetbios                     string `json:"domain_controller_netbios,omitempty" mapstructure:"domain_controller_netbios,omitempty" flag:"domain-controller-netbios" desc:"Domain controller NetBIOS name for ephemeral domain user creation. Default: empty."`
	EphemeralDomainUserLocation                 string `json:"ephemeral_domain_user_location,omitempty" mapstructure:"ephemeral_domain_user_location,omitempty" flag:"ephemeral-domain-user-location" desc:"OU path for ephemeral domain user creation. Default: empty."`
	DomainControllerUseLdaps                    *bool  `json:"domain_controller_use_ldaps,omitempty" mapstructure:"domain_controller_use_ldaps,omitempty" flag:"domain-controller-use-ldaps" desc:"Use LDAPS for the domain controller. Default: true."`
	DomainControllerEnableCertificateValidation *bool  `json:"domain_controller_enable_certificate_validation,omitempty" mapstructure:"domain_controller_enable_certificate_validation,omitempty" flag:"domain-controller-enable-certificate-validation" desc:"Enable certificate validation for domain controller LDAPS. Requires domain-controller-use-ldaps and domain-controller-ldaps-certificate. Default: false."`
	DomainControllerLdapsCertificate            string `json:"domain_controller_ldaps_certificate,omitempty" mapstructure:"domain_controller_ldaps_certificate,omitempty" flag:"domain-controller-ldaps-certificate" desc:"LDAPS certificate ID for domain controller. Default: empty."`
	UseWinrmForHTTPS                            *bool  `json:"use_winrm_for_https,omitempty" mapstructure:"use_winrm_for_https,omitempty" flag:"use-winrm-for-https" desc:"Use WinRM over HTTPS. Default: true."`
	WinrmEnableCertificateValidation            *bool  `json:"winrm_enable_certificate_validation,omitempty" mapstructure:"winrm_enable_certificate_validation,omitempty" flag:"winrm-enable-certificate-validation" desc:"Enable certificate validation for WinRM. Requires use-winrm-for-https and winrm-certificate. Default: false."`
	WinrmCertificate                            string `json:"winrm_certificate,omitempty" mapstructure:"winrm_certificate,omitempty" flag:"winrm-certificate" desc:"WinRM certificate ID. Default: empty."`
}
