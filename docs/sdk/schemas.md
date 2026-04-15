---
title: Schemas
description: Schemas
---

# Schemas

Idsec SDK is entirely based on schemas constructed from standard Golang structs, along with the tagging of `json` and `mapstructure` values for serialization.

All `exec` actions in the Idsec SDK receive a model parsed from the CLI or SDK in code and, some of them, return a model or set of models.

## Example

Any request can be called with a defined model, for example:

```go
secret, err := siaAPI.SecretsVM().AddSecret(
    &vmsecretsmodels.IdsecSIAVMAddSecret{
        SecretType:          "ProvisionerUser",
        ProvisionerUsername: "CoolUser",
        ProvisionerPassword: "CoolPassword",
    },
)
```

The above example creates a VM secret service and calls `AddSecret()` to add a new VM secret. The add secret schema is passed, and a result schema for the secret is returned:

```go
// IdsecSIAVMSecret represents a secret in the Idsec SIA VM.
// Flattened fields (account_domain, ephemeral_domain_user_data, etc.) are populated from the API's secret_details by the service layer.
type IdsecSIAVMSecret struct {
	SecretID      string              `json:"secret_id" mapstructure:"secret_id" flag:"secret-id" desc:"ID of the secret"`
	TenantID      string              `json:"tenant_id,omitempty" mapstructure:"tenant_id,omitempty" flag:"tenant-id" desc:"Tenant ID of the secret"`
	Secret        IdsecSIAVMSecretData `json:"secret,omitempty" mapstructure:"secret,omitempty" flag:"secret" desc:"Secret itself"`
	SecretType    string              `json:"secret_type" mapstructure:"secret_type" flag:"secret-type" desc:"Type of the secret" choices:"ProvisionerUser,PCloudAccount"`
	IsActive      bool                `json:"is_active" mapstructure:"is_active" flag:"is-active" desc:"Whether this secret is active or not and can be retrieved or modified"`
	IsRotatable   bool                `json:"is_rotatable" mapstructure:"is_rotatable" flag:"is-rotatable" desc:"Whether this secret can be rotated"`
	CreationTime  string              `json:"creation_time" mapstructure:"creation_time" flag:"creation-time" desc:"Creation time of the secret"`
	LastModified  string              `json:"last_modified" mapstructure:"last_modified" flag:"last-modified" desc:"Last time the secret was modified"`
	SecretName    string              `json:"secret_name,omitempty" mapstructure:"secret_name,omitempty" flag:"secret-name" desc:"A friendly name label"`

	// Fields for create/update operations (matching IdsecSIAVMAddSecret and IdsecSIAVMChangeSecret)
	ProvisionerUsername string `json:"provisioner_username,omitempty" mapstructure:"provisioner_username,omitempty" flag:"provisioner-username" desc:"If provisioner user type is selected, the username."`
	ProvisionerPassword string `json:"provisioner_password,omitempty" mapstructure:"provisioner_password,omitempty" flag:"provisioner-password" desc:"If provisioner user type is selected, the password."`
	PCloudAccountSafe   string `json:"pcloud_account_safe,omitempty" mapstructure:"pcloud_account_safe,omitempty" flag:"pcloud-account-safe" desc:"If Priviledge Cloud account type is selected, the account Safe."`
	PCloudAccountName   string `json:"pcloud_account_name,omitempty" mapstructure:"pcloud_account_name,omitempty" flag:"pcloud-account-name" desc:"If Priviledge Cloud account type is selected, the account name."`

	// Ephemeral domain user fields (flattened from secret_details)
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
```

All models can be found [here](https://github.com/cyberark/idsec-sdk-golang/tree/main/pkg/models), and are separated into folders according to type.
