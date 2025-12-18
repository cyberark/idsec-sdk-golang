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
type IdsecSIAVMSecret struct {
	SecretID      string                 `json:"secret_id" mapstructure:"secret_id" flag:"secret-id" desc:"ID of the secret"`
	TenantID      string                 `json:"tenant_id,omitempty" mapstructure:"tenant_id,omitempty" flag:"tenant-id" desc:"Tenant ID of the secret"`
	Secret        IdsecSIAVMSecretData     `json:"secret,omitempty" mapstructure:"secret,omitempty" flag:"secret" desc:"Secret itself"`
	SecretType    string                 `json:"secret_type" mapstructure:"secret_type" flag:"secret-type" desc:"Type of the secret" choices:"ProvisionerUser,PCloudAccount"`
	SecretDetails string             `json:"secret_details" mapstructure:"secret_details" flag:"secret-details" desc:"Secret extra details as JSON string"`
	IsActive      bool                   `json:"is_active" mapstructure:"is_active" flag:"is-active" desc:"Whether this secret is active or not and can be retrieved or modified"`
	IsRotatable   bool                   `json:"is_rotatable" mapstructure:"is_rotatable" flag:"is-rotatable" desc:"Whether this secret can be rotated"`
	CreationTime  string                 `json:"creation_time" mapstructure:"creation_time" flag:"creation-time" desc:"Creation time of the secret"`
	LastModified  string                 `json:"last_modified" mapstructure:"last_modified" flag:"last-modified" desc:"Last time the secret was modified"`
	SecretName    string                 `json:"secret_name,omitempty" mapstructure:"secret_name,omitempty" flag:"secret-name" desc:"A friendly name label"`
}
```

All models can be found [here](https://github.com/cyberark/idsec-sdk-golang/tree/main/pkg/models), and are separated into folders according to type.
