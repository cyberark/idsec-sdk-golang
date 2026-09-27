// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudAddLocalGroup represents the input for creating a Vault local group
// via POST /PasswordVault/API/UserGroups.
type IdsecPCloudAddLocalGroup struct {
	GroupName   string `json:"group_name"            mapstructure:"group_name"  flag:"group-name"  desc:"Name of the Vault local group to create"                               validate:"required" maxlength:"255"`
	Description string `json:"description,omitempty" mapstructure:"description" flag:"description" desc:"Description of the Vault local group"                                   maxlength:"100"`
	Location    string `json:"location,omitempty"    mapstructure:"location"    flag:"location"    desc:"Vault location to create the group in, including a leading backslash"`
}
