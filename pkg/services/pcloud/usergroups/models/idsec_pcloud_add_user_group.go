// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudAddUserGroup represents the input for creating a Vault user group
// via POST /PasswordVault/API/UserGroups.
//
// The optional fields are omitted from the request when empty so the Vault applies its own
// defaults instead of receiving an empty location.
//
// The group's vault authorizations are deliberately not part of this input. They are not needed
// to create a group, and nothing in the group lifecycle can read them back: a group is read
// through the filtered list endpoint, whose projection does not carry them, and there is no
// per-group GET to ask instead. Accepting them here would mean writing a grant that neither the
// SDK nor its callers could ever verify or report drift on.
type IdsecPCloudAddUserGroup struct {
	GroupName   string `json:"group_name"            mapstructure:"group_name"  flag:"group-name"  desc:"Name of the Vault user group to create"                              validate:"required"`
	Description string `json:"description,omitempty" mapstructure:"description" flag:"description" desc:"Description of the Vault user group"`
	Location    string `json:"location,omitempty"    mapstructure:"location"    flag:"location"    desc:"Vault location to create the group in, including a leading backslash"`
}
