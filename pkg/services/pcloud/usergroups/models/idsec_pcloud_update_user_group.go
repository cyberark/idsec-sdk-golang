// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudUpdateUserGroup represents the input for updating a Vault user group
// via PUT /PasswordVault/API/UserGroups/{groupId}.
type IdsecPCloudUpdateUserGroup struct {
	GroupID     int    `json:"group_id"     mapstructure:"group_id"     flag:"group-id"     desc:"Numeric ID of the Vault user group" validate:"required"`
	GroupName   string `json:"group_name"   mapstructure:"group_name"   flag:"group-name"   desc:"Name of the Vault user group"        validate:"required"`
	Description string `json:"description"  mapstructure:"description"  flag:"description"  desc:"Description of the Vault user group"`
	Location    string `json:"location"     mapstructure:"location"     flag:"location"     desc:"Location of the group in the Vault"`
}
