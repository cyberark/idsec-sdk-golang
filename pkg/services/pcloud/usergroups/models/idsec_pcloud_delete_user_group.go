// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudDeleteUserGroup represents the input for deleting a Vault user group
// via DELETE /PasswordVault/API/UserGroups/{groupId}.
type IdsecPCloudDeleteUserGroup struct {
	GroupID int `json:"group_id" mapstructure:"group_id" flag:"group-id" desc:"Numeric ID of the Vault user group to delete" validate:"required"`
}
