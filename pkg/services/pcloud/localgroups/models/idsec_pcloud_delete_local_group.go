// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudDeleteLocalGroup represents the input for deleting a Vault local group
// via DELETE /PasswordVault/API/UserGroups/{groupId}.
type IdsecPCloudDeleteLocalGroup struct {
	GroupID string `json:"group_id" mapstructure:"group_id" flag:"group-id" desc:"ID of the Vault local group to delete" validate:"required"`
}
