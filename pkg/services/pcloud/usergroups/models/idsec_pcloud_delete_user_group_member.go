// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudDeleteUserGroupMember represents the input for removing a member from a Vault user
// group via DELETE /PasswordVault/API/UserGroups/{groupId}/Members/{memberName}.
//
// The final path segment is the member's name, not the numeric member ID: the group is the only
// part of the route addressed by number.
type IdsecPCloudDeleteUserGroupMember struct {
	GroupID    int    `json:"group_id"    mapstructure:"group_id"    flag:"group-id"    desc:"Numeric ID of the Vault user group"                                       validate:"required"`
	MemberName string `json:"member_name" mapstructure:"member_name" flag:"member-name" desc:"Vault user name, or name of the nested group, to remove from the group"    validate:"required"`
}
