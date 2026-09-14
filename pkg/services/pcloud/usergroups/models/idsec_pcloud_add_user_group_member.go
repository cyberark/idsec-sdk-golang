// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudAddUserGroupMember represents the input for adding a member to a Vault user group
// via POST /PasswordVault/API/UserGroups/{groupId}/Members.
//
// The group is addressed by its numeric ID, but the member is addressed by name: the request's
// "memberId" field carries the Vault user name or the name of a nested group, not a number. The
// numeric member ID only ever comes back in the response.
type IdsecPCloudAddUserGroupMember struct {
	GroupID    int    `json:"group_id"    mapstructure:"group_id"    flag:"group-id"    desc:"Numeric ID of the Vault user group"                                    validate:"required"`
	MemberName string `json:"member_name" mapstructure:"member_name" flag:"member-name" desc:"Vault user name, or name of the nested group, to add to the group"     validate:"required"`
	MemberType string `json:"member_type" mapstructure:"member_type" flag:"member-type" desc:"Type of the member being added (Vault or Domain)"                      validate:"required" choices:"Vault,Domain"`
}
