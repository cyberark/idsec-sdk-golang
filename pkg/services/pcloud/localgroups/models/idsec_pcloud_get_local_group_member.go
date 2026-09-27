// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudGetLocalGroupMember represents the input for retrieving a single membership of a
// Vault local group.
//
// Both fields are required: a membership is identified by the pair, and neither half on its own
// names one.
type IdsecPCloudGetLocalGroupMember struct {
	GroupID    string `json:"group_id"    mapstructure:"group_id"    flag:"group-id"    desc:"ID of the Vault local group"                                          validate:"required"`
	MemberName string `json:"member_name" mapstructure:"member_name" flag:"member-name" desc:"Name of the user or group to retrieve from the group"                validate:"required"`
}
