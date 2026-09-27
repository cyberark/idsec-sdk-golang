// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudLocalGroup represents the state of a Vault local group.
//
// GroupID is populated from the API's "id" field. GroupName, Description, and Location are the
// mutable fields; CreatedTime and LastModifiedTime are read-only timestamps reported by the Vault.
type IdsecPCloudLocalGroup struct {
	GroupID          string `json:"group_id"           mapstructure:"group_id"           desc:"Unique ID of the Vault local group"`
	GroupName        string `json:"group_name"          mapstructure:"group_name"         desc:"Name of the Vault local group"`
	Description      string `json:"description"         mapstructure:"description"        desc:"Description of the Vault local group"`
	Location         string `json:"location"            mapstructure:"location"           desc:"Vault location of the group, including a leading backslash"`
	GroupType        string `json:"group_type"          mapstructure:"group_type"         desc:"Type of the group as reported by the Vault"`
	CreatedTime      int64  `json:"created_time"        mapstructure:"created_time"       desc:"Unix timestamp when the group was created"`
	LastModifiedTime int64  `json:"last_modified_time"  mapstructure:"last_modified_time" desc:"Unix timestamp of the last modification to the group"`
}
