// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudUserGroup represents the state of a Vault user group.
//
// GroupID is populated from the API's "id" field, which the service normalizes to
// "group_id" so the group's own identifier matches the group_id used by the member models.
//
// There is deliberately no VaultAuthorizations field. A group is read through the filtered list
// endpoint, whose projection carries only the fields below, and there is no per-group GET to ask
// instead, so such a field would decode to nil on every read and report every group as having no
// authorizations at all. IdsecPCloudAddUserGroup leaves them out for the same reason.
type IdsecPCloudUserGroup struct {
	GroupID     int    `json:"group_id"             mapstructure:"group_id"             desc:"Unique numeric ID of the Vault user group"`
	GroupName   string `json:"group_name"           mapstructure:"group_name"           desc:"Name of the Vault user group"`
	Description string `json:"description"          mapstructure:"description"          desc:"Description of the Vault user group"`
	Location    string `json:"location"             mapstructure:"location"             desc:"Vault location of the group, including a leading backslash"`
	GroupType   string `json:"group_type"           mapstructure:"group_type"           desc:"Type of the group as reported by the Vault (Vault or Directory)"`
}
