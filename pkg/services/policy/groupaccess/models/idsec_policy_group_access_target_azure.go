package models

// IdsecPolicyGroupAccessAzureTarget represents a single Entra ID (Azure) group target for a group access policy.
//
// Mandatory fields:
//   - GroupID: The unique identifier (UUID) of the Entra group (non-empty).
//   - DirectoryID: The Entra ID tenant (directory) ID containing the group (non-empty).
//
// Read-only fields (populated by API):
//   - GroupName: The display name of the group.
//   - GroupType: The type of the group (e.g. security, microsoft365).
//   - DirectoryName: The Entra ID directory display name.
//   - Description: The group description.
//
// JSON & mapstructure tags use snake_case to integrate with existing camelCase conversion utilities.
// flag / desc tags enable CLI flag generation and inline documentation.
//
// Example:
//
//	item := IdsecPolicyGroupAccessAzureTarget{
//	  GroupID:     "75657604-6af0-48ce-b6fc-3a7e72b27524",
//	  DirectoryID: "c5a5de91-6a2f-467e-aefa-b3f62876ec6a",
//	  GroupName:   "gilad_group_cybrsca",
//	  GroupType:   "security",
//	  DirectoryName: "AzureAD Directory",
//	  Description:   "Contractors group",
//	}
//
// Concurrency: Instances are not inherently thread-safe; use per-goroutine copies.
type IdsecPolicyGroupAccessAzureTarget struct { //nolint:revive
	GroupID       string `json:"group_id" mapstructure:"group_id" flag:"group-id" desc:"Entra Group ID (UUID)"`
	DirectoryID   string `json:"directory_id" mapstructure:"directory_id" flag:"directory-id" desc:"Entra ID Directory ID (UUID)"`
	GroupName     string `json:"group_name,omitempty" mapstructure:"group_name,omitempty" flag:"group-name" desc:"Display name of the Entra group (read-only)"`
	GroupType     string `json:"group_type,omitempty" mapstructure:"group_type,omitempty" flag:"group-type" desc:"Type of the Entra group, e.g. security, microsoft365 (read-only)"`
	DirectoryName string `json:"directory_name,omitempty" mapstructure:"directory_name,omitempty" flag:"directory-name" desc:"Entra ID Directory display name (read-only)"`
	Description   string `json:"description,omitempty" mapstructure:"description,omitempty" flag:"description" desc:"Group description (read-only)"`
}

// IdsecPolicyGroupAccessTargetItem is the original name of IdsecPolicyGroupAccessAzureTarget, kept for backward compatibility.
type IdsecPolicyGroupAccessTargetItem = IdsecPolicyGroupAccessAzureTarget //nolint:revive

// Validate ensures the mandatory write fields are populated.
func (t *IdsecPolicyGroupAccessAzureTarget) Validate() error {
	if t.GroupID == "" || t.DirectoryID == "" {
		return errEmptyMandatoryFields
	}
	return nil
}

// Serialize converts the Azure target into the API write payload. Read-only fields are omitted.
func (t *IdsecPolicyGroupAccessAzureTarget) Serialize() (map[string]interface{}, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"groupId":     t.GroupID,
		"directoryId": t.DirectoryID,
	}, nil
}

// Deserialize populates the Azure target from an API item map, accepting snake_case or camelCase keys.
func (t *IdsecPolicyGroupAccessAzureTarget) Deserialize(data map[string]interface{}) error {
	t.GroupID = targetStringField(data, "group_id", "groupId")
	t.DirectoryID = targetStringField(data, "directory_id", "directoryId")
	t.GroupName = targetStringField(data, "group_name", "groupName")
	t.GroupType = targetStringField(data, "group_type", "groupType")
	t.DirectoryName = targetStringField(data, "directory_name", "directoryName")
	t.Description = targetStringField(data, "description")
	return t.Validate()
}
