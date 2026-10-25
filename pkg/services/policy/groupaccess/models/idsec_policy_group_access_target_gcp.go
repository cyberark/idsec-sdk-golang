package models

// IdsecPolicyGroupAccessGCPTarget represents a single Google (GCP) group target for a group access policy.
//
// Mandatory fields:
//   - GroupID: The ID of the Google group; format: groups/{id} (non-empty).
//   - OrganizationID: The ID of the Google Cloud organization that owns the group, stored for delegation (non-empty).
//
// Read-only fields (populated by API from scanned data, ignored on write):
//   - GroupName: The display name of the group.
//   - OrganizationName: The display name of the Google Cloud organization that owns the group.
//   - Description: The group description.
//
// Example:
//
//	item := IdsecPolicyGroupAccessGCPTarget{
//	  GroupID:        "groups/01234abcde",
//	  OrganizationID: "123456789012",
//	}
//
// Concurrency: Instances are not inherently thread-safe; use per-goroutine copies.
type IdsecPolicyGroupAccessGCPTarget struct { //nolint:revive
	GroupID          string "json:\"group_id\" mapstructure:\"group_id\" flag:\"group-id\" desc:\"ID of the Google group; format: `groups/{id}`\""
	OrganizationID   string `json:"organization_id" mapstructure:"organization_id" flag:"organization-id" desc:"ID of the Google Cloud organization that owns the group"`
	GroupName        string `json:"group_name,omitempty" mapstructure:"group_name,omitempty" flag:"group-name" desc:"Display name of the Google group (read-only)"`
	OrganizationName string `json:"organization_name,omitempty" mapstructure:"organization_name,omitempty" flag:"organization-name" desc:"Display name of the Google Cloud organization that owns the group (read-only)"`
	Description      string `json:"description,omitempty" mapstructure:"description,omitempty" flag:"description" desc:"Group description (read-only)"`
}

// Validate ensures the mandatory write fields are populated.
func (t *IdsecPolicyGroupAccessGCPTarget) Validate() error {
	if t.GroupID == "" || t.OrganizationID == "" {
		return errEmptyMandatoryFields
	}
	return nil
}

// Serialize converts the GCP target into the API write payload. Read-only fields are omitted.
func (t *IdsecPolicyGroupAccessGCPTarget) Serialize() (map[string]interface{}, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"groupId":        t.GroupID,
		"organizationId": t.OrganizationID,
	}, nil
}

// Deserialize populates the GCP target from an API item map, accepting snake_case or camelCase keys.
func (t *IdsecPolicyGroupAccessGCPTarget) Deserialize(data map[string]interface{}) error {
	t.GroupID = targetStringField(data, "group_id", "groupId")
	t.OrganizationID = targetStringField(data, "organization_id", "organizationId")
	t.GroupName = targetStringField(data, "group_name", "groupName")
	t.OrganizationName = targetStringField(data, "organization_name", "organizationName")
	t.Description = targetStringField(data, "description")
	return t.Validate()
}
