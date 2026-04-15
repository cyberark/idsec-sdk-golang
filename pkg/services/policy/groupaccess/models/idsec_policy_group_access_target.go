package models

import "fmt"

// IdsecPolicyGroupAccessTargetItem represents a single Entra group target for an Entra group assignment policy (groupaccess).
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
//	item := IdsecPolicyGroupAccessTargetItem{
//	  GroupID:     "75657604-6af0-48ce-b6fc-3a7e72b27524",
//	  DirectoryID: "c5a5de91-6a2f-467e-aefa-b3f62876ec6a",
//	  GroupName:   "gilad_group_cybrsca",
//	  GroupType:   "security",
//	  DirectoryName: "AzureAD Directory",
//	  Description:   "Contractors group",
//	}
//
// Concurrency: Instances are not inherently thread-safe; use per-goroutine copies.
type IdsecPolicyGroupAccessTargetItem struct { //nolint:revive
	GroupID       string `json:"group_id" mapstructure:"group_id" flag:"group-id" desc:"Entra Group ID (UUID)"`
	DirectoryID   string `json:"directory_id" mapstructure:"directory_id" flag:"directory-id" desc:"Entra ID Directory ID (UUID)"`
	GroupName     string `json:"group_name,omitempty" mapstructure:"group_name,omitempty" flag:"group-name" desc:"Display name of the Entra group (read-only)"`
	GroupType     string `json:"group_type,omitempty" mapstructure:"group_type,omitempty" flag:"group-type" desc:"Type of the Entra group, e.g. security, microsoft365 (read-only)"`
	DirectoryName string `json:"directory_name,omitempty" mapstructure:"directory_name,omitempty" flag:"directory-name" desc:"Entra ID Directory display name (read-only)"`
	Description   string `json:"description,omitempty" mapstructure:"description,omitempty" flag:"description" desc:"Group description (read-only)"`
}

// IdsecPolicyGroupAccessTarget is a wrapper holding a list of group target items.
//
// Fields:
//   - Targets: Mandatory slice of IdsecPolicyGroupAccessTargetItem entries.
//
// Example:
//
//	targets := IdsecPolicyGroupAccessTarget{Targets: []IdsecPolicyGroupAccessTargetItem{item}}
//
// Validation & Errors:
//   - Serialize enforces at least one item and non-empty mandatory fields per item.
//   - Deserialize enforces presence and validity for each item.
//
// Concurrency: Safe for read-only concurrent access; copy before mutation.
type IdsecPolicyGroupAccessTarget struct { //nolint:revive
	Targets []IdsecPolicyGroupAccessTargetItem `json:"targets" mapstructure:"targets" flag:"targets" desc:"List of Entra group targets for group assignment policy - mandatory"`
}

// NewIdsecPolicyGroupAccessTarget constructs a new target wrapper from provided items slice.
// Parameters:
//   - items: Slice of IdsecPolicyGroupAccessTargetItem; must be non-empty and each item must have all mandatory fields populated.
//
// Returns pointer to IdsecPolicyGroupAccessTarget or error if validation fails.
func NewIdsecPolicyGroupAccessTarget(items []IdsecPolicyGroupAccessTargetItem) (*IdsecPolicyGroupAccessTarget, error) { //nolint:revive
	if len(items) == 0 {
		return nil, fmt.Errorf("targets cannot be empty")
	}
	for i, it := range items {
		if it.GroupID == "" || it.DirectoryID == "" {
			return nil, fmt.Errorf("target index %d has empty mandatory field(s)", i)
		}
	}
	return &IdsecPolicyGroupAccessTarget{Targets: items}, nil
}

// Serialize converts the wrapper into a map[string]interface{} with a camelCase 'targets' key holding an array of item maps.
func (t *IdsecPolicyGroupAccessTarget) Serialize() (map[string]interface{}, error) { //nolint:revive
	if t == nil || len(t.Targets) == 0 {
		return nil, fmt.Errorf("targets cannot be empty")
	}
	serialized := make([]interface{}, 0, len(t.Targets))
	for i, it := range t.Targets {
		if it.GroupID == "" || it.DirectoryID == "" {
			return nil, fmt.Errorf("target index %d has empty mandatory field(s)", i)
		}
		itemMap := map[string]interface{}{
			"groupId":     it.GroupID,
			"directoryId": it.DirectoryID,
		}
		// GroupName, GroupType, DirectoryName, Description are read-only; omit from create/update payload
		serialized = append(serialized, itemMap)
	}
	return map[string]interface{}{"targets": serialized}, nil
}

// Deserialize populates the wrapper from a map containing a 'targets' key with array of item maps in snake_case.
func (t *IdsecPolicyGroupAccessTarget) Deserialize(data map[string]interface{}) error { //nolint:revive
	if data == nil {
		return fmt.Errorf("data cannot be nil")
	}
	arr, ok := data["targets"].([]interface{})
	if !ok {
		return fmt.Errorf("targets missing or not an array")
	}
	items := make([]IdsecPolicyGroupAccessTargetItem, 0, len(arr))
	for i, raw := range arr {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return fmt.Errorf("target index %d is not a map", i)
		}
		item := IdsecPolicyGroupAccessTargetItem{}
		if v, ok := m["group_id"].(string); ok {
			item.GroupID = v
		}
		if v, ok := m["directory_id"].(string); ok {
			item.DirectoryID = v
		}
		if v, ok := m["group_name"].(string); ok {
			item.GroupName = v
		}
		if v, ok := m["directory_name"].(string); ok {
			item.DirectoryName = v
		}
		if v, ok := m["description"].(string); ok {
			item.Description = v
		}
		if v, ok := m["group_type"].(string); ok {
			item.GroupType = v
		}
		if item.GroupID == "" || item.DirectoryID == "" {
			return fmt.Errorf("target index %d has empty mandatory field(s)", i)
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return fmt.Errorf("targets cannot be empty")
	}
	t.Targets = items
	return nil
}
