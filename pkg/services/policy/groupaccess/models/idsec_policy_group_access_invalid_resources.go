package models

// IdsecPolicyGroupAccessInvalidGroup represents an invalid Entra group reference in an Entra group assignment policy (groupaccess).
//
// Fields:
//   - ID: The group ID that was deemed invalid.
//   - Status: A string describing the invalid state (e.g., REMOVED, SUSPENDED). Values are not strictly enumerated
//     here to allow backend-driven expansion. Validation can be added later if needed.
//
// Example serialized (camelCase after external conversion):
//
//	{"id": "75657604-6af0-48ce-b6fc-3a7e72b27524", "status": "REMOVED"}
//
// Concurrency: Safe for read-only usage.
type IdsecPolicyGroupAccessInvalidGroup struct { //nolint:revive
	ID     string `json:"id" mapstructure:"id" flag:"id" desc:"Invalid group ID"`
	Status string `json:"status" mapstructure:"status" flag:"status" desc:"Invalid group status (e.g., REMOVED, SUSPENDED)"`
}

// IdsecPolicyGroupAccessInvalidResources aggregates invalid Entra group references for a group assignment policy (groupaccess).
//
// Fields:
//   - Groups: Slice of invalid group descriptors.
//
// Usage:
//
//	policy.InvalidResources = IdsecPolicyGroupAccessInvalidResources{Groups: []IdsecPolicyGroupAccessInvalidGroup{{ID: "id", Status: "REMOVED"}}}
//
// Concurrency: Safe for read-only usage.
type IdsecPolicyGroupAccessInvalidResources struct { //nolint:revive
	Groups []IdsecPolicyGroupAccessInvalidGroup `json:"groups,omitempty" mapstructure:"groups,omitempty" flag:"groups" desc:"List of invalid groups referenced by the policy"`
}
