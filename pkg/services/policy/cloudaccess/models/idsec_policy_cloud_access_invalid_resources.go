package models

// Possible values for IdsecPolicyCloudAccessCloudInvalidWorkspace status (per Access control policies API).
const (
	StatusDeleted   string = "DELETED"
	StatusSuspended string = "SUSPENDED"
)

// IdsecPolicyCloudAccessCloudInvalidWorkspace represents an invalid workspace.
type IdsecPolicyCloudAccessCloudInvalidWorkspace struct {
	ID     string `json:"id" mapstructure:"id" flag:"id" desc:"Resource ID"`
	Status string `json:"status" mapstructure:"status" flag:"status" desc:"The status of the workspace. Valid values: DELETED, SUSPENDED" choices:"DELETED,SUSPENDED"`
}

// IdsecPolicyCloudAccessCloudInvalidRole represents an invalid role.
type IdsecPolicyCloudAccessCloudInvalidRole struct {
	ID string `json:"id" mapstructure:"id" flag:"id" desc:"Invalid role ID. For example: arn:aws:iam::123456789:role/FullAccessToDevelopers"`
}

// IdsecPolicyCloudAccessCloudInvalidResources represents invalid Cloud Console resources (cloudaccess, excludes VM/DB).
// Per Access control policies API: CloudInvalidResources has workspaces and roles.
type IdsecPolicyCloudAccessCloudInvalidResources struct {
	Workspaces []IdsecPolicyCloudAccessCloudInvalidWorkspace `json:"workspaces,omitempty" mapstructure:"workspaces,omitempty" flag:"workspaces" desc:"The invalid targets (workspaces) in the policy"`
	Roles      []IdsecPolicyCloudAccessCloudInvalidRole      `json:"roles,omitempty" mapstructure:"roles,omitempty" flag:"roles" desc:"The invalid roles in the policy"`
}
