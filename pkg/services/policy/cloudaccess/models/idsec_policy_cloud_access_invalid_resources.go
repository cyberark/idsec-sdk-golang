package models

// Possible values for IdsecPolicyCloudAccessCloudInvalidWorkspace status.
const (
	StatusRemoved   string = "REMOVED"
	StatusSuspended string = "SUSPENDED"
)

// IdsecPolicyCloudAccessCloudInvalidWorkspace represents an invalid workspace.
type IdsecPolicyCloudAccessCloudInvalidWorkspace struct {
	ID     string `json:"id" mapstructure:"id" flag:"id" desc:"Resource ID"`
	Status string `json:"status" mapstructure:"status" flag:"status" desc:"Workspace status" choices:"REMOVED,SUSPENDED"`
}

// IdsecPolicyCloudAccessCloudInvalidRole represents an invalid role.
type IdsecPolicyCloudAccessCloudInvalidRole struct {
	ID string `json:"id" mapstructure:"id" flag:"id" desc:"Invalid role ID"`
}

// IdsecPolicyCloudAccessCloudInvalidWebapp represents an invalid webapp.
type IdsecPolicyCloudAccessCloudInvalidWebapp struct {
	ID string `json:"id" mapstructure:"id" flag:"id" desc:"Invalid webapp ID"`
}

// IdsecPolicyCloudAccessCloudInvalidResources represents a collection of invalid resources.
type IdsecPolicyCloudAccessCloudInvalidResources struct {
	Workspaces []IdsecPolicyCloudAccessCloudInvalidWorkspace `json:"workspaces,omitempty" mapstructure:"workspaces,omitempty" flag:"workspaces" desc:"List of invalid workspaces"`
	Roles      []IdsecPolicyCloudAccessCloudInvalidRole      `json:"roles,omitempty" mapstructure:"roles,omitempty" flag:"roles" desc:"List of invalid roles"`
	Webapps    []IdsecPolicyCloudAccessCloudInvalidWebapp    `json:"webapps,omitempty" mapstructure:"webapps,omitempty" flag:"webapps" desc:"List of invalid webapps"`
}
