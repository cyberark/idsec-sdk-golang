package models

import (
	"errors"
)

// IdsecSCAAzureWorkspaceType represents the workspace types in Azure.
const (
	AzureWSTypeDirectory       = "directory"
	AzureWSTypeSubscription    = "subscription"
	AzureWSTypeResourceGroup   = "resource_group"
	AzureWSTypeResource        = "resource"
	AzureWSTypeManagementGroup = "management_group"
)

// IdsecSCAGCPWorkspaceType represents the workspace types in GCP.
const (
	GCPWSTypeOrganization = "gcp_organization"
	GCPWSTypeFolder       = "folder"
	GCPWSTypeProject      = "project"
)

// IdsecSCAGcpRoleType represents the role types in GCP.
const (
	GCPRoleTypePreDefined = iota
	GCPRoleTypeCustom
	GCPRoleTypeBasic
)

// IdsecUAPSCABaseTarget defines the interface for serializing and deserializing target structures.
type IdsecUAPSCABaseTarget interface {
	Serialize() (map[string]interface{}, error)
	Deserialize(data map[string]interface{}) error
}

// IdsecUAPSCATarget represents the base target structure.
type IdsecUAPSCATarget struct {
	RoleID        string `json:"role_id" validate:"required" mapstructure:"role_id" flag:"role-id" desc:"AWS: The unique identifier assigned to the IAM role in AWS (IAM role ARN); AWS organization: The unique identifier assigned to the IAM role in AWS (IAM role ARN); Azure: The identifier of Azure resource role or Entra ID role; GCP: The Google Cloud role and hierarchy structure"`
	WorkspaceID   string `json:"workspace_id" validate:"required" mapstructure:"workspace_id" flag:"workspace-id" desc:"AWS: The workspace ID given to the standalone AWS account when it was onboarded to CyberArk; AWS organization: The workspace ID given to the AWS organization when it was onboarded to CyberArk; Azure: The workspace ID given to Microsoft Entra ID when it was onboarded to CyberArk; GCP: The workspace ID given to the Google Cloud organization when it was onboarded to CyberArk"`
	RoleName      string `json:"role_name,omitempty" mapstructure:"role_name,omitempty" flag:"role-name" desc:"The name of role with which the identity can access the target workspace"`
	WorkspaceName string `json:"workspace_name,omitempty" mapstructure:"workspace_name,omitempty" flag:"workspace-name" desc:"The workspace name of the target. GCP: The Google Cloud Workspace"`
}

// IdsecUAPSCAOrgTarget represents a target with an organization ID.
type IdsecUAPSCAOrgTarget struct {
	IdsecUAPSCATarget `mapstructure:",squash"`
	OrgID             string `json:"org_id" mapstructure:"org_id" flag:"org-id" desc:"AWSOrg:Management account ID (required only for AWS IAM Identity Center), Azure: Azure directory ID (UUID), GCP: The Google Cloud organization ID"`
}

// IdsecUAPSCAAWSAccountTarget represents an AWS account target.
type IdsecUAPSCAAWSAccountTarget struct {
	IdsecUAPSCATarget `mapstructure:",squash" desc:"AWS account details"`
}

// Serialize serializes the IdsecUAPSCAAWSAccountTarget to a map.
func (s *IdsecUAPSCAAWSAccountTarget) Serialize() (map[string]interface{}, error) {
	return map[string]interface{}{
		"roleId":        s.RoleID,
		"workspaceId":   s.WorkspaceID,
		"roleName":      s.RoleName,
		"workspaceName": s.WorkspaceName,
	}, nil
}

// Deserialize deserializes the map into the IdsecUAPSCAAWSAccountTarget.
func (s *IdsecUAPSCAAWSAccountTarget) Deserialize(data map[string]interface{}) error {
	if roleID, ok := data["role_id"].(string); ok {
		s.RoleID = roleID
	}
	if workspaceID, ok := data["workspace_id"].(string); ok {
		s.WorkspaceID = workspaceID
	}
	if roleName, ok := data["role_name"].(string); ok {
		s.RoleName = roleName
	}
	if workspaceName, ok := data["workspace_name"].(string); ok {
		s.WorkspaceName = workspaceName
	}
	return nil
}

// IdsecUAPSCAAWSOrganizationTarget represents an AWS organization target.
type IdsecUAPSCAAWSOrganizationTarget struct {
	IdsecUAPSCAOrgTarget `mapstructure:",squash"`
}

// Serialize serializes the IdsecUAPSCAAWSOrganizationTarget to a map.
func (s *IdsecUAPSCAAWSOrganizationTarget) Serialize() (map[string]interface{}, error) {
	return map[string]interface{}{
		"roleId":        s.RoleID,
		"workspaceId":   s.WorkspaceID,
		"roleName":      s.RoleName,
		"workspaceName": s.WorkspaceName,
		"orgId":         s.OrgID,
	}, nil
}

// Deserialize deserializes the map into the IdsecUAPSCAAWSOrganizationTarget.
func (s *IdsecUAPSCAAWSOrganizationTarget) Deserialize(data map[string]interface{}) error {
	if roleID, ok := data["role_id"].(string); ok {
		s.RoleID = roleID
	}
	if workspaceID, ok := data["workspace_id"].(string); ok {
		s.WorkspaceID = workspaceID
	}
	if roleName, ok := data["role_name"].(string); ok {
		s.RoleName = roleName
	}
	if workspaceName, ok := data["workspace_name"].(string); ok {
		s.WorkspaceName = workspaceName
	}
	if orgID, ok := data["org_id"].(string); ok {
		s.OrgID = orgID
	}
	return nil
}

// IdsecUAPSCAAzureTarget represents an Azure target.
type IdsecUAPSCAAzureTarget struct {
	IdsecUAPSCAOrgTarget `mapstructure:",squash"`
	WorkspaceType        string `json:"workspace_type" validate:"required" mapstructure:"workspace_type" flag:"workspace-type" desc:"The level at which the Microsoft Entra ID workspace was onboarded to CyberArk" choices:"directory,subscription,resource_group,resource,management_group"`
	RoleType             int    `json:"role_type,omitempty" mapstructure:"role_type,omitempty" flag:"role-type" desc:"The type of the role in Azure"`
}

// Serialize serializes the IdsecUAPSCAAzureTarget to a map.
func (s *IdsecUAPSCAAzureTarget) Serialize() (map[string]interface{}, error) {
	return map[string]interface{}{
		"roleId":        s.RoleID,
		"workspaceId":   s.WorkspaceID,
		"roleName":      s.RoleName,
		"workspaceName": s.WorkspaceName,
		"orgId":         s.OrgID,
		"workspaceType": s.WorkspaceType,
		"roleType":      s.RoleType,
	}, nil
}

// Deserialize deserializes the map into the IdsecUAPSCAAzureTarget.
func (s *IdsecUAPSCAAzureTarget) Deserialize(data map[string]interface{}) error {
	if roleID, ok := data["role_id"].(string); ok {
		s.RoleID = roleID
	}
	if workspaceID, ok := data["workspace_id"].(string); ok {
		s.WorkspaceID = workspaceID
	}
	if roleName, ok := data["role_name"].(string); ok {
		s.RoleName = roleName
	}
	if workspaceName, ok := data["workspace_name"].(string); ok {
		s.WorkspaceName = workspaceName
	}
	if orgID, ok := data["org_id"].(string); ok {
		s.OrgID = orgID
	}
	if workspaceType, ok := data["workspace_type"].(string); ok {
		s.WorkspaceType = workspaceType
	}
	if roleType, ok := data["role_type"].(int); ok {
		s.RoleType = roleType
	}
	return nil
}

// IdsecUAPSCAGCPTarget represents a GCP target.
type IdsecUAPSCAGCPTarget struct {
	IdsecUAPSCAOrgTarget `mapstructure:",squash"`
	WorkspaceType        string `json:"workspace_type" validate:"required" mapstructure:"workspace_type" flag:"workspace-type" desc:"The level at which the Google Cloud organization was onboarded to CyberArk - Full organization, folder, project" choices:"gcp_organization,folder,project"`
	RolePackage          string `json:"role_package,omitempty" mapstructure:"role_package,omitempty" flag:"role-package" desc:"The role package of the target"`
	RoleType             int    `json:"role_type,omitempty" mapstructure:"role_type,omitempty" flag:"role-type" desc:"The type of role in GCP"`
}

// Serialize serializes the IdsecUAPSCAGCPTarget to a map.
func (s *IdsecUAPSCAGCPTarget) Serialize() (map[string]interface{}, error) {
	return map[string]interface{}{
		"roleId":        s.RoleID,
		"workspaceId":   s.WorkspaceID,
		"roleName":      s.RoleName,
		"workspaceName": s.WorkspaceName,
		"orgId":         s.OrgID,
		"workspaceType": s.WorkspaceType,
		"rolePackage":   s.RolePackage,
		"roleType":      s.RoleType,
	}, nil
}

// Deserialize deserializes the map into the IdsecUAPSCAGCPTarget.
func (s *IdsecUAPSCAGCPTarget) Deserialize(data map[string]interface{}) error {
	if roleID, ok := data["role_id"].(string); ok {
		s.RoleID = roleID
	}
	if workspaceID, ok := data["workspace_id"].(string); ok {
		s.WorkspaceID = workspaceID
	}
	if roleName, ok := data["role_name"].(string); ok {
		s.RoleName = roleName
	}
	if workspaceName, ok := data["workspace_name"].(string); ok {
		s.WorkspaceName = workspaceName
	}
	if orgID, ok := data["org_id"].(string); ok {
		s.OrgID = orgID
	}
	if workspaceType, ok := data["workspace_type"].(string); ok {
		s.WorkspaceType = workspaceType
	}
	if rolePackage, ok := data["role_package"].(string); ok {
		s.RolePackage = rolePackage
	}
	if roleType, ok := data["role_type"].(int); ok {
		s.RoleType = roleType
	}
	return nil
}

// IdsecUAPSCACloudConsoleTarget represents a cloud console target.
type IdsecUAPSCACloudConsoleTarget struct {
	AwsAccountTargets      []IdsecUAPSCAAWSAccountTarget      `json:"aws_account_targets,omitempty" mapstructure:"aws_account_targets,omitempty" flag:"aws-account-targets" desc:"AWS account details"`
	AwsOrganizationTargets []IdsecUAPSCAAWSOrganizationTarget `json:"aws_organization_targets,omitempty" mapstructure:"aws_organization_targets,omitempty" flag:"aws-organization-targets" desc:"AWS organization workspace details"`
	AzureTargets           []IdsecUAPSCAAzureTarget           `json:"azure_targets,omitempty" mapstructure:"azure_targets,omitempty" flag:"azure-targets" desc:"List of Azure targets or Microsoft Entra ID workspace details"`
	GcpTargets             []IdsecUAPSCAGCPTarget             `json:"gcp_targets,omitempty" mapstructure:"gcp_targets,omitempty" flag:"gcp-targets" desc:"Google Cloud workspace details"`
}

// SerializeTargets serializes the IdsecUAPSCACloudConsoleTarget to a map.
func (s *IdsecUAPSCACloudConsoleTarget) SerializeTargets() (map[string]interface{}, error) {
	targets := make([]interface{}, 0)

	for _, target := range s.AwsAccountTargets {
		data, err := target.Serialize()
		if err != nil {
			return nil, err
		}
		targets = append(targets, data)
	}

	for _, target := range s.AwsOrganizationTargets {
		data, err := target.Serialize()
		if err != nil {
			return nil, err
		}
		targets = append(targets, data)
	}

	for _, target := range s.AzureTargets {
		data, err := target.Serialize()
		if err != nil {
			return nil, err
		}
		targets = append(targets, data)
	}

	for _, target := range s.GcpTargets {
		data, err := target.Serialize()
		if err != nil {
			return nil, err
		}
		targets = append(targets, data)
	}

	return map[string]interface{}{
		"targets": targets,
	}, nil
}

// DeserializeTargets deserializes the map into the IdsecUAPSCACloudConsoleTarget.
func (s *IdsecUAPSCACloudConsoleTarget) DeserializeTargets(data map[string]interface{}) error {
	targetsData, ok := data["targets"].([]interface{})
	if !ok {
		return errors.New("invalid targets data format")
	}
	for _, targetData := range targetsData {
		targetMap, ok := targetData.(map[string]interface{})
		if !ok {
			return errors.New("invalid target data format")
		}
		if workspaceType, ok := targetMap["workspace_type"].(string); ok {
			switch workspaceType {
			case AzureWSTypeDirectory, AzureWSTypeSubscription, AzureWSTypeResourceGroup, AzureWSTypeResource, AzureWSTypeManagementGroup:
				var target IdsecUAPSCAAzureTarget
				if err := target.Deserialize(targetMap); err != nil {
					return err
				}
				s.AzureTargets = append(s.AzureTargets, target)
			case GCPWSTypeOrganization, GCPWSTypeFolder, GCPWSTypeProject:
				var target IdsecUAPSCAGCPTarget
				if err := target.Deserialize(targetMap); err != nil {
					return err
				}
				s.GcpTargets = append(s.GcpTargets, target)
			default:
				return errors.New("unknown workspace type in cloud console targets")
			}
		} else {
			if _, ok := targetMap["org_id"]; ok {
				var target IdsecUAPSCAAWSOrganizationTarget
				if err := target.Deserialize(targetMap); err != nil {
					return err
				}
				s.AwsOrganizationTargets = append(s.AwsOrganizationTargets, target)
			} else if _, ok := targetMap["workspace_id"]; ok {
				var target IdsecUAPSCAAWSAccountTarget
				if err := target.Deserialize(targetMap); err != nil {
					return err
				}
				s.AwsAccountTargets = append(s.AwsAccountTargets, target)
			} else {
				return errors.New("unknown target type in cloud console targets")
			}
		}
	}
	return nil
}

// ClearTargetsFromData clears the target data from the provided map.
func (s *IdsecUAPSCACloudConsoleTarget) ClearTargetsFromData(data map[string]interface{}) {
	delete(data, "aws_account_targets")
	delete(data, "awsAccountTargets")
	delete(data, "aws_organization_targets")
	delete(data, "awsOrganizationTargets")
	delete(data, "azure_targets")
	delete(data, "azureTargets")
	delete(data, "gcp_targets")
	delete(data, "gcpTargets")
}
