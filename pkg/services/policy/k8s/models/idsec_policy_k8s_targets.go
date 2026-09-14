package models

import (
	"errors"
	"fmt"
	"strings"
)

// IdsecPolicyK8sBaseTarget defines serialize/deserialize behavior for a single K8s policy target.
type IdsecPolicyK8sBaseTarget interface {
	Serialize() (map[string]interface{}, error)
	Deserialize(data map[string]interface{}) error
}

// IdsecPolicyK8sSharedTarget contains fields with identical descriptions across all K8s policy target types.
type IdsecPolicyK8sSharedTarget struct {
	Scope         string `json:"scope" validate:"required" mapstructure:"scope" flag:"scope" desc:"Indicates whether the role grants access to the entire cluster or to a specific namespace within the cluster."`
	NamespaceID   string `json:"namespace_id,omitempty" mapstructure:"namespace_id,omitempty" flag:"namespace-id" desc:"The unique identifier of the Kubernetes namespace. Required only when scope is set to namespace."`
	FQDN          string `json:"fqdn,omitempty" mapstructure:"fqdn,omitempty" flag:"fqdn" desc:"Fully qualified domain name of the Kubernetes cluster endpoint (e.g. my-cluster.example.com)"`
	NamespaceName string `json:"namespace_name,omitempty" mapstructure:"namespace_name,omitempty" flag:"namespace-name" desc:"The display name of the Kubernetes namespace. Required only when scope is set to namespace."`
}

// appendSharedTo adds the shared K8s fields to a serialized policy target.
func (s IdsecPolicyK8sSharedTarget) appendSharedTo(result map[string]interface{}) {
	result["scope"] = s.Scope
	if s.NamespaceID != "" {
		result["namespaceId"] = s.NamespaceID
	}
	if s.FQDN != "" {
		result["fqdn"] = s.FQDN
	}
	if s.NamespaceName != "" {
		result["namespaceName"] = s.NamespaceName
	}
}

// IdsecPolicyK8sAWSTarget contains AWS-specific fields shared by both AWS K8s policy target types.
type IdsecPolicyK8sAWSTarget struct {
	IdsecPolicyK8sSharedTarget `mapstructure:",squash"`
	RoleID                     string `json:"role_id" validate:"required" mapstructure:"role_id" flag:"role-id" desc:"The unique identifier assigned to the IAM role in AWS (IAM role ARN)."`
	WorkspaceID                string `json:"workspace_id" validate:"required" mapstructure:"workspace_id" flag:"workspace-id" desc:"The unique identifier created for the AWS account in Idira when it was connected."`
	RoleName                   string `json:"role_name,omitempty" mapstructure:"role_name,omitempty" flag:"role-name" desc:"The display name of the IAM role."`
	WorkspaceName              string `json:"workspace_name,omitempty" mapstructure:"workspace_name,omitempty" flag:"workspace-name" desc:"The display name of the AWS account in Idira."`
	ClusterID                  string `json:"cluster_id" validate:"required" mapstructure:"cluster_id" flag:"cluster-id" desc:"The unique identifier of the cluster (cluster ARN)."`
	ClusterName                string `json:"cluster_name,omitempty" mapstructure:"cluster_name,omitempty" flag:"cluster-name" desc:"The display name of the cluster."`
	Region                     string `json:"region,omitempty" mapstructure:"region,omitempty" flag:"region" desc:"The AWS region where the EKS cluster is located."`
}

// appendAWSTo adds all AWS K8s target fields to a serialized policy target.
func (s IdsecPolicyK8sAWSTarget) appendAWSTo(result map[string]interface{}) {
	result["clusterId"] = s.ClusterID
	if s.ClusterName != "" {
		result["clusterName"] = s.ClusterName
	}
	if s.Region != "" {
		result["region"] = s.Region
	}
	s.appendSharedTo(result)
}

// IdsecPolicyK8sTargets contains the supported K8s cluster policy targets.
type IdsecPolicyK8sTargets struct {
	AwsAccountTargets []IdsecPolicyK8sAWSAccountTarget `json:"aws_account_targets,omitempty" mapstructure:"aws_account_targets,omitempty" flag:"aws-account-targets" desc:"Amazon EKS cluster target details (AWS IAM)"`
	AwsIdcTargets     []IdsecPolicyK8sAWSIDCTarget     `json:"aws_idc_targets,omitempty" mapstructure:"aws_idc_targets,omitempty" flag:"aws-idc-targets" desc:"Amazon EKS cluster target details (AWS IAM Identity Center)"`
	AzureTargets      []IdsecPolicyK8sAzureTarget      `json:"azure_targets,omitempty" mapstructure:"azure_targets,omitempty" flag:"azure-targets" desc:"AKS cluster target details"`
}

// SerializeTargets converts all configured K8s policy targets into the API payload shape.
func (s *IdsecPolicyK8sTargets) SerializeTargets() (map[string]interface{}, error) {
	for i := range s.AzureTargets {
		if err := ValidateAzureK8sTargetRequiredFields(i, &s.AzureTargets[i]); err != nil {
			return nil, err
		}
	}
	targets := make([]interface{}, 0)
	for _, target := range s.AwsAccountTargets {
		data, err := target.Serialize()
		if err != nil {
			return nil, err
		}
		targets = append(targets, data)
	}
	for _, target := range s.AwsIdcTargets {
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
	return map[string]interface{}{"targets": targets}, nil
}

// DeserializeTargets populates K8s policy targets from serialized API data.
func (s *IdsecPolicyK8sTargets) DeserializeTargets(data map[string]interface{}) error {
	targetsData, ok := data["targets"].([]interface{})
	if !ok {
		return errors.New("invalid targets data format")
	}
	for _, targetData := range targetsData {
		targetMap, ok := targetData.(map[string]interface{})
		if !ok {
			return errors.New("invalid target data format")
		}
		workspaceType := k8sTargetStringField(targetMap, "workspace_type", "workspaceType")
		roleID := k8sTargetStringField(targetMap, "role_id", "roleId")
		switch {
		case workspaceType != "":
			switch workspaceType {
			case AzureWSTypeDirectory, AzureWSTypeSubscription, AzureWSTypeResourceGroup, AzureWSTypeResource, AzureWSTypeManagementGroup:
				var target IdsecPolicyK8sAzureTarget
				if err := target.Deserialize(targetMap); err != nil {
					return err
				}
				if err := ValidateAzureK8sTargetRequiredFields(len(s.AzureTargets), &target); err != nil {
					return err
				}
				s.AzureTargets = append(s.AzureTargets, target)
			default:
				return errors.New("unknown workspace type in k8s targets")
			}
		case strings.HasPrefix(roleID, AWSIDCPermissionSetARNPrefix):
			var target IdsecPolicyK8sAWSIDCTarget
			if err := target.Deserialize(targetMap); err != nil {
				return err
			}
			s.AwsIdcTargets = append(s.AwsIdcTargets, target)
		case k8sTargetStringField(targetMap, "workspace_id", "workspaceId") != "":
			var target IdsecPolicyK8sAWSAccountTarget
			if err := target.Deserialize(targetMap); err != nil {
				return err
			}
			s.AwsAccountTargets = append(s.AwsAccountTargets, target)
		default:
			return errors.New("unknown target type in k8s targets")
		}
	}
	return nil
}

// ClearTargetsFromData removes K8s target fields from a serialized policy payload.
func (s *IdsecPolicyK8sTargets) ClearTargetsFromData(data map[string]interface{}) {
	delete(data, "aws_account_targets")
	delete(data, "awsAccountTargets")
	delete(data, "aws_idc_targets")
	delete(data, "awsIdcTargets")
	delete(data, "azure_targets")
	delete(data, "azureTargets")
}

// k8sTargetStringField reads the first non-empty string among alternate JSON keys (snake_case and camelCase).
func k8sTargetStringField(data map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		v, ok := data[k]
		if !ok || v == nil {
			continue
		}
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// k8sTargetIntField reads an int from alternate keys (snake_case and camelCase), including JSON number decoding as float64.
func k8sTargetIntField(data map[string]interface{}, keys ...string) int {
	for _, k := range keys {
		v, ok := data[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case int:
			return t
		case int32:
			return int(t)
		case int64:
			return int(t)
		case float64:
			return int(t)
		}
	}
	return 0
}

func deserializeK8sSharedTarget(data map[string]interface{}, target *IdsecPolicyK8sSharedTarget) {
	target.Scope = k8sTargetStringField(data, "scope")
	target.NamespaceID = k8sTargetStringField(data, "namespace_id", "namespaceId")
	target.FQDN = k8sTargetStringField(data, "fqdn")
	target.NamespaceName = k8sTargetStringField(data, "namespace_name", "namespaceName")
}

func deserializeK8sAWSTarget(data map[string]interface{}, target *IdsecPolicyK8sAWSTarget) {
	deserializeK8sSharedTarget(data, &target.IdsecPolicyK8sSharedTarget)
	target.RoleID = k8sTargetStringField(data, "role_id", "roleId")
	target.WorkspaceID = k8sTargetStringField(data, "workspace_id", "workspaceId")
	target.RoleName = k8sTargetStringField(data, "role_name", "roleName")
	target.WorkspaceName = k8sTargetStringField(data, "workspace_name", "workspaceName")
	target.ClusterID = k8sTargetStringField(data, "cluster_id", "clusterId")
	target.ClusterName = k8sTargetStringField(data, "cluster_name", "clusterName")
	target.Region = k8sTargetStringField(data, "region")
}

// ValidateAzureK8sTargetRequiredFields ensures Azure K8s targets always carry scope and cluster_id (AKS-by-resource-id uses full ARM resource ID in cluster_id).
func ValidateAzureK8sTargetRequiredFields(idx int, t *IdsecPolicyK8sAzureTarget) error {
	if err := validateAzureK8sTargetCore(t); err != nil {
		if idx >= 0 {
			return fmt.Errorf("azure_targets[%d]: %w", idx, err)
		}
		return fmt.Errorf("azure_targets: %w", err)
	}
	return nil
}
