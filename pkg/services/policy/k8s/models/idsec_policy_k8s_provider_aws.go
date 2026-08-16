package models

// IdsecPolicyK8sAWSAccountTarget represents an AWS IAM K8s cluster policy target.
type IdsecPolicyK8sAWSAccountTarget struct {
	IdsecPolicyK8sTarget `mapstructure:",squash" desc:"AWS account target with IAM role ARN and account workspace ID"`
}

// Serialize converts an AWS IAM K8s policy target into the API request payload shape.
func (s *IdsecPolicyK8sAWSAccountTarget) Serialize() (map[string]interface{}, error) {
	result := map[string]interface{}{
		"roleId":      s.RoleID,
		"workspaceId": s.WorkspaceID,
	}
	if s.RoleName != "" {
		result["roleName"] = s.RoleName
	}
	if s.WorkspaceName != "" {
		result["workspaceName"] = s.WorkspaceName
	}
	s.AppendTo(result)
	return result, nil
}

// Deserialize populates an AWS IAM K8s policy target from serialized API data.
func (s *IdsecPolicyK8sAWSAccountTarget) Deserialize(data map[string]interface{}) error {
	deserializeK8sTarget(data, &s.IdsecPolicyK8sTarget)
	return nil
}

// AWSIDCPermissionSetARNPrefix is the ARN prefix that identifies an AWS IAM Identity Center
// permission set. K8s IDC targets carry this ARN in RoleID, which is how they are distinguished
// from plain AWS IAM account targets (whose RoleID is an arn:aws:iam:: role ARN).
const AWSIDCPermissionSetARNPrefix = "arn:aws:sso:::permissionSet/"

// IdsecPolicyK8sAWSIDCTarget represents an AWS IAM Identity Center (IDC) Kubernetes cluster policy target.
//
// IDC targets share the flat target shape with AWS IAM account targets, with two differences:
//   - RoleID carries the AWS SSO permission-set ARN (see AWSIDCPermissionSetARNPrefix).
//   - OrgID identifies the AWS organization / SSO instance owner account.
type IdsecPolicyK8sAWSIDCTarget struct {
	IdsecPolicyK8sTarget `mapstructure:",squash"`
	OrgID                string `json:"org_id" validate:"required" mapstructure:"org_id" flag:"org-id" desc:"Management account ID (required only for AWS IAM Identity Center)."`
}

// Serialize converts an AWS IDC K8s policy target into the API request payload shape.
func (s *IdsecPolicyK8sAWSIDCTarget) Serialize() (map[string]interface{}, error) {
	result := map[string]interface{}{
		"roleId":      s.RoleID,
		"workspaceId": s.WorkspaceID,
		"orgId":       s.OrgID,
	}
	if s.RoleName != "" {
		result["roleName"] = s.RoleName
	}
	if s.WorkspaceName != "" {
		result["workspaceName"] = s.WorkspaceName
	}
	s.AppendTo(result)
	return result, nil
}

// Deserialize populates an AWS IDC K8s policy target from serialized API data.
func (s *IdsecPolicyK8sAWSIDCTarget) Deserialize(data map[string]interface{}) error {
	deserializeK8sTarget(data, &s.IdsecPolicyK8sTarget)
	s.OrgID = k8sTargetStringField(data, "org_id", "orgId")
	return nil
}
