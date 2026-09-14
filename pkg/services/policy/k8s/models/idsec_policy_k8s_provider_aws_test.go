package models

import (
	"testing"
)

// TestAWSAccountTarget_roundTrip verifies that an AWS IAM (account) target survives a
// Serialize -> Deserialize cycle with all fields preserved.
func TestAWSAccountTarget_roundTrip(t *testing.T) {
	t.Parallel()
	original := IdsecPolicyK8sAWSAccountTarget{
		IdsecPolicyK8sAWSTarget: IdsecPolicyK8sAWSTarget{
			IdsecPolicyK8sSharedTarget: IdsecPolicyK8sSharedTarget{
				Scope:       "cluster",
				NamespaceID: "ns-1",
				FQDN:        "https://example.eks.us-east-1.amazonaws.com",
			},
			RoleID:        "arn:aws:iam::123456789012:role/EKSRole",
			WorkspaceID:   "123456789012",
			RoleName:      "EKSRole",
			WorkspaceName: "Example AWS Account",
			ClusterID:     "arn:aws:eks:us-east-1:123456789012:cluster/example",
		},
	}

	data, err := original.Serialize()
	if err != nil {
		t.Fatalf("unexpected serialize error: %v", err)
	}

	var got IdsecPolicyK8sAWSAccountTarget
	if err := got.Deserialize(data); err != nil {
		t.Fatalf("unexpected deserialize error: %v", err)
	}

	if got.IdsecPolicyK8sAWSTarget != original.IdsecPolicyK8sAWSTarget {
		t.Fatalf("round-trip mismatch:\n got  %+v\n want %+v", got.IdsecPolicyK8sAWSTarget, original.IdsecPolicyK8sAWSTarget)
	}
}

// TestAWSIDCTarget_roundTrip verifies that an AWS IAM Identity Center target survives a
// Serialize -> Deserialize cycle. The permission set is carried in RoleID (SSO ARN) and the
// owning account in OrgID; no separate permission_set_id field is used (matches the live API).
func TestAWSIDCTarget_roundTrip(t *testing.T) {
	t.Parallel()
	original := IdsecPolicyK8sAWSIDCTarget{
		IdsecPolicyK8sAWSTarget: IdsecPolicyK8sAWSTarget{
			IdsecPolicyK8sSharedTarget: IdsecPolicyK8sSharedTarget{
				Scope: "cluster",
			},
			RoleID:        AWSIDCPermissionSetARNPrefix + "ssoins-72231f8423e74442/ps-e7fd50e355dea4d6",
			WorkspaceID:   "081626391589",
			RoleName:      "AdminPS",
			WorkspaceName: "CybrSCA AWS Organization",
			ClusterID:     "arn:aws:eks:us-east-1:081626391589:cluster/peculiar-classical-goose",
			ClusterName:   "peculiar-classical-goose",
			Region:        "us-east-1",
		},
		OrgID: "081626391589",
	}

	data, err := original.Serialize()
	if err != nil {
		t.Fatalf("unexpected serialize error: %v", err)
	}
	if _, ok := data["permissionSetId"]; ok {
		t.Fatalf("did not expect permissionSetId in serialized payload, got keys: %v", data)
	}
	if data["orgId"] != original.OrgID {
		t.Fatalf("expected orgId %q in serialized payload, got: %v", original.OrgID, data["orgId"])
	}

	var got IdsecPolicyK8sAWSIDCTarget
	if err := got.Deserialize(data); err != nil {
		t.Fatalf("unexpected deserialize error: %v", err)
	}

	if got.IdsecPolicyK8sAWSTarget != original.IdsecPolicyK8sAWSTarget {
		t.Fatalf("base round-trip mismatch:\n got  %+v\n want %+v", got.IdsecPolicyK8sAWSTarget, original.IdsecPolicyK8sAWSTarget)
	}
	if got.OrgID != original.OrgID {
		t.Fatalf("org_id: got %q want %q", got.OrgID, original.OrgID)
	}
}

// TestDeserializeTargets_dispatch verifies that DeserializeTargets routes each raw target to
// the correct slice: an SSO permission-set ARN in roleId selects IDC, a plain IAM role ARN with a
// workspace_id selects an AWS account target, and workspace_type selects Azure.
func TestDeserializeTargets_dispatch(t *testing.T) {
	t.Parallel()
	input := map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"role_id":      "arn:aws:iam::111111111111:role/EKSRole",
				"workspace_id": "111111111111",
				"scope":        "cluster",
				"cluster_id":   "arn:aws:eks:us-east-1:111111111111:cluster/iam-cluster",
			},
			map[string]interface{}{
				"role_id":      AWSIDCPermissionSetARNPrefix + "ssoins-abc/ps-123",
				"workspace_id": "222222222222",
				"org_id":       "222222222222",
				"scope":        "cluster",
				"cluster_id":   "arn:aws:eks:us-east-1:222222222222:cluster/idc-cluster",
			},
			map[string]interface{}{
				"workspace_type": AzureWSTypeSubscription,
				"role_id":        "azure-role",
				"workspace_id":   "sub-1",
				"org_id":         "tenant-1",
				"scope":          "cluster",
				"cluster_id":     "/subscriptions/sub-1/managedClusters/aks",
			},
		},
	}

	var targets IdsecPolicyK8sTargets
	if err := targets.DeserializeTargets(input); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets.AwsAccountTargets) != 1 {
		t.Fatalf("expected 1 aws account target, got %d", len(targets.AwsAccountTargets))
	}
	if len(targets.AwsIdcTargets) != 1 {
		t.Fatalf("expected 1 aws idc target, got %d", len(targets.AwsIdcTargets))
	}
	if len(targets.AzureTargets) != 1 {
		t.Fatalf("expected 1 azure target, got %d", len(targets.AzureTargets))
	}
	if targets.AwsIdcTargets[0].OrgID != "222222222222" {
		t.Fatalf("idc org_id: got %q want %q", targets.AwsIdcTargets[0].OrgID, "222222222222")
	}
	if targets.AwsAccountTargets[0].WorkspaceID != "111111111111" {
		t.Fatalf("aws account workspace_id: got %q want %q", targets.AwsAccountTargets[0].WorkspaceID, "111111111111")
	}
}

// TestSerializeTargets_idcRoundTrip verifies that an IDC target added to IdsecPolicyK8sTargets
// serializes into the flat "targets" array and deserializes back into AwsIdcTargets.
func TestSerializeTargets_idcRoundTrip(t *testing.T) {
	t.Parallel()
	in := IdsecPolicyK8sTargets{
		AwsIdcTargets: []IdsecPolicyK8sAWSIDCTarget{
			{
				IdsecPolicyK8sAWSTarget: IdsecPolicyK8sAWSTarget{
					IdsecPolicyK8sSharedTarget: IdsecPolicyK8sSharedTarget{
						Scope: "cluster",
					},
					RoleID:      AWSIDCPermissionSetARNPrefix + "ssoins-abc/ps-123",
					WorkspaceID: "081626391589",
					RoleName:    "AdminPS",
					ClusterID:   "arn:aws:eks:us-east-1:081626391589:cluster/example",
				},
				OrgID: "081626391589",
			},
		},
	}

	serialized, err := in.SerializeTargets()
	if err != nil {
		t.Fatalf("unexpected serialize error: %v", err)
	}

	var out IdsecPolicyK8sTargets
	if err := out.DeserializeTargets(serialized); err != nil {
		t.Fatalf("unexpected deserialize error: %v", err)
	}
	if len(out.AwsIdcTargets) != 1 {
		t.Fatalf("expected 1 idc target after round-trip, got %d (account=%d azure=%d)",
			len(out.AwsIdcTargets), len(out.AwsAccountTargets), len(out.AzureTargets))
	}
	if out.AwsIdcTargets[0].OrgID != "081626391589" {
		t.Fatalf("idc org_id: got %q", out.AwsIdcTargets[0].OrgID)
	}
}
