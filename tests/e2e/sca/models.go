//go:build (e2e && sca) || e2e

package sca

import (
	"testing"

	policycloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess/models"
	scacloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudaccess/models"
)

type principalFields struct {
	ID            string
	Name          string
	SourceDirName string
	SourceDirID   string
}

type k8sTestContext struct {
	AuthBlock      map[string]interface{}
	PrincipalBlock map[string]interface{}
	Targets        []map[string]interface{}
}

type k8sTargetConfig struct {
	PolicyTarget *scacloudaccessmodels.IdsecSCAEligibleTarget
	VerifyTarget *scacloudaccessmodels.IdsecSCAEligibleTarget
	Scope        string
	ClusterID    string
	FQDN         string
}

type k8sListTargetsConfig struct {
	configBlockKey             string
	displayName                string
	csp                        string
	policyNamePrefix           string
	paginationPolicyNamePrefix string
	buildTarget                func(map[string]interface{}) k8sTargetConfig
}

type cloudAccessListTargetsConfig struct {
	configBlockKey             string
	displayName                string
	csp                        string
	policyNamePrefix           string
	paginationPolicyNamePrefix string
	verifyTarget               func(*testing.T, *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, *scacloudaccessmodels.IdsecSCAEligibleTarget, []scacloudaccessmodels.IdsecSCAEligibleTarget)
}

var awsK8sListTargetsConfig = k8sListTargetsConfig{
	configBlockKey:             "k8s_aws_clusters",
	displayName:                "K8s AWS Clusters ListTargets",
	csp:                        "AWS",
	policyNamePrefix:           "sca_cli_k8s_aws_e2e",
	paginationPolicyNamePrefix: "sca_cli_k8s_aws_pagination_e2e",
	buildTarget:                buildAWSK8sTargetFromConfig,
}

var azureK8sListTargetsConfig = k8sListTargetsConfig{
	configBlockKey:             "k8s_azure_clusters",
	displayName:                "K8s Azure Clusters ListTargets",
	csp:                        "AZURE",
	policyNamePrefix:           "sca_cli_k8s_azure_e2e",
	paginationPolicyNamePrefix: "sca_cli_k8s_azure_pagination_e2e",
	buildTarget:                buildAzureK8sTargetFromConfig,
}

var awsCloudAccessListTargetsConfig = cloudAccessListTargetsConfig{
	configBlockKey:             "aws_cloudaccess",
	displayName:                "CloudAccess AWS ListTargets",
	csp:                        "AWS",
	policyNamePrefix:           "sca_cli_cloudaccess_aws_e2e",
	paginationPolicyNamePrefix: "sca_cli_cloudaccess_aws_pagination_e2e",
	verifyTarget: func(t *testing.T, _ *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, target *scacloudaccessmodels.IdsecSCAEligibleTarget, response []scacloudaccessmodels.IdsecSCAEligibleTarget) {
		verifyAWSCloudAccessTargetInListTargets(t, target, response)
	},
}

var azureEntraIDCloudAccessListTargetsConfig = cloudAccessListTargetsConfig{
	configBlockKey:             "azure_cloudaccess",
	displayName:                "CloudAccess Azure Entra ID ListTargets",
	csp:                        "AZURE",
	policyNamePrefix:           "sca_cli_cloudaccess_azure_entra_id_e2e",
	paginationPolicyNamePrefix: "sca_cli_cloudaccess_azure_entra_id_pagination_e2e",
	verifyTarget: func(t *testing.T, fetchedPolicy *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, _ *scacloudaccessmodels.IdsecSCAEligibleTarget, response []scacloudaccessmodels.IdsecSCAEligibleTarget) {
		verifyCloudAccessTargetInListTargets(t, fetchedPolicy, response)
	},
}

var azureResourceCloudAccessListTargetsConfig = cloudAccessListTargetsConfig{
	configBlockKey:             "azure_cloudaccess_resource",
	displayName:                "CloudAccess Azure Resource ListTargets",
	csp:                        "AZURE",
	policyNamePrefix:           "sca_cli_cloudaccess_azure_resource_e2e",
	paginationPolicyNamePrefix: "sca_cli_cloudaccess_azure_resource_pagination_e2e",
	verifyTarget: func(t *testing.T, fetchedPolicy *policycloudaccessmodels.IdsecPolicyCloudAccessCloudConsoleAccessPolicy, _ *scacloudaccessmodels.IdsecSCAEligibleTarget, response []scacloudaccessmodels.IdsecSCAEligibleTarget) {
		verifyCloudAccessTargetInListTargets(t, fetchedPolicy, response)
	},
}
