//go:build (e2e && sca) || e2e

package k8s

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	policyk8s "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/k8s"
	k8sservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
	scahelpers "github.com/cyberark/idsec-sdk-golang/tests/e2e/sca"
)

// TestK8sAWSGenerateKubeconfig creates an AWS K8s policy, verifies ListTargets eligibility,
// then calls GenerateKubeconfig and validates the returned AWS kubeconfig YAML.
func TestK8sAWSGenerateKubeconfig(t *testing.T) {
	framework.LogSection(t, "Test: K8s AWS Clusters Generate Kubeconfig")
	testCtx := scahelpers.SetupK8sListTargetsTest(t, scahelpers.AWSK8sListTargetsConfig, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		// K8s cluster policies are created via policy-k8s (not Cloud Console policy-cloudaccess).
		policySvc := scahelpers.MustPolicyK8sService(t, ctx)
		principal := scahelpers.CloudAccessPrincipalFromConfig(t, testCtx)
		target := scahelpers.K8sTargetFromConfig(t, scahelpers.AWSK8sListTargetsConfig, testCtx, 0)
		createdPolicyID := scahelpers.CreateK8sPolicy(t, policySvc, scahelpers.AWSK8sListTargetsConfig, principal, target, scahelpers.AWSK8sListTargetsConfig.PolicyNamePrefix)
		defer scahelpers.DeletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		k8sSvc := scahelpers.MustPrincipalK8sService(t, testCtx)
		filteredResp := scahelpers.ListK8sTargets(t, k8sSvc, scahelpers.AWSK8sListTargetsConfig.CSP, target.PolicyTarget.WorkspaceID, 20)
		scahelpers.VerifyK8sFilteredTargets(t, target, filteredResp)

		generateResp, err := k8sSvc.GenerateKubeconfig(&k8smodels.IdsecSCAK8sGenerateKubeconfigRequest{
			CSP: "aws",
		})
		require.NoError(t, err)
		require.NotEmpty(t, generateResp, "GenerateKubeconfig response should not be empty")

		kubeconfigYAML := strings.TrimSpace(generateResp["aws"])
		require.NotEmpty(t, kubeconfigYAML, "GenerateKubeconfig should return AWS kubeconfig YAML")
		scahelpers.VerifyAWSKubeconfigEligibilityDetails(t, kubeconfigYAML, target)
	}, k8sservice.ServiceConfig, policyk8s.ServiceConfig)
}
