//go:build (e2e && sca) || e2e

package k8s

import (
	"testing"

	policyk8s "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/k8s"
	k8sservice "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
	scahelpers "github.com/cyberark/idsec-sdk-golang/tests/e2e/sca"
)

// TestK8sAWSKubelogin creates an AWS K8s policy, verifies ListTargets eligibility,
// then exercises the kubectl-login path by elevating and building an ExecCredential token.
func TestK8sAWSKubelogin(t *testing.T) {
	framework.LogSection(t, "Test: K8s AWS Clusters Kubelogin")
	testCtx := scahelpers.SetupK8sListTargetsTest(t, scahelpers.AWSK8sListTargetsConfig, true)

	framework.Run(t, func(ctx *framework.TestContext) {
		// K8s cluster policies are created via policy-k8s (not Cloud Console policy-cloudaccess).
		policySvc := scahelpers.MustPolicyK8sService(t, ctx)
		principal := scahelpers.CloudAccessPrincipalFromConfig(t, testCtx)
		target := scahelpers.K8sTargetFromConfig(t, scahelpers.AWSK8sListTargetsConfig, testCtx, 0)
		createdPolicyID := scahelpers.CreateK8sPolicy(t, policySvc, scahelpers.AWSK8sListTargetsConfig, principal, target, "sca_cli_k8s_aws_kubelogin_e2e")
		defer scahelpers.DeletePolicyBestEffort(t, createdPolicyID, policySvc.DeletePolicy)

		k8sSvc := scahelpers.MustPrincipalK8sService(t, testCtx)
		filteredResp := scahelpers.ListK8sTargets(t, k8sSvc, scahelpers.AWSK8sListTargetsConfig.CSP, target.PolicyTarget.WorkspaceID, 20)
		scahelpers.VerifyK8sFilteredTargets(t, target, filteredResp)

		elevateResp := scahelpers.ElevateK8sKubeloginTarget(t, k8sSvc, target)
		scahelpers.VerifyAWSK8sKubelogin(t, elevateResp, target)
	}, k8sservice.ServiceConfig, policyk8s.ServiceConfig)
}
