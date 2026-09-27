package k8s

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/golang-jwt/jwt/v5"

	scak8sazurecommonhelper "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/azure/common"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

const (
	// Well-known AKS AAD server app; scope "<id>/.default" yields an AKS-scoped token (no exchange).
	aksServerAppID = "6dae42f8-4368-4678-94ff-3960e28e3630"
	aksTokenScope  = aksServerAppID + "/.default"
	aksExecCredAPI = "client.authentication.k8s.io/v1beta1"

	acquireAKSTokenTimeout   = 30 * time.Second
	aksExecCredRefreshBuffer = 60 * time.Second // subtract from JWT exp for ExecCredential.expirationTimestamp
)

// AzureTokenProvider: AKS token via local az session; validates az identity vs the Elevate cloudUserName.
type AzureTokenProvider struct{}

func (p *AzureTokenProvider) CSP() string { return k8smodels.CSPAzure }

// GenerateToken returns an AKS ExecCredential after EnsureAzureCLISession (diagnostics gated by ctx.Diagnostics).
func (p *AzureTokenProvider) GenerateToken(
	result *k8smodels.IdsecSCAK8sElevateResult,
	ctx *IdsecSCAK8sClusterContext,
) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	if ctx == nil {
		return nil, fmt.Errorf("cluster context cannot be nil")
	}

	accessToken, err := EnsureAzureCLISession(ctx.OrganizationID, result, ctx.Diagnostics)
	if err != nil {
		return nil, err
	}
	return BuildAzureExecCredential(accessToken), nil
}

// EnsureAzureCLISession obtains an AKS token via az; may run az login / account set.
// Subscription and expected cloud user are both derived from the Elevate result.
// diagnostics gates stderr logs.
func EnsureAzureCLISession(
	organizationID string,
	result *k8smodels.IdsecSCAK8sElevateResult,
	diagnostics bool,
) (string, error) {
	if result == nil {
		return "", fmt.Errorf("elevate result cannot be nil")
	}
	cloudUserName := strings.TrimSpace(result.CloudUserName)
	subscriptionID := strings.TrimSpace(AzureSubscriptionFromTargetID(result.TargetID))

	// Announced before the session is resolved so the requirement is stated
	// whether az is already signed in or a fresh login is about to run.
	announceExpectedAzureCloudUser(cloudUserName)

	accessToken, err := acquireAKSToken(organizationID)
	if err != nil && subscriptionID != "" && azureCLIErrNeedsSubscription(err) {
		if setErr := runAzAccountSet(subscriptionID); setErr != nil {
			if diagnostics {
				KubectlLoginLog(KubectlLoginLogLevelInfo, "az account set --subscription %s: %v", subscriptionID, setErr)
			}
		} else {
			accessToken, err = acquireAKSToken(organizationID)
		}
	}
	if err != nil {
		if diagnostics {
			KubectlLoginLog(KubectlLoginLogLevelInfo, "No usable az login session found. Running 'az login'...")
		}
		if loginErr := runAzLogin(); loginErr != nil {
			return "", fmt.Errorf("az login failed: %w", loginErr)
		}
		if subscriptionID != "" {
			if setErr := runAzAccountSet(subscriptionID); setErr != nil {
				if diagnostics {
					KubectlLoginLog(KubectlLoginLogLevelInfo, "az account set --subscription %s: %v", subscriptionID, setErr)
				}
			}
		}
		accessToken, err = acquireAKSToken(organizationID)
		if err != nil {
			return "", fmt.Errorf("failed to acquire AKS token after az login: %w", err)
		}
	}

	if err := validateAzureCLIIdentity(cloudUserName, accessToken); err != nil {
		return "", err
	}
	return accessToken, nil
}

func azureCLIErrNeedsSubscription(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no subscription found") ||
		strings.Contains(s, "run 'az account set'")
}

// VerifyAzureCLISession acquires an AKS token via az without interactive login; use after cache hit before trusting token.
func VerifyAzureCLISession(organizationID string, result *k8smodels.IdsecSCAK8sElevateResult) (string, error) {
	if result == nil {
		return "", fmt.Errorf("elevate result cannot be nil")
	}
	cloudUserName := strings.TrimSpace(result.CloudUserName)
	announceExpectedAzureCloudUser(cloudUserName)

	accessToken, err := acquireAKSToken(organizationID)
	if err != nil {
		return "", fmt.Errorf("no active az login session: %w", err)
	}
	if err := validateAzureCLIIdentity(cloudUserName, accessToken); err != nil {
		return "", err
	}
	return accessToken, nil
}

// BuildAzureExecCredential builds client.authentication.k8s.io/v1beta1 ExecCredential; expirationTimestamp = JWT exp − aksExecCredRefreshBuffer when exp parses.
func BuildAzureExecCredential(accessToken string) *k8smodels.IdsecSCAK8sExecCredential {
	cred := &k8smodels.IdsecSCAK8sExecCredential{
		APIVersion: aksExecCredAPI,
		Kind:       "ExecCredential",
		Status: k8smodels.IdsecSCAK8sExecCredentialStatus{
			Token: accessToken,
		},
	}
	if exp, err := ParseAccessTokenExpiry(accessToken); err == nil {
		cred.Status.ExpirationTimestamp = exp.Add(-aksExecCredRefreshBuffer).UTC().Format(time.RFC3339)
	}
	return cred
}

// acquireAKSToken shells out to az (AzureCLICredential); organizationID sets Entra tenant when non-empty.
func acquireAKSToken(organizationID string) (string, error) {
	opts := &azidentity.AzureCLICredentialOptions{}
	if organizationID != "" {
		opts.TenantID = organizationID
	}

	cred, err := azidentity.NewAzureCLICredential(opts)
	if err != nil {
		return "", fmt.Errorf("create Azure CLI credential: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), acquireAKSTokenTimeout)
	defer cancel()

	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{aksTokenScope},
	})
	if err != nil {
		return "", fmt.Errorf("get AKS token via Azure CLI: %w", err)
	}

	return token.Token, nil
}

// runAzLogin: stdout discarded so parent stdout stays clean for kubectl ExecCredential JSON.
func runAzLogin() error {
	cmd := exec.Command("az", "login")
	cmd.Stdin = os.Stdin
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("'az login' exited with error: %w", err)
	}
	return nil
}

func runAzAccountSet(subscriptionID string) error {
	cmd := exec.Command("az", "account", "set", "--subscription", subscriptionID)
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("'az account set' exited with error: %w", err)
	}
	return nil
}

// announceExpectedAzureCloudUser tells the user which account the az session must
// belong to, whether one already exists or 'az login' is about to run. Written to
// stderr because stdout carries the kubectl ExecCredential JSON, and emitted
// unfiltered so a restrictive log level cannot hide it.
func announceExpectedAzureCloudUser(cloudUserName string) {
	if cloudUserName == "" {
		return
	}
	KubectlLoginLogLine(os.Stderr, KubectlLoginLogLevelWarning,
		"az login must use the elevated user %s; any other account will be rejected.",
		cloudUserName,
	)
}

// validateAzureCLIIdentity fails when the az login account is not the elevated
// cloud user. Skipped when the Elevate API did not return cloudUserName, so the
// CLI keeps working against backends that predate the field.
func validateAzureCLIIdentity(cloudUserName, azureAccessToken string) error {
	if cloudUserName == "" {
		return nil
	}

	azureID, err := extractAzureJWTIdentity(
		azureAccessToken,
		[]string{"upn", "preferred_username", "unique_name"},
	)
	if err != nil {
		return fmt.Errorf("failed to extract identity from Azure access token: %w", err)
	}

	if scak8sazurecommonhelper.CloudUserMatches(cloudUserName, azureID) {
		return nil
	}

	return fmt.Errorf( //nolint:staticcheck // ST1005: surfaced verbatim to the user as a sentence.
		"az is logged in as %s, which is not the elevated user; "+
			"run 'az logout'; az login must use %s user.",
		azureID.Name(), cloudUserName,
	)
}

func extractAzureJWTIdentity(tokenString string, upnClaimKeys []string) (scak8sazurecommonhelper.JWTIdentity, error) {
	claims, err := parseJWTMapClaims(tokenString)
	if err != nil {
		return scak8sazurecommonhelper.JWTIdentity{}, err
	}

	id := scak8sazurecommonhelper.JWTIdentity{
		UPN:   firstStringClaim(claims, upnClaimKeys...),
		Email: firstStringClaim(claims, "email"),
	}
	if id.UPN == "" && id.Email == "" {
		return scak8sazurecommonhelper.JWTIdentity{}, fmt.Errorf("no identity claim found (upn keys=%v, email)", upnClaimKeys)
	}
	return id, nil
}

// ParseAccessTokenExpiry returns JWT exp (ParseUnverified) for keyring TTL and ExecCredential hints.
func ParseAccessTokenExpiry(tokenString string) (time.Time, error) {
	claims, err := parseJWTMapClaims(tokenString)
	if err != nil {
		return time.Time{}, err
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return time.Time{}, fmt.Errorf("JWT has no exp claim")
	}
	return exp.UTC(), nil
}

func parseJWTMapClaims(tokenString string) (jwt.MapClaims, error) {
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected JWT claims type")
	}
	return claims, nil
}

func firstStringClaim(claims jwt.MapClaims, keys ...string) string {
	for _, key := range keys {
		if val, exists := claims[key]; exists {
			if s, ok := val.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}
