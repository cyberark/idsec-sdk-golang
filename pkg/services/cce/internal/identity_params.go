package internal

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// IdentityParamsResponse holds the parsed result of a GET identity-params API call.
type IdentityParamsResponse struct {
	TenantID       string
	IdentityParams map[string]ccemodels.IdsecCCEWorkloadFederation
}

// AWS ARN format: arn:partition:service:region:account-id:resource
// Example:        arn:aws:iam::403839327297:role/DiscoveryServiceRole
const (
	arnPartCount  = 6 // total colon-separated segments in a well-formed ARN
	arnAccountIdx = 4 // zero-based index of the account-id segment
)

// arnAccountID extracts the AWS account ID from a standard IAM ARN.
// Example: "arn:aws:iam::403839327297:role/DiscoveryServiceRole" → "403839327297"
func arnAccountID(arn string) string {
	parts := strings.SplitN(arn, ":", arnPartCount)
	if len(parts) == arnPartCount {
		return parts[arnAccountIdx]
	}
	return ""
}

// ParseIdentityParamsResponse parses the raw JSON body from a GET /api/{platform}/identity-params endpoint.
// The API returns tenantId at root level alongside service-keyed WIF objects.
// Services using OIDC (e.g. cloud_onboarding, sca) return identity_app_id / identity_user_id fields.
// Services using AWS IAM roles (e.g. dpa) return global_role_arn; those are mapped to
// IdentityAppID (account ID) and IdentityUserID (full ARN) for uniform downstream consumption.
func ParseIdentityParamsResponse(body []byte, logger *common.IdsecLogger) (*IdentityParamsResponse, error) {
	var rawResponse map[string]interface{}
	if err := json.Unmarshal(body, &rawResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal identity parameters: %w", err)
	}

	tenantID, _ := rawResponse["tenantId"].(string)

	paramsMap := make(map[string]ccemodels.IdsecCCEWorkloadFederation)
	for key, value := range rawResponse {
		if key == "tenantId" {
			continue
		}

		valueBytes, err := json.Marshal(value)
		if err != nil {
			logger.Warning("Failed to marshal identity param for service %s: %v", key, err)
			continue
		}

		// AWS IAM role-based services (e.g. dpa) return global_role_arn.
		// Try that shape first; if it matches, map to the uniform WIF fields and move on.
		var awsWIF ccemodels.IdsecCCEAwsWorkloadFederation
		if err := json.Unmarshal(valueBytes, &awsWIF); err == nil && awsWIF.GlobalRoleARN != "" {
			paramsMap[key] = ccemodels.IdsecCCEWorkloadFederation{
				IdentityAppID:  arnAccountID(awsWIF.GlobalRoleARN),
				IdentityUserID: awsWIF.GlobalRoleARN,
			}
			continue
		}

		// OIDC-based services (e.g. cloud_onboarding, sca) return identity_app_id / identity_user_id.
		var wif ccemodels.IdsecCCEWorkloadFederation
		if err := json.Unmarshal(valueBytes, &wif); err != nil {
			logger.Warning("Failed to unmarshal identity param for service %s: %v", key, err)
			continue
		}
		paramsMap[key] = wif
	}

	return &IdentityParamsResponse{
		TenantID:       tenantID,
		IdentityParams: paramsMap,
	}, nil
}
