package internal

import (
	"encoding/json"
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// IdentityParamsResponse holds the parsed result of a GET identity-params API call.
type IdentityParamsResponse struct {
	TenantID       string
	IdentityParams map[string]ccemodels.IdsecCCEWorkloadFederation
}

// ParseIdentityParamsResponse parses the raw JSON body from a GET /api/{platform}/identity-params endpoint.
// The API returns tenantId at root level alongside service-keyed WIF objects.
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
