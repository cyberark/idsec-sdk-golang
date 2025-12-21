package policy

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	cloudaccess "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess"
)

// IdsecPolicyAPI provides a unified API for accessing various Policy services, including SCA and SIA DB services.
type IdsecPolicyAPI struct {
	policy      *IdsecPolicyService
	cloudaccess *cloudaccess.IdsecPolicyCloudAccessService
}

// NewIdsecPolicyAPI creates a new instance of IdsecPolicyAPI with the provided IdsecISPAuth.
func NewIdsecPolicyAPI(ispAuth *auth.IdsecISPAuth) (*IdsecPolicyAPI, error) {
	var baseIspAuth auth.IdsecAuth = ispAuth
	policyService, err := NewIdsecPolicyService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	cloudAccessService, err := cloudaccess.NewIdsecPolicyCloudAccessService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	return &IdsecPolicyAPI{
		policy:      policyService,
		cloudaccess: cloudAccessService,
	}, nil
}

// Policy returns the IdsecPolicyService instance from the IdsecPolicyAPI.
func (api *IdsecPolicyAPI) Policy() *IdsecPolicyService {
	return api.policy
}

// CloudAccess returns the IdsecPolicyCloudAccessService instance from the IdsecPolicyAPI.
func (api *IdsecPolicyAPI) CloudAccess() *cloudaccess.IdsecPolicyCloudAccessService {
	return api.cloudaccess
}
