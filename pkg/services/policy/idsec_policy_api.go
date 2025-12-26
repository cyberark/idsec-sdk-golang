package policy

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	cloudaccess "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/db"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/vm"
)

// IdsecPolicyAPI provides a unified API for accessing various Policy services, including Cloud Console, VM and DB services.
type IdsecPolicyAPI struct {
	policy      *IdsecPolicyService
	cloudaccess *cloudaccess.IdsecPolicyCloudAccessService
	db          *db.IdsecPolicyDBService
	vm          *vm.IdsecPolicyVMService
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
	dbService, err := db.NewIdsecPolicyDBService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	vmService, err := vm.NewIdsecPolicyVMService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	return &IdsecPolicyAPI{
		policy:      policyService,
		cloudaccess: cloudAccessService,
		db:          dbService,
		vm:          vmService,
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

// Db returns the IdsecPolicyDBService instance from the IdsecPolicyAPI.
func (api *IdsecPolicyAPI) Db() *db.IdsecPolicyDBService {
	return api.db
}

// VM returns the IdsecPolicyVMService instance from the IdsecPolicyAPI.
func (api *IdsecPolicyAPI) VM() *vm.IdsecPolicyVMService {
	return api.vm
}
