package policy

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	cloudaccess "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/cloudaccess"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/db"
	groupaccess "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/groupaccess"
	policyk8s "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/k8s"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/vm"
)

// IdsecPolicyAPI provides a unified API for accessing various Policy services, including Cloud Console, K8s clusters, VM and DB services.
type IdsecPolicyAPI struct {
	policy      *IdsecPolicyService
	cloudaccess *cloudaccess.IdsecPolicyCloudAccessService
	groupaccess *groupaccess.IdsecPolicyGroupAccessService
	k8s         *policyk8s.IdsecPolicyK8sService
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
	groupAccessService, err := groupaccess.NewIdsecPolicyGroupAccessService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	// K8s cluster policies are served by policy-k8s (distinct from Cloud Console policy-cloudaccess).
	k8sService, err := policyk8s.NewIdsecPolicyK8sService(baseIspAuth)
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
		groupaccess: groupAccessService,
		k8s:         k8sService,
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

// GroupAccess returns the IdsecPolicyGroupAccessService instance from the IdsecPolicyAPI.
func (api *IdsecPolicyAPI) GroupAccess() *groupaccess.IdsecPolicyGroupAccessService {
	return api.groupaccess
}

// K8s returns the IdsecPolicyK8sService instance from the IdsecPolicyAPI.
func (api *IdsecPolicyAPI) K8s() *policyk8s.IdsecPolicyK8sService {
	return api.k8s
}

// Db returns the IdsecPolicyDBService instance from the IdsecPolicyAPI.
func (api *IdsecPolicyAPI) Db() *db.IdsecPolicyDBService {
	return api.db
}

// VM returns the IdsecPolicyVMService instance from the IdsecPolicyAPI.
func (api *IdsecPolicyAPI) VM() *vm.IdsecPolicyVMService {
	return api.vm
}
