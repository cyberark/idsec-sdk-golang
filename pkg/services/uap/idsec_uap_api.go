package uap

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/db"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/uap/sia/vm"
)

// IdsecUAPAPI provides a unified API for accessing various UAP services, including SCA and SIA DB services.
type IdsecUAPAPI struct {
	uap *IdsecUAPService
	db  *db.IdsecUAPSIADBService
	vm  *vm.IdsecUAPSIAVMService
}

// NewIdsecUAPAPI creates a new instance of IdsecUAPAPI with the provided IdsecISPAuth.
func NewIdsecUAPAPI(ispAuth *auth.IdsecISPAuth) (*IdsecUAPAPI, error) {
	var baseIspAuth auth.IdsecAuth = ispAuth
	uapService, err := NewIdsecUAPService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	dbService, err := db.NewIdsecUAPSIADBService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	vmService, err := vm.NewIdsecUAPSIAVMService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	return &IdsecUAPAPI{
		uap: uapService,
		db:  dbService,
		vm:  vmService,
	}, nil
}

// Uap returns the IdsecUAPService instance from the IdsecUAPAPI.
func (api *IdsecUAPAPI) Uap() *IdsecUAPService {
	return api.uap
}

// Db returns the IdsecUAPSIADBService instance from the IdsecUAPAPI.
func (api *IdsecUAPAPI) Db() *db.IdsecUAPSIADBService {
	return api.db
}

// VM returns the IdsecUAPSIAVMService instance from the IdsecUAPAPI.
func (api *IdsecUAPAPI) VM() *vm.IdsecUAPSIAVMService {
	return api.vm
}
