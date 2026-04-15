package cmgr

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/networks"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/poolcomponents"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/poolidentifiers"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/pools"
)

// IdsecCmgrAPI is a struct that provides access to the Idsec CMGR API as a wrapped set of services.
type IdsecCmgrAPI struct {
	networksService        *networks.IdsecCmgrNetworksService
	poolsService           *pools.IdsecCmgrPoolsService
	poolIdentifiersService *poolidentifiers.IdsecCmgrPoolIdentifiersService
	poolComponentsService  *poolcomponents.IdsecCmgrPoolComponentsService
}

// NewIdsecCmgrAPI creates a new instance of IdsecCmgrAPI with the provided IdsecISPAuth.
func NewIdsecCmgrAPI(ispAuth *auth.IdsecISPAuth) (*IdsecCmgrAPI, error) {
	var baseIspAuth auth.IdsecAuth = ispAuth
	networksService, err := networks.NewIdsecCmgrNetworksService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	poolsService, err := pools.NewIdsecCmgrPoolsService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	poolIdentifiersService, err := poolidentifiers.NewIdsecCmgrPoolIdentifiersService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	poolComponentsService, err := poolcomponents.NewIdsecCmgrPoolComponentsService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	return &IdsecCmgrAPI{
		networksService:        networksService,
		poolsService:           poolsService,
		poolIdentifiersService: poolIdentifiersService,
		poolComponentsService:  poolComponentsService,
	}, nil
}

// Networks returns the Networks service of the IdsecCmgrAPI instance.
func (api *IdsecCmgrAPI) Networks() *networks.IdsecCmgrNetworksService {
	return api.networksService
}

// Pools returns the Pools service of the IdsecCmgrAPI instance.
func (api *IdsecCmgrAPI) Pools() *pools.IdsecCmgrPoolsService {
	return api.poolsService
}

// PoolIdentifiers returns the Pool Identifiers service of the IdsecCmgrAPI instance.
func (api *IdsecCmgrAPI) PoolIdentifiers() *poolidentifiers.IdsecCmgrPoolIdentifiersService {
	return api.poolIdentifiersService
}

// PoolComponents returns the Pool Components service of the IdsecCmgrAPI instance.
func (api *IdsecCmgrAPI) PoolComponents() *poolcomponents.IdsecCmgrPoolComponentsService {
	return api.poolComponentsService
}
