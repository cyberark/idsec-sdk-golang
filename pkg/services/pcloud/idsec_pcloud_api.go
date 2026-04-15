package pcloud

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/applications"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/platforms"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/targetplatforms"
)

// IdsecPCloudAPI is a struct that provides access to the Idsec PCloud API as a wrapped set of services.
type IdsecPCloudAPI struct {
	safesService           *safes.IdsecPCloudSafesService
	accountsService        *accounts.IdsecPCloudAccountsService
	platformsService       *platforms.IdsecPCloudPlatformsService
	targetPlatformsService *targetplatforms.IdsecPCloudTargetPlatformsService
	applicationsService    *applications.IdsecPCloudApplicationsService
}

// NewIdsecPCloudAPI creates a new instance of IdsecPCloudAPI with the provided IdsecISPAuth.
func NewIdsecPCloudAPI(ispAuth *auth.IdsecISPAuth) (*IdsecPCloudAPI, error) {
	var baseIspAuth auth.IdsecAuth = ispAuth
	safesService, err := safes.NewIdsecPCloudSafesService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	accountsService, err := accounts.NewIdsecPCloudAccountsService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	platformsService, err := platforms.NewIdsecPCloudPlatformsService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	targetPlatformsService, err := targetplatforms.NewIdsecPCloudTargetPlatformsService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	applicationsService, err := applications.NewIdsecPCloudApplicationsService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	return &IdsecPCloudAPI{
		safesService:           safesService,
		accountsService:        accountsService,
		platformsService:       platformsService,
		targetPlatformsService: targetPlatformsService,
		applicationsService:    applicationsService,
	}, nil
}

// Safes returns the Safes service of the IdsecPCloudAPI instance.
func (api *IdsecPCloudAPI) Safes() *safes.IdsecPCloudSafesService {
	return api.safesService
}

// Accounts returns the Accounts service of the IdsecPCloudAPI instance.
func (api *IdsecPCloudAPI) Accounts() *accounts.IdsecPCloudAccountsService {
	return api.accountsService
}

// Platforms returns the Platforms service of the IdsecPCloudAPI instance.
func (api *IdsecPCloudAPI) Platforms() *platforms.IdsecPCloudPlatformsService {
	return api.platformsService
}

// TargetPlatforms returns the Target Platforms service of the IdsecPCloudAPI instance.
func (api *IdsecPCloudAPI) TargetPlatforms() *targetplatforms.IdsecPCloudTargetPlatformsService {
	return api.targetPlatformsService
}

// Applications returns the Applications service of the IdsecPCloudAPI instance.
func (api *IdsecPCloudAPI) Applications() *applications.IdsecPCloudApplicationsService {
	return api.applicationsService
}
