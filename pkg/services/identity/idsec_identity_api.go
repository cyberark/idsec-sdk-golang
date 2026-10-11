// Package identity provides the Identity service API, which wraps the individual Identity services.
package identity

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/authprofiles"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/directories"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/policies"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/roles"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/tenantsuffixes"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/users"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/webapps"
)

// IdsecIdentityAPI is a struct that provides access to the Idsec Identity API as a wrapped set of services.
type IdsecIdentityAPI struct {
	directoriesService    *directories.IdsecIdentityDirectoriesService
	rolesService          *roles.IdsecIdentityRolesService
	usersService          *users.IdsecIdentityUsersService
	authProfilesService   *authprofiles.IdsecIdentityAuthProfilesService
	policiesService       *policies.IdsecIdentityPoliciesService
	webappsService        *webapps.IdsecIdentityWebappsService
	tenantSuffixesService *tenantsuffixes.IdsecIdentityTenantSuffixesService
}

// NewIdsecIdentityAPI creates a new instance of IdsecIdentityAPI with the provided IdsecISPAuth.
func NewIdsecIdentityAPI(ispAuth *auth.IdsecISPAuth) (*IdsecIdentityAPI, error) {
	var baseIspAuth auth.IdsecAuth = ispAuth
	directoriesService, err := directories.NewIdsecIdentityDirectoriesService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	rolesService, err := roles.NewIdsecIdentityRolesService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	usersService, err := users.NewIdsecIdentityUsersService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	authProfilesService, err := authprofiles.NewIdsecIdentityAuthProfilesService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	policiesService, err := policies.NewIdsecIdentityPoliciesService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	webappsService, err := webapps.NewIdsecIdentityWebappsService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	tenantSuffixesService, err := tenantsuffixes.NewIdsecIdentityTenantSuffixesService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	return &IdsecIdentityAPI{
		directoriesService:    directoriesService,
		rolesService:          rolesService,
		usersService:          usersService,
		authProfilesService:   authProfilesService,
		policiesService:       policiesService,
		webappsService:        webappsService,
		tenantSuffixesService: tenantSuffixesService,
	}, nil
}

// Directories returns the Directories service of the IdsecIdentityAPI instance.
func (api *IdsecIdentityAPI) Directories() *directories.IdsecIdentityDirectoriesService {
	return api.directoriesService
}

// Roles returns the Roles service of the IdsecIdentityAPI instance.
func (api *IdsecIdentityAPI) Roles() *roles.IdsecIdentityRolesService {
	return api.rolesService
}

// Users returns the Users service of the IdsecIdentityAPI instance.
func (api *IdsecIdentityAPI) Users() *users.IdsecIdentityUsersService {
	return api.usersService
}

// AuthProfiles returns the Auth Profiles service of the IdsecIdentityAPI instance.
func (api *IdsecIdentityAPI) AuthProfiles() *authprofiles.IdsecIdentityAuthProfilesService {
	return api.authProfilesService
}

// Policies returns the Policies service of the IdsecIdentityAPI instance.
func (api *IdsecIdentityAPI) Policies() *policies.IdsecIdentityPoliciesService {
	return api.policiesService
}

// Webapps returns the Webapps service of the IdsecIdentityAPI instance.
func (api *IdsecIdentityAPI) Webapps() *webapps.IdsecIdentityWebappsService {
	return api.webappsService
}

// TenantSuffixes returns the Tenant Suffixes service of the IdsecIdentityAPI instance.
//
// Not to be confused with Directories().TenantSuffixes(), which is a read-only discovery helper
// returning the tenant's suffix list and its default. That helper calls Core/GetCdsAliasesForTenant
// and reports the stored ROW KEY, so on a tenant with the suffixless fix enabled it does not see the
// suffixes this service manages. This service is the CRUD surface for an individual suffix.
func (api *IdsecIdentityAPI) TenantSuffixes() *tenantsuffixes.IdsecIdentityTenantSuffixesService {
	return api.tenantSuffixesService
}
