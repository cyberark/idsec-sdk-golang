package pamsh

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshsafes"
)

// IdsecPamshAPI groups PAM self-hosted SDK services that call PAS REST on the PVWA host (not the HTML UI).
type IdsecPamshAPI struct {
	accountsService *pamshaccounts.IdsecPamshAccountsService
	safesService    *pamshsafes.IdsecPamshSafesService
}

// NewIdsecPamshAPI builds an API facade backed by an authenticated PVWA authenticator.
func NewIdsecPamshAPI(pvwaAuth *auth.IdsecPVWAAuth) (*IdsecPamshAPI, error) {
	if pvwaAuth == nil {
		return nil, fmt.Errorf("pamsh: PVWA authenticator is required")
	}
	var base auth.IdsecAuth = pvwaAuth
	acct, err := pamshaccounts.NewIdsecPamshAccountsService(base)
	if err != nil {
		return nil, err
	}
	safesSvc, err := pamshsafes.NewIdsecPamshSafesService(base)
	if err != nil {
		return nil, err
	}
	return &IdsecPamshAPI{
		accountsService: acct,
		safesService:    safesSvc,
	}, nil
}

// Accounts returns the pamsh pamshaccounts service.
func (api *IdsecPamshAPI) Accounts() *pamshaccounts.IdsecPamshAccountsService {
	return api.accountsService
}

// Safes returns the pamsh pamshsafes service.
func (api *IdsecPamshAPI) Safes() *pamshsafes.IdsecPamshSafesService {
	return api.safesService
}
