package cli

import (
	api "github.com/cyberark/idsec-sdk-golang/pkg"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
)

// IdsecCLIAPI is a struct that represents the Idsec CLI API client.
type IdsecCLIAPI struct {
	api.IdsecAPI
}

// NewIdsecCLIAPI creates a new instance of IdsecCLIAPI.
func NewIdsecCLIAPI(authenticators []auth.IdsecAuth, profile *models.IdsecProfile) (*IdsecCLIAPI, error) {
	idsecAPI, err := api.NewIdsecAPI(authenticators, profile)
	if err != nil {
		return nil, err
	}
	return &IdsecCLIAPI{
		IdsecAPI: *idsecAPI,
	}, nil
}
