package cce

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/aws"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/azure"
)

// IdsecCCEAPI is a struct that provides access to the CCE API as a wrapped set of services.
type IdsecCCEAPI struct {
	awsService   *aws.IdsecCCEAWSService
	azureService *azure.IdsecCCEAzureService
}

// NewIdsecCCEAPI creates a new instance of IdsecCCEAPI with the provided IdsecISPAuth.
func NewIdsecCCEAPI(ispAuth *auth.IdsecISPAuth) (*IdsecCCEAPI, error) {
	var baseIspAuth auth.IdsecAuth = ispAuth
	awsService, err := aws.NewIdsecCCEAWSService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	azureService, err := azure.NewIdsecCCEAzureService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	return &IdsecCCEAPI{
		awsService:   awsService,
		azureService: azureService,
	}, nil
}

// AWS returns the AWS service of the IdsecCCEAPI instance.
func (api *IdsecCCEAPI) AWS() *aws.IdsecCCEAWSService {
	return api.awsService
}

// Azure returns the Azure service of the IdsecCCEAPI instance.
func (api *IdsecCCEAPI) Azure() *azure.IdsecCCEAzureService {
	return api.azureService
}
