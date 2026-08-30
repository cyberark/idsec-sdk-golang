package models

import (
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// IdsecCCEWorkloadFederation is an alias for the shared workload federation struct.
// Kept for backward compatibility with existing code that references this type.
type IdsecCCEWorkloadFederation = ccemodels.IdsecCCEWorkloadFederation

// TfIdsecCCEAzureGetIdentityParams is the Azure-specific alias for the shared input type.
type TfIdsecCCEAzureGetIdentityParams = ccemodels.TfIdsecCCEGetIdentityParams

// TfIdsecCCEAzureIdentityParams is the Azure-specific alias for the shared output type.
type TfIdsecCCEAzureIdentityParams = ccemodels.TfIdsecCCEIdentityParams
