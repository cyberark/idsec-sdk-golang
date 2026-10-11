package actions

import onboardingmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretsonboarding/models"

// ActionToSchemaMap defines the mapping between Secrets Hub secret onboarding action names
// and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"create": &onboardingmodels.IdsecSecHubOnboardSecret{},
}
