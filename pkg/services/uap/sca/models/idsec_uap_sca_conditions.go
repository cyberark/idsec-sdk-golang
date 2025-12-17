package models

import (
	uapcommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/uap/common/models"
)

// IdsecUAPSCAConditions represents SCA-specific conditions.
// It is currently identical to IdsecUAPConditions but defined separately for clarity
// and future extensibility without refactoring the IdsecUAPSCACloudConsoleAccessPolicy model.
type IdsecUAPSCAConditions struct {
	uapcommonmodels.IdsecUAPConditions `mapstructure:",squash"`
}
