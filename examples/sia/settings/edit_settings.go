package main

import (
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia"
	settingsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/settings/models"
)

func main() {
	// Perform authentication using IdsecISPAuth to the platform
	// First, create an ISP authentication class
	// Afterwards, perform the authentication
	ispAuth := auth.NewIdsecISPAuth(false)
	_, err := ispAuth.Authenticate(
		nil,
		&authmodels.IdsecAuthProfile{
			Username:           "user@cyberark.cloud.12345",
			AuthMethod:         authmodels.Identity,
			AuthMethodSettings: &authmodels.IdentityIdsecAuthMethodSettings{},
		},
		&authmodels.IdsecSecret{
			Secret: os.Getenv("IDSEC_SECRET"),
		},
		false,
		false,
	)
	if err != nil {
		panic(err)
	}
	siaAPI, err := sia.NewIdsecSIAAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}

	// Load all settings
	settings, err := siaAPI.Settings().ListSettings()
	if err != nil {
		panic(err)
	}
	settings.AdbMfaCaching.IsMfaCachingEnabled = common.Ptr(false)

	// Update settings
	_, err = siaAPI.Settings().SetSettings(settings)
	if err != nil {
		panic(err)
	}

	// Set specific setting partially
	adbMfa := &settingsmodels.IdsecSIASettingsAdbMfaCaching{
		KeyExpirationTimeSec: common.Ptr(7200),
		ClientIPEnforced:     common.Ptr(false),
	}
	_, err = siaAPI.Settings().SetAdbMfaCaching(adbMfa)
	if err != nil {
		panic(err)
	}
}
