package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia"
	certificatesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/certificates/models"
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

	// Add a new certificate
	cert, err := siaAPI.Certificates().AddCertificate(
		&certificatesmodels.IdsecSIACertificatesAddCertificate{
			CertName:        "My New SIA Certificate",
			CertDescription: "Certificate added via SDK example",
			File:            "/path/to/file",
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Added certificate: %+v\n", cert)
}
