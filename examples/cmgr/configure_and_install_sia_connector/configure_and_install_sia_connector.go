package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr"
	cmgrmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cmgr/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia"
	accessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/access/models"
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

	// Configure a network, pool and identifiers
	cmgrService, err := cmgr.NewIdsecCmgrService(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	network, err := cmgrService.AddNetwork(&cmgrmodels.IdsecCmgrAddNetwork{Name: "tlv"})
	if err != nil {
		panic(err)
	}
	pool, err := cmgrService.AddPool(&cmgrmodels.IdsecCmgrAddPool{Name: "tlvpool", AssignedNetworkIDs: []string{network.NetworkID}})
	if err != nil {
		panic(err)
	}
	identifier, err := cmgrService.AddPoolIdentifier(&cmgrmodels.IdsecCmgrAddPoolSingleIdentifier{PoolID: pool.PoolID, Type: cmgrmodels.GeneralFQDN, Value: "mymachine.tlv.com"})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Added pool: %s\n", pool.PoolID)
	fmt.Printf("Added network: %s\n", network.NetworkID)
	fmt.Printf("Added identifier: %s\n", identifier.IdentifierID)

	// Install a connector on the pool above
	siaAPI, err := sia.NewIdsecSIAAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	connectorID, err := siaAPI.Access().InstallConnector(
		&accessmodels.IdsecSIAInstallConnector{
			ConnectorType:   "ON-PREMISE",
			ConnectorOS:     "linux",
			ConnectorPoolID: pool.PoolID,
			TargetMachine:   "1.1.1.1",
			Username:        "root",
			PrivateKeyPath:  "/path/to/key.pem",
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Installed connector: %s\n", connectorID)
}
