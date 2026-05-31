package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia"
	sshmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/ssh/models"
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

	// Mode 1: Run a single command on the remote target through the SIA SSH
	// gateway. Output is streamed to this process' stdout/stderr.
	fmt.Println("Running single command via SIA SSH gateway...")
	if err := siaAPI.Ssh().Connect(&sshmodels.IdsecSIASSHConnectExecution{
		IdsecSIASSHBaseExecution: sshmodels.IdsecSIASSHBaseExecution{
			TargetAddress:  "10.0.0.42",
			TargetUsername: "ec2-user",
		},
		Command: "uname -a && id",
	}); err != nil {
		panic(err)
	}

	// Mode 2: Open an interactive terminal session through the SIA SSH gateway.
	// Omit Command to get an interactive shell — stdin/stdout/stderr are wired
	// to the parent process, matching the UX of the DB service's interactive
	// clients.
	fmt.Println("Opening interactive SSH terminal via SIA SSH gateway...")
	if err := siaAPI.Ssh().Connect(&sshmodels.IdsecSIASSHConnectExecution{
		IdsecSIASSHBaseExecution: sshmodels.IdsecSIASSHBaseExecution{
			TargetAddress:  "10.0.0.42",
			TargetUsername: "ec2-user",
		},
	}); err != nil {
		panic(err)
	}
}
