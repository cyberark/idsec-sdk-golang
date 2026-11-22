package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/ars/requests"
	requestsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/ars/requests/models"
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

	// Create an ARS requests service from the authenticator above
	requestsService, err := requests.NewIdsecARSRequestsService(ispAuth)
	if err != nil {
		panic(err)
	}

	// List the request form of VM on demand requests, to know which details to provide
	forms, err := requestsService.ListRequestForms(&requestsmodels.IdsecARSListAccessRequestForms{
		TargetCategory: requestsmodels.TargetCategoryVM,
	})
	if err != nil {
		panic(err)
	}
	for _, form := range forms.RequestForms {
		for _, question := range form.RequestForm.Questions {
			fmt.Printf("Question: %s (%s) - required: %v\n", question.Key, question.ValueType, question.Required)
		}
	}

	// Submit an access request answering the request form, and poll until it is pending approval
	request, err := requestsService.Submit(&requestsmodels.IdsecARSSubmitAccessRequest{
		TargetCategory: requestsmodels.TargetCategoryVM,
		RequestDetails: map[string]interface{}{
			"target_host": "10.0.0.1",
			"reason":      "Troubleshooting",
		},
		Poll: true,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Access request %s is %s\n", request.RequestID, request.RequestState)

	// List the access requests, newest first
	pages, err := requestsService.ListBy(&requestsmodels.IdsecARSFilter{
		Sort: []requestsmodels.IdsecARSSortQuery{{Field: "createdAt", Direction: requestsmodels.SortDirectionDesc}},
	})
	if err != nil {
		panic(err)
	}
	for page := range pages {
		for _, accessRequest := range page.Items {
			fmt.Printf("Access request: %s (%s) - %s\n", accessRequest.RequestID, accessRequest.TargetCategory, accessRequest.RequestState)
		}
	}
}
