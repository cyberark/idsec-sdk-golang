package gcp

import (
	"fmt"

	gcpmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/gcp/models"
	cceinternal "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

// API path constant for GCP manual onboarding
const (
	pathManualBaseURL = "/api/gcp/manual"
)

// manual returns a ManualClient bound to this service's ISP client and the GCP manual base path.
func (s *IdsecCCEGCPService) manual() *cceinternal.ManualClient {
	return cceinternal.NewManualClient(s.ISPClient(), s.Logger, pathManualBaseURL)
}

// tfAddProject adds a GCP Project manually.
// After creation, it retrieves the full Project details with retry logic (3 attempts, 1 second delay).
// API: POST /api/gcp/manual
func (s *IdsecCCEGCPService) tfAddProject(input *gcpmodels.TfIdsecCCEGCPAddProject) (*gcpmodels.TfIdsecCCEGCPProject, error) {
	s.Logger.Info("Adding GCP Project with ID [%s]", input.ProjectID)

	requestBody, err := cceinternal.StructToMap(input)
	if err != nil {
		return nil, err
	}

	id, err := s.manual().Create(requestBody, cceinternal.DeploymentTypeStandalone)
	if err != nil {
		return nil, err
	}

	// Retrieve the full Project details with retry
	s.Logger.Info("Retrieving Project details for ID [%s]", id)
	project, err := cceinternal.GetWithRetry(s.Logger, "Project", func() (*gcpmodels.TfIdsecCCEGCPProject, error) {
		return s.TfProject(&gcpmodels.TfIdsecCCEGCPGetProject{ID: id})
	})
	if err != nil {
		return nil, fmt.Errorf("project created with ID %s, but failed to fetch details: %w", id, err)
	}

	return project, nil
}

// tfUpdateProject updates a GCP Project's services.
// Compares the desired services in the input with the current services on the Project,
// then adds new services and removes services that are no longer desired.
// API: POST/DELETE /api/gcp/manual/{id}/services
func (s *IdsecCCEGCPService) tfUpdateProject(input *gcpmodels.TfIdsecCCEGCPUpdateProject) (*gcpmodels.TfIdsecCCEGCPProject, error) {
	s.Logger.Info("Updating GCP Project [%s]", input.ID)

	// Step 1: Get current Project services
	currentServiceNames, err := s.manual().CurrentServiceNames(fmt.Sprintf(pathProjectGetURL, input.ID))
	if err != nil {
		return nil, err
	}

	// Step 2: Use shared update logic to reconcile services
	err = s.manual().UpdateServices(input.ID, currentServiceNames, input.Services, "project")
	if err != nil {
		return nil, err
	}

	// Step 3: Fetch and return updated Project details
	s.Logger.Info("Fetching full details for Project [%s]", input.ID)
	fullProject, err := cceinternal.GetWithRetry(s.Logger, "Project", func() (*gcpmodels.TfIdsecCCEGCPProject, error) {
		return s.TfProject(&gcpmodels.TfIdsecCCEGCPGetProject{ID: input.ID})
	})
	if err != nil {
		return nil, fmt.Errorf("project updated with ID %s, but failed to fetch details: %w", input.ID, err)
	}

	return fullProject, nil
}

// tfDeleteProject deletes a GCP Project.
// API: DELETE /api/gcp/manual/{id}
func (s *IdsecCCEGCPService) tfDeleteProject(input *gcpmodels.TfIdsecCCEGCPDeleteProject) error {
	s.Logger.Info("Deleting GCP Project [%s]", input.ID)
	return s.manual().Delete(input.ID)
}

// tfAddOrganization adds a GCP organization manually.
// After creation, it retrieves the full organization details with retry logic (3 attempts, 1 second delay).
// API: POST /api/gcp/manual
func (s *IdsecCCEGCPService) tfAddOrganization(input *gcpmodels.TfIdsecCCEGCPAddOrganization) (*gcpmodels.TfIdsecCCEGCPOrganization, error) {
	s.Logger.Info("Adding GCP organization with ID [%s]", input.OrganizationID)

	requestBody, err := cceinternal.StructToMap(input)
	if err != nil {
		return nil, err
	}

	id, err := s.manual().Create(requestBody, cceinternal.DeploymentTypeOrganization)
	if err != nil {
		return nil, err
	}

	s.Logger.Info("Retrieving GCP organization details for ID [%s]", id)
	org, err := cceinternal.GetWithRetry(s.Logger, "GCP organization", func() (*gcpmodels.TfIdsecCCEGCPOrganization, error) {
		return s.TfOrganization(&gcpmodels.TfIdsecCCEGCPGetOrganization{ID: id})
	})
	if err != nil {
		return nil, fmt.Errorf("GCP organization created with ID %s, but failed to fetch details: %w", id, err)
	}

	return org, nil
}

// tfUpdateOrganization updates a GCP organization's services.
// Compares the desired services in the input with the current services on the organization,
// then adds new services and removes services that are no longer desired.
// API: POST/DELETE /api/gcp/manual/{id}/services
func (s *IdsecCCEGCPService) tfUpdateOrganization(input *gcpmodels.TfIdsecCCEGCPUpdateOrganization) (*gcpmodels.TfIdsecCCEGCPOrganization, error) {
	s.Logger.Info("Updating GCP organization [%s]", input.ID)

	// Step 1: Get current Organization services
	currentServiceNames, err := s.manual().CurrentServiceNames(fmt.Sprintf(pathOrganizationGetURL, input.ID))
	if err != nil {
		return nil, err
	}

	// Step 2: Use shared update logic to reconcile services
	err = s.manual().UpdateServices(input.ID, currentServiceNames, input.Services, "organization")
	if err != nil {
		return nil, err
	}

	// Step 3: Fetch and return updated Organization details
	s.Logger.Info("Fetching full details for GCP organization [%s]", input.ID)
	fullOrg, err := cceinternal.GetWithRetry(s.Logger, "GCP organization", func() (*gcpmodels.TfIdsecCCEGCPOrganization, error) {
		return s.TfOrganization(&gcpmodels.TfIdsecCCEGCPGetOrganization{ID: input.ID})
	})
	if err != nil {
		return nil, fmt.Errorf("GCP organization updated with ID %s, but failed to fetch details: %w", input.ID, err)
	}

	return fullOrg, nil
}

// tfDeleteOrganization deletes a GCP organization.
// API: DELETE /api/gcp/manual/{id}
func (s *IdsecCCEGCPService) tfDeleteOrganization(input *gcpmodels.TfIdsecCCEGCPDeleteOrganization) error {
	s.Logger.Info("Deleting GCP organization [%s]", input.ID)
	return s.manual().Delete(input.ID)
}
