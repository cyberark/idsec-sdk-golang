package certificates

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	certificatesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/certificates/models"
)

const (
	certificatesURL = "api/certificates"
	certificateURL  = "api/certificates/%s"
)

// IdsecSIACertificatesService is a struct that implements the IdsecService interface and provides functionality for Certificates of SIA.
type IdsecSIACertificatesService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient

	doGet    func(ctx context.Context, path string, params interface{}) (*http.Response, error)
	doPost   func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	doPut    func(ctx context.Context, path string, body interface{}) (*http.Response, error)
	doDelete func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error)
}

// NewIdsecSIACertificatesService creates a new instance of IdsecSIACertificatesService with the provided authenticators.
func NewIdsecSIACertificatesService(authenticators ...auth.IdsecAuth) (*IdsecSIACertificatesService, error) {
	certificatesService := &IdsecSIACertificatesService{}
	var sshCaServiceInterface services.IdsecService = certificatesService
	baseService, err := services.NewIdsecBaseService(sshCaServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "dpa", ".", "", certificatesService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	certificatesService.client = client
	certificatesService.ispAuth = ispAuth
	certificatesService.IdsecBaseService = baseService
	return certificatesService, nil
}

func (s *IdsecSIACertificatesService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecSIACertificatesService) getOperation() func(ctx context.Context, path string, params interface{}) (*http.Response, error) {
	if s.doGet != nil {
		return s.doGet
	}
	return s.client.Get
}

func (s *IdsecSIACertificatesService) postOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.doPost != nil {
		return s.doPost
	}
	return s.client.Post
}

func (s *IdsecSIACertificatesService) putOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.doPut != nil {
		return s.doPut
	}
	return s.client.Put
}

func (s *IdsecSIACertificatesService) deleteOperation() func(ctx context.Context, path string, body interface{}, params interface{}) (*http.Response, error) {
	if s.doDelete != nil {
		return s.doDelete
	}
	return s.client.Delete
}

// AddCertificate adds a new SIA certificate.
func (s *IdsecSIACertificatesService) AddCertificate(addCertificate *certificatesmodels.IdsecSIACertificatesAddCertificate) (*certificatesmodels.IdsecSIACertificatesCertificate, error) {
	s.Logger.Info("Adding new certificate")
	certBody := ""
	if addCertificate.Labels == nil {
		addCertificate.Labels = make(map[string]interface{})
	}
	addCertificate.Labels["origin"] = config.IdsecToolInUse()
	if addCertificate.CertificateBody != "" {
		certBody = addCertificate.CertificateBody
	} else if addCertificate.File != "" {
		fileContent, err := os.ReadFile(addCertificate.File)
		if err != nil {
			return nil, err
		}
		certBody = string(fileContent)
		fileName := path.Base(addCertificate.File)
		if addCertificate.CertName == "" {
			addCertificate.CertName = fileName
		}
		if addCertificate.CertDescription == "" {
			addCertificate.CertDescription = fmt.Sprintf("Certificate imported from file %s", fileName)
		}
		addCertificate.Labels["file_name"] = fileName
	} else {
		return nil, fmt.Errorf("either CertificateBody or File must be provided")
	}
	if certBody == "" {
		return nil, fmt.Errorf("certificate body cannot be empty")
	}
	var addCertificateJSON map[string]interface{}
	err := mapstructure.Decode(addCertificate, &addCertificateJSON)
	if err != nil {
		return nil, err
	}
	delete(addCertificateJSON, "certificate_body")
	delete(addCertificateJSON, "file")
	addCertificateJSON["cert_body"] = certBody
	response, err := s.postOperation()(context.Background(), certificatesURL, addCertificateJSON)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to add certificate - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	certificateResponseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	certificateResponseJSONMap := certificateResponseJSON.(map[string]interface{})
	if certificateID, ok := certificateResponseJSONMap["certificate_id"]; ok {
		return s.Certificate(&certificatesmodels.IdsecSIACertificatesGetCertificate{
			CertificateID: certificateID.(string),
		})
	}
	return nil, fmt.Errorf("certificate_id not found in response")
}

// UpdateCertificate updates an existing SIA certificate.
func (s *IdsecSIACertificatesService) UpdateCertificate(updateCertificate *certificatesmodels.IdsecSIACertificatesUpdateCertificate) (*certificatesmodels.IdsecSIACertificatesCertificate, error) {
	s.Logger.Info("Adding new certificate")
	certBody := ""
	if updateCertificate.CertificateBody != "" {
		certBody = updateCertificate.CertificateBody
	} else if updateCertificate.File != "" {
		fileContent, err := os.ReadFile(updateCertificate.File)
		if err != nil {
			return nil, err
		}
		certBody = string(fileContent)
	}
	var updateCertificateJSON map[string]interface{}
	err := mapstructure.Decode(updateCertificate, &updateCertificateJSON)
	if err != nil {
		return nil, err
	}
	delete(updateCertificateJSON, "certificate_body")
	delete(updateCertificateJSON, "file")
	delete(updateCertificateJSON, "certificate_id")
	if certBody != "" {
		updateCertificateJSON["cert_body"] = certBody
	}
	existingCertificate, err := s.Certificate(&certificatesmodels.IdsecSIACertificatesGetCertificate{
		CertificateID: updateCertificate.CertificateID,
	})
	if err != nil {
		return nil, err
	}
	existingCertificateJSON := make(map[string]interface{})
	err = mapstructure.Decode(existingCertificate, &existingCertificateJSON)
	if err != nil {
		return nil, err
	}
	for key, value := range existingCertificateJSON {
		if _, exists := updateCertificateJSON[key]; !exists {
			updateCertificateJSON[key] = value
		}
	}
	response, err := s.putOperation()(context.Background(), fmt.Sprintf(certificateURL, updateCertificate.CertificateID), updateCertificateJSON)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to update certificate - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return s.Certificate(&certificatesmodels.IdsecSIACertificatesGetCertificate{
		CertificateID: updateCertificate.CertificateID,
	})
}

// DeleteCertificate deletes an existing SIA certificate.
func (s *IdsecSIACertificatesService) DeleteCertificate(deleteCertificate *certificatesmodels.IdsecSIACertificatesDeleteCertificate) error {
	s.Logger.Info("Deleting certificate [%s]", deleteCertificate.CertificateID)
	response, err := s.deleteOperation()(context.Background(), fmt.Sprintf(certificateURL, deleteCertificate.CertificateID), nil, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete certificate - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	return nil
}

// Certificate retrieves a specific SIA certificate by its ID.
func (s *IdsecSIACertificatesService) Certificate(getCertificate *certificatesmodels.IdsecSIACertificatesGetCertificate) (*certificatesmodels.IdsecSIACertificatesCertificate, error) {
	s.Logger.Info("Getting certificate [%s]", getCertificate.CertificateID)
	response, err := s.getOperation()(context.Background(), fmt.Sprintf(certificateURL, getCertificate.CertificateID), nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get certificate - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	certificateJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var certificate certificatesmodels.IdsecSIACertificatesCertificate
	err = mapstructure.Decode(certificateJSON, &certificate)
	if err != nil {
		return nil, err
	}
	return &certificate, nil
}

// ListCertificates lists all SIA certificates.
func (s *IdsecSIACertificatesService) ListCertificates() ([]*certificatesmodels.IdsecSIACertificatesShortCertificate, error) {
	s.Logger.Info("Listing certificates")
	response, err := s.getOperation()(context.Background(), certificatesURL, nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list certificates - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	certificatesJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	certificatesJSONMap, ok := certificatesJSON.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response format")
	}
	certificatesListMap, ok := certificatesJSONMap["certificates"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid certificates format")
	}
	certificatesListItems, ok := certificatesListMap["items"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid items format")
	}
	certificates := make([]*certificatesmodels.IdsecSIACertificatesShortCertificate, len(certificatesListItems))
	for idx, certificateItem := range certificatesListItems {
		var certificate certificatesmodels.IdsecSIACertificatesShortCertificate
		err = mapstructure.Decode(certificateItem, &certificate)
		if err != nil {
			return nil, err
		}
		certificates[idx] = &certificate
	}
	return certificates, nil
}

// ListCertificatesBy lists SIA certificates based on provided filters.
func (s *IdsecSIACertificatesService) ListCertificatesBy(filters *certificatesmodels.IdsecSIACertificatesFilter) ([]*certificatesmodels.IdsecSIACertificatesShortCertificate, error) {
	s.Logger.Info("Getting certificates by filter [%v]", filters)
	certificates, err := s.ListCertificates()
	if err != nil {
		return nil, err
	}
	if filters == nil {
		return certificates, nil
	}
	filteredCertificates := make([]*certificatesmodels.IdsecSIACertificatesShortCertificate, 0)
	for _, certificate := range certificates {
		matches := true
		if filters.DomainName != "" && certificate.Domain != filters.DomainName {
			matches = false
		}
		if filters.CertName != "" && certificate.CertName != filters.CertName {
			matches = false
		}
		if matches {
			filteredCertificates = append(filteredCertificates, certificate)
		}
	}
	return filteredCertificates, nil
}

// CertificatesStats retrieves statistics about SIA certificates.
func (s *IdsecSIACertificatesService) CertificatesStats() (*certificatesmodels.IdsecSIACertificatesStats, error) {
	s.Logger.Info("Getting certificates stats")
	certificates, err := s.ListCertificates()
	if err != nil {
		return nil, err
	}
	return &certificatesmodels.IdsecSIACertificatesStats{
		CertificatesCount: len(certificates),
	}, nil
}

// ServiceConfig returns the service configuration for the IdsecSIACertificatesService.
func (s *IdsecSIACertificatesService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
