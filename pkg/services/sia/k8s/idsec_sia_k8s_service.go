package k8s

import (
	"context"
	"errors"
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/k8s/models"

	"io"
	"net/http"
	"os"
	"path/filepath"
)

const (
	kubeConfigGenerationURL = "/api/k8s/kube-config"
)

// DefaultKubeConfigFolderPath is the default folder path for kubeconfig files.
const (
	DefaultKubeConfigFolderPath = "~/.kube"
)

// IdsecSIAK8SService is a struct that implements the IdsecService interface and provides functionality for K8S service of SIA.
type IdsecSIAK8SService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth *auth.IdsecISPAuth
	client  *isp.IdsecISPServiceClient
}

// NewIdsecSIAK8SService creates a new instance of IdsecSIAK8SService with the provided authenticators.
func NewIdsecSIAK8SService(authenticators ...auth.IdsecAuth) (*IdsecSIAK8SService, error) {
	k8sService := &IdsecSIAK8SService{}
	var k8sServiceInterface services.IdsecService = k8sService
	baseService, err := services.NewIdsecBaseService(k8sServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "dpa", ".", "", k8sService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	k8sService.client = client
	k8sService.ispAuth = ispAuth
	k8sService.IdsecBaseService = baseService
	return k8sService, nil
}

func (s *IdsecSIAK8SService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

// GenerateKubeconfig generates a kubeconfig file for the SIA K8S service and saves it to the specified folder.
func (s *IdsecSIAK8SService) GenerateKubeconfig(generateKubeConfig *k8smodels.IdsecSIAK8SGenerateKubeconfig) (string, error) {
	s.Logger.Info("Getting kubeconfig")
	response, err := s.client.Get(context.Background(), kubeConfigGenerationURL, nil)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get kubeconfig - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	folderPath := generateKubeConfig.Folder
	if folderPath == "" {
		folderPath = DefaultKubeConfigFolderPath
	}
	folderPath = common.ExpandFolder(folderPath)
	if folderPath == "" {
		return "", errors.New("folder parameter is required")
	}
	if _, err := os.Stat(folderPath); os.IsNotExist(err) {
		err := os.MkdirAll(folderPath, os.ModePerm)
		if err != nil {
			return "", err
		}
	}
	baseName := "config"
	fullPath := filepath.Join(folderPath, baseName)
	resp, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	err = os.WriteFile(fullPath, resp, 0644)
	if err != nil {
		return "", err
	}
	return fullPath, nil
}

// ServiceConfig returns the service configuration for the IdsecSIAK8SService.
func (s *IdsecSIAK8SService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
