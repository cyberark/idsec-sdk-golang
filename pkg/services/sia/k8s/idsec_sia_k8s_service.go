package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/k8s/models"

	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	kubeConfigGenerationURL  = "/api/k8s/kube-config"
	clustersURL              = "/api/k8s/clusters"
	generateClusterConfigURL = "/api/k8s/clusters/generate"
)

// DefaultKubeConfigFolderPath is the default folder path for kubeconfig files.
const (
	DefaultKubeConfigFolderPath = "~/.kube"
)

// IdsecSIAK8SService is a struct that implements the IdsecService interface and provides functionality for K8S service of SIA.
type IdsecSIAK8SService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
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

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "dpa", ".", "", k8sService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}

	k8sService.IdsecBaseService = baseService
	k8sService.IdsecISPBaseService = ispBaseService
	return k8sService, nil
}

func (s *IdsecSIAK8SService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

// GenerateKubeconfig generates a kubeconfig file for the SIA K8S service and saves it to the specified folder.
func (s *IdsecSIAK8SService) GenerateKubeconfig(generateKubeConfig *k8smodels.IdsecSIAK8SGenerateKubeconfig) (string, error) {
	s.Logger.Info("Getting kubeconfig")
	response, err := s.ISPClient().Get(context.Background(), kubeConfigGenerationURL, nil)
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

// clusterToMap converts a single K8S cluster into a map keyed by its camelCase wire-format field
// names, matching both the API payload shape and the ark-sdk-python reference implementation's
// clusters file format. "isReasonRequired" is always included; a "reason" entry is only added for
// clusters that require one, so that:
//   - a clusters file saved from ListClusters is ready to be filled in and used as-is with
//     GenerateClusterConfig, and
//   - the request body sent to GenerateClusterConfig only carries a reason where the API expects one.
func clusterToMap(cluster *k8smodels.IdsecSIAK8SCluster) map[string]interface{} {
	entry := map[string]interface{}{
		"clusterAddress":   cluster.ClusterAddress,
		"clusterUsername":  cluster.ClusterUsername,
		"isReasonRequired": cluster.IsReasonRequired,
	}
	if cluster.IsReasonRequired {
		entry["reason"] = cluster.Reason
	}
	return entry
}

// clustersToMap converts a list of K8S clusters into the camelCase map representation used both
// for saving a clusters JSON file and for building the GenerateClusterConfig request body.
func clustersToMap(clusters *k8smodels.IdsecSIAK8SClusters) map[string]interface{} {
	clusterItems := make([]interface{}, len(clusters.Clusters))
	for idx := range clusters.Clusters {
		clusterItems[idx] = clusterToMap(&clusters.Clusters[idx])
	}
	return map[string]interface{}{"clusters": clusterItems}
}

// anyClusterRequiresReason reports whether at least one of the given clusters requires a reason in
// order to access it.
func anyClusterRequiresReason(clusters *k8smodels.IdsecSIAK8SClusters) bool {
	for _, cluster := range clusters.Clusters {
		if cluster.IsReasonRequired {
			return true
		}
	}
	return false
}

// saveClustersFile saves the given clusters as a JSON file to the specified output path.
func saveClustersFile(outputFile string, clusters *k8smodels.IdsecSIAK8SClusters) error {
	folderPath := filepath.Dir(outputFile)
	if folderPath != "" && folderPath != "." {
		if _, err := os.Stat(folderPath); os.IsNotExist(err) {
			if err := os.MkdirAll(folderPath, os.ModePerm); err != nil {
				return err
			}
		}
	}
	data, err := json.MarshalIndent(clustersToMap(clusters), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputFile, data, 0644)
}

// ListClusters lists the K8s clusters that are available for the current user to access. When an
// output file is provided, the clusters list is also saved as a JSON file to that path. If at least
// one of the returned clusters requires a reason to access it, a warning is printed to the console
// after the clusters list is reported.
func (s *IdsecSIAK8SService) ListClusters(listClusters *k8smodels.IdsecSIAK8SListClusters) (*k8smodels.IdsecSIAK8SClusters, error) {
	s.Logger.Info("Listing k8s clusters")
	response, err := s.ISPClient().Get(context.Background(), clustersURL, nil)
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
		return nil, fmt.Errorf("failed to list k8s clusters - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	clustersJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var clusters k8smodels.IdsecSIAK8SClusters
	err = mapstructure.Decode(clustersJSON, &clusters)
	if err != nil {
		return nil, err
	}
	if listClusters != nil && listClusters.OutputFile != "" {
		if err := saveClustersFile(listClusters.OutputFile, &clusters); err != nil {
			return nil, err
		}
	}
	if anyClusterRequiresReason(&clusters) {
		// Printed directly to stdout (rather than via s.Logger.Warning) so it is always visible to
		// the user, regardless of --verbose / log level, right after the clusters list is reported.
		fmt.Println("WARNING: At least one cluster requires a reason. Add a reason to the relevant cluster(s) in the JSON file, or use --reason-to-all to provide the same reason for all clusters when generating the kubeconfig file.")
	}
	return &clusters, nil
}

// GenerateClusterConfig generates a kubeconfig file for the clusters and access reasons supplied in
// the given clusters file. The clusters file is expected to be in the same format as the one
// returned/saved by ListClusters, with an additional "reason" field filled in per cluster where a
// reason is required (IsReasonRequired is true). If ReasonToAll is set, it overrides any per-cluster
// "reason" value in the file and is used for every cluster in the request.
func (s *IdsecSIAK8SService) GenerateClusterConfig(generateClusterConfig *k8smodels.IdsecSIAK8SGenerateClusterConfig) (string, error) {
	if generateClusterConfig.ClustersFile == "" {
		return "", errors.New("clusters_file parameter is required")
	}
	if strings.ContainsAny(generateClusterConfig.ReasonToAll, "<>") {
		return "", errors.New("reason_to_all parameter must not contain '<' or '>'")
	}
	if _, err := os.Stat(generateClusterConfig.ClustersFile); os.IsNotExist(err) {
		return "", fmt.Errorf("clusters file [%s] does not exist", generateClusterConfig.ClustersFile)
	}
	fileContent, err := os.ReadFile(generateClusterConfig.ClustersFile)
	if err != nil {
		return "", err
	}
	var clustersRaw map[string]interface{}
	if err := json.Unmarshal(fileContent, &clustersRaw); err != nil {
		return "", err
	}
	// The clusters file uses the same camelCase field names as the API/ListClusters output, so
	// convert it to snake_case before decoding into the (snake_case-tagged) Go model.
	var clusters k8smodels.IdsecSIAK8SClusters
	if err := mapstructure.Decode(common.ConvertToSnakeCase(clustersRaw, nil), &clusters); err != nil {
		return "", err
	}
	if generateClusterConfig.ReasonToAll != "" {
		// Ignore whatever reason (if any) is set per-cluster in the file and use the same reason
		// for every cluster in the request.
		for idx := range clusters.Clusters {
			clusters.Clusters[idx].Reason = generateClusterConfig.ReasonToAll
		}
	}
	s.Logger.Info("Generating kube config file for the given clusters and reasons")
	response, err := s.ISPClient().Post(context.Background(), generateClusterConfigURL, clustersToMap(&clusters))
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
		return "", fmt.Errorf("failed to generate k8s cluster config - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	resp, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	folderPath := generateClusterConfig.Folder
	if folderPath == "" {
		folderPath = DefaultKubeConfigFolderPath
	}
	folderPath = common.ExpandFolder(folderPath)
	if folderPath == "" {
		return "", errors.New("folder parameter is required")
	}
	if _, err := os.Stat(folderPath); os.IsNotExist(err) {
		if err := os.MkdirAll(folderPath, os.ModePerm); err != nil {
			return "", err
		}
	}
	fullPath := filepath.Join(folderPath, "kubeconfig.config")
	if err := os.WriteFile(fullPath, resp, 0644); err != nil {
		return "", err
	}
	return fullPath, nil
}

// ServiceConfig returns the service configuration for the IdsecSIAK8SService.
func (s *IdsecSIAK8SService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
