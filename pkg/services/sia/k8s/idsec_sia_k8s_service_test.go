package k8s

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/k8s/models"
)

// capturedPost records the last request body sent to the mock server, so tests can assert on it.
type capturedPost struct {
	mu   sync.Mutex
	body map[string]interface{}
}

func (c *capturedPost) set(body map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.body = body
}

func (c *capturedPost) get() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.body
}

// setupMockK8SService wires an IdsecSIAK8SService to a real httptest server via the same
// reflection trick used by the SSO/access service tests, since the K8S service does not
// expose overridable doGet/doPost fields.
func setupMockK8SService(t *testing.T, handler http.HandlerFunc) *IdsecSIAK8SService {
	t.Helper()
	testServer := httptest.NewServer(handler)
	t.Cleanup(testServer.Close)

	client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
	client.BaseURL = testServer.URL

	ispBase := &services.IdsecISPBaseService{}
	clientField := reflect.ValueOf(ispBase).Elem().FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(&isp.IdsecISPServiceClient{IdsecClient: client}))

	return &IdsecSIAK8SService{
		IdsecBaseService:    &services.IdsecBaseService{Logger: common.GlobalLogger},
		IdsecISPBaseService: ispBase,
	}
}

func TestListClusters_Success(t *testing.T) {
	mockClustersResponse := `{
		"clusters": [
			{"clusterAddress": "cluster-1.example.com", "clusterUsername": "user1", "isReasonRequired": true},
			{"clusterAddress": "cluster-2.example.com", "clusterUsername": "user2", "isReasonRequired": false}
		]
	}`

	service := setupMockK8SService(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, clustersURL, r.URL.Path)
		require.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockClustersResponse))
	})

	clusters, err := service.ListClusters(nil)
	require.NoError(t, err)
	require.NotNil(t, clusters)
	require.Len(t, clusters.Clusters, 2)
	require.Equal(t, "cluster-1.example.com", clusters.Clusters[0].ClusterAddress)
	require.Equal(t, "user1", clusters.Clusters[0].ClusterUsername)
	require.True(t, clusters.Clusters[0].IsReasonRequired)
	require.False(t, clusters.Clusters[1].IsReasonRequired)
}

func TestListClusters_WithOutputFile(t *testing.T) {
	mockClustersResponse := `{
		"clusters": [
			{"clusterAddress": "cluster-1.example.com", "clusterUsername": "user1", "isReasonRequired": true},
			{"clusterAddress": "cluster-2.example.com", "clusterUsername": "user2", "isReasonRequired": false}
		]
	}`

	service := setupMockK8SService(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockClustersResponse))
	})

	outputFile := filepath.Join(t.TempDir(), "clusters.json")
	clusters, err := service.ListClusters(&k8smodels.IdsecSIAK8SListClusters{OutputFile: outputFile})
	require.NoError(t, err)
	require.NotNil(t, clusters)

	written, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	var savedClusters map[string]interface{}
	require.NoError(t, json.Unmarshal(written, &savedClusters))
	items, ok := savedClusters["clusters"].([]interface{})
	require.True(t, ok)
	require.Len(t, items, 2)

	// Cluster requiring a reason gets an empty placeholder ready to be filled in. Field names are
	// camelCase, matching the API wire format and the ark-sdk-python reference file format.
	first := items[0].(map[string]interface{})
	require.Equal(t, "cluster-1.example.com", first["clusterAddress"])
	require.Equal(t, "", first["reason"])
	require.Equal(t, true, first["isReasonRequired"])

	// Cluster not requiring a reason still carries isReasonRequired: false, but has no "reason" key.
	second := items[1].(map[string]interface{})
	require.Equal(t, "cluster-2.example.com", second["clusterAddress"])
	require.Equal(t, false, second["isReasonRequired"])
	_, hasReason := second["reason"]
	require.False(t, hasReason)
}

// captureStdout redirects os.Stdout for the duration of fn and returns everything written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	fn()

	require.NoError(t, w.Close())
	os.Stdout = original

	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func TestListClusters_WarningPrintedWhenReasonRequired(t *testing.T) {
	mockClustersResponse := `{
		"clusters": [
			{"clusterAddress": "cluster-1.example.com", "clusterUsername": "user1", "isReasonRequired": true}
		]
	}`

	service := setupMockK8SService(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockClustersResponse))
	})

	stdout := captureStdout(t, func() {
		_, err := service.ListClusters(nil)
		require.NoError(t, err)
	})
	require.Contains(t, stdout, "WARNING")
	require.Contains(t, stdout, "At least one cluster requires a reason")
	require.Contains(t, stdout, "--reason-to-all")
}

func TestListClusters_NoWarningWhenNoReasonRequired(t *testing.T) {
	mockClustersResponse := `{
		"clusters": [
			{"clusterAddress": "cluster-1.example.com", "clusterUsername": "user1", "isReasonRequired": false}
		]
	}`

	service := setupMockK8SService(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockClustersResponse))
	})

	stdout := captureStdout(t, func() {
		_, err := service.ListClusters(nil)
		require.NoError(t, err)
	})
	require.NotContains(t, stdout, "WARNING")
}

func TestListClusters_Non200Status(t *testing.T) {
	service := setupMockK8SService(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "boom"}`))
	})

	clusters, err := service.ListClusters(nil)
	require.Error(t, err)
	require.Nil(t, clusters)
	require.Contains(t, err.Error(), "failed to list k8s clusters")
}

func TestGenerateClusterConfig_Success(t *testing.T) {
	const kubeConfigContent = "apiVersion: v1\nkind: Config\n"
	captured := &capturedPost{}

	service := setupMockK8SService(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, generateClusterConfigURL, r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(raw, &body))
		captured.set(body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(kubeConfigContent))
	})

	// The clusters file uses the same camelCase format ListClusters would have saved, with
	// "reason" filled in for the cluster that requires one.
	clustersFile := filepath.Join(t.TempDir(), "clusters.json")
	require.NoError(t, os.WriteFile(clustersFile, []byte(`{
		"clusters": [
			{"clusterAddress": "cluster-1.example.com", "clusterUsername": "user1", "isReasonRequired": true, "reason": "debugging"},
			{"clusterAddress": "cluster-2.example.com", "clusterUsername": "user2", "isReasonRequired": false}
		]
	}`), 0644))

	folder := t.TempDir()
	result, err := service.GenerateClusterConfig(&k8smodels.IdsecSIAK8SGenerateClusterConfig{
		ClustersFile: clustersFile,
		Folder:       folder,
	})
	require.NoError(t, err)
	require.Equal(t, filepath.Join(folder, "kubeconfig.config"), result.KubeconfigPath)

	written, err := os.ReadFile(result.KubeconfigPath)
	require.NoError(t, err)
	require.Equal(t, kubeConfigContent, string(written))

	body := captured.get()
	items, ok := body["clusters"].([]interface{})
	require.True(t, ok)
	require.Len(t, items, 2)

	first := items[0].(map[string]interface{})
	require.Equal(t, "cluster-1.example.com", first["clusterAddress"])
	require.Equal(t, true, first["isReasonRequired"])
	require.Equal(t, "debugging", first["reason"])

	second := items[1].(map[string]interface{})
	require.Equal(t, "cluster-2.example.com", second["clusterAddress"])
	require.Equal(t, false, second["isReasonRequired"])
	_, hasReason := second["reason"]
	require.False(t, hasReason)
}

func TestGenerateClusterConfig_ReasonToAll(t *testing.T) {
	const kubeConfigContent = "apiVersion: v1\nkind: Config\n"
	captured := &capturedPost{}

	service := setupMockK8SService(t, func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var body map[string]interface{}
		require.NoError(t, json.Unmarshal(raw, &body))
		captured.set(body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(kubeConfigContent))
	})

	// Both clusters already have a per-cluster reason in the file; --reason-to-all should
	// ignore both and use the override reason for every cluster instead.
	clustersFile := filepath.Join(t.TempDir(), "clusters.json")
	require.NoError(t, os.WriteFile(clustersFile, []byte(`{
		"clusters": [
			{"clusterAddress": "cluster-1.example.com", "clusterUsername": "user1", "isReasonRequired": true, "reason": "orig-1"},
			{"clusterAddress": "cluster-2.example.com", "clusterUsername": "user2", "isReasonRequired": true, "reason": "orig-2"}
		]
	}`), 0644))

	_, err := service.GenerateClusterConfig(&k8smodels.IdsecSIAK8SGenerateClusterConfig{
		ClustersFile: clustersFile,
		Folder:       t.TempDir(),
		ReasonToAll:  "override-reason",
	})
	require.NoError(t, err)

	body := captured.get()
	items, ok := body["clusters"].([]interface{})
	require.True(t, ok)
	require.Len(t, items, 2)

	for _, item := range items {
		entry := item.(map[string]interface{})
		require.Equal(t, "override-reason", entry["reason"])
	}
}

func TestGenerateClusterConfig_ReasonToAllInvalidChars(t *testing.T) {
	service := setupMockK8SService(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be called when reason_to_all contains invalid characters")
	})

	clustersFile := filepath.Join(t.TempDir(), "clusters.json")
	require.NoError(t, os.WriteFile(clustersFile, []byte(`{"clusters": []}`), 0644))

	for _, reason := range []string{"<script>", "reason>with>angle", "<reason", "reason<"} {
		_, err := service.GenerateClusterConfig(&k8smodels.IdsecSIAK8SGenerateClusterConfig{
			ClustersFile: clustersFile,
			ReasonToAll:  reason,
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "must not contain '<' or '>'")
	}
}

func TestGenerateClusterConfig_MissingClustersFile(t *testing.T) {
	service := setupMockK8SService(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be called when the clusters file is missing")
	})

	_, err := service.GenerateClusterConfig(&k8smodels.IdsecSIAK8SGenerateClusterConfig{
		ClustersFile: filepath.Join(t.TempDir(), "does-not-exist.json"),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not exist")
}

func TestGenerateClusterConfig_EmptyClustersFileParam(t *testing.T) {
	service := setupMockK8SService(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be called when clusters_file is empty")
	})

	_, err := service.GenerateClusterConfig(&k8smodels.IdsecSIAK8SGenerateClusterConfig{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "clusters_file parameter is required")
}

func TestAnyClusterRequiresReason(t *testing.T) {
	require.False(t, anyClusterRequiresReason(&k8smodels.IdsecSIAK8SClusters{}))

	require.False(t, anyClusterRequiresReason(&k8smodels.IdsecSIAK8SClusters{
		Clusters: []k8smodels.IdsecSIAK8SCluster{
			{ClusterAddress: "cluster-1.example.com", IsReasonRequired: false},
			{ClusterAddress: "cluster-2.example.com", IsReasonRequired: false},
		},
	}))

	require.True(t, anyClusterRequiresReason(&k8smodels.IdsecSIAK8SClusters{
		Clusters: []k8smodels.IdsecSIAK8SCluster{
			{ClusterAddress: "cluster-1.example.com", IsReasonRequired: false},
			{ClusterAddress: "cluster-2.example.com", IsReasonRequired: true},
		},
	}))
}

func TestGenerateClusterConfig_Non200Status(t *testing.T) {
	service := setupMockK8SService(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "invalid reason"}`))
	})

	clustersFile := filepath.Join(t.TempDir(), "clusters.json")
	require.NoError(t, os.WriteFile(clustersFile, []byte(`{"clusters": []}`), 0644))

	_, err := service.GenerateClusterConfig(&k8smodels.IdsecSIAK8SGenerateClusterConfig{
		ClustersFile: clustersFile,
		Folder:       t.TempDir(),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to generate k8s cluster config")
}
