package common

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/collectors"
)

// fakeService stands in for an SDK service calling through a client.
type fakeService struct {
	client *IdsecClient
}

// Get names the operation the metadata should be attributed to.
func (s *fakeService) Get(route string) collectors.IdsecRequestMetadata {
	return s.client.requestMetadataTelemetry(route)
}

// listThroughPagination stands in for the pagination helper carrying a request
// on a service's behalf.
func (s *fakeService) listThroughPagination(route string) collectors.IdsecRequestMetadata {
	return s.Get(route)
}

func TestRequestMetadataTelemetryDescribesTheCallingOperation(t *testing.T) {
	t.Parallel()

	service := &fakeService{client: &IdsecClient{owningService: "test-service"}}
	metadata := service.Get("/route")

	if metadata.Route != "/route" {
		t.Errorf("Reported route %q, want %q", metadata.Route, "/route")
	}
	if metadata.Service != "test-service" {
		t.Errorf("Reported service %q, want %q", metadata.Service, "test-service")
	}
	if metadata.Class != "fakeService" {
		t.Errorf("Reported class %q, want %q", metadata.Class, "fakeService")
	}
	if metadata.Operation != "Get" {
		t.Errorf("Reported operation %q, want %q", metadata.Operation, "Get")
	}
}

// The caller is found by walking out of the client's own frames, so an extra
// method between the service and the client must not change the attribution
// the way the old fixed stack depth did.
func TestRequestMetadataTelemetryIsUnaffectedByCallDepth(t *testing.T) {
	t.Parallel()

	service := &fakeService{client: &IdsecClient{owningService: "test-service"}}
	direct := service.Get("/route")
	nested := service.listThroughPagination("/route")

	if direct.Class != nested.Class {
		t.Errorf("Nested call reported class %q, want %q", nested.Class, direct.Class)
	}
	if nested.Operation != "Get" {
		t.Errorf("Nested call reported operation %q, want %q", nested.Operation, "Get")
	}
}

// Each request must describe itself, so that a client shared between goroutines
// never reports one request's route or operation on behalf of another.
//
// Run with -race.
func TestRequestMetadataTelemetryIsPerRequest(t *testing.T) {
	t.Parallel()

	client := &IdsecClient{owningService: "test-service"}
	service := &fakeService{client: client}

	const requests = 64
	var waitGroup sync.WaitGroup
	failures := make(chan string, requests)

	for requestIndex := range requests {
		waitGroup.Add(1)
		go func(requestIndex int) {
			defer waitGroup.Done()

			route := fmt.Sprintf("/route/%d", requestIndex)
			metadata := service.Get(route)
			if metadata.Route != route {
				failures <- fmt.Sprintf("request %d reported route %q", requestIndex, metadata.Route)
			}
			if metadata.Operation != "Get" {
				failures <- fmt.Sprintf("request %d reported operation %q", requestIndex, metadata.Operation)
			}
		}(requestIndex)
	}

	waitGroup.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
}

func TestSplitQualifiedFunction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		function          string
		expectedClass     string
		expectedOperation string
	}{
		{
			name:              "success_splits_a_pointer_method",
			function:          "github.com/org/repo/pkg/services.(*IdsecPCloudSafesService).Get",
			expectedClass:     "IdsecPCloudSafesService",
			expectedOperation: "Get",
		},
		{
			name:              "success_splits_a_value_method",
			function:          "github.com/org/repo/pkg/services.(IdsecPCloudSafesService).Get",
			expectedClass:     "IdsecPCloudSafesService",
			expectedOperation: "Get",
		},
		{
			name:              "success_reports_a_plain_function_without_a_class",
			function:          "github.com/org/repo/pkg/services.ListSafes",
			expectedClass:     "",
			expectedOperation: "ListSafes",
		},
		{
			name:              "success_handles_a_name_without_a_package",
			function:          "main",
			expectedClass:     "",
			expectedOperation: "main",
		},
		{
			name:              "success_handles_an_empty_name",
			function:          "",
			expectedClass:     "",
			expectedOperation: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			class, operation := splitQualifiedFunction(tt.function)
			if class != tt.expectedClass {
				t.Errorf("Reported class %q, want %q", class, tt.expectedClass)
			}
			if operation != tt.expectedOperation {
				t.Errorf("Reported operation %q, want %q", operation, tt.expectedOperation)
			}
		})
	}
}

func TestIsRequestPlumbing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		function string
		class    string
		expected bool
	}{
		{
			name:     "success_treats_the_client_as_plumbing",
			function: "github.com/org/repo/pkg/common.(*IdsecClient).Get",
			class:    "IdsecClient",
			expected: true,
		},
		{
			name:     "success_treats_the_isp_client_as_plumbing",
			function: "github.com/org/repo/pkg/common/isp.(*IdsecISPServiceClient).Get",
			class:    "IdsecISPServiceClient",
			expected: true,
		},
		{
			name:     "success_treats_pagination_as_plumbing",
			function: "github.com/org/repo/pkg/common/pagination.Paginate[...]",
			class:    "",
			expected: true,
		},
		{
			name:     "success_treats_a_service_as_the_caller",
			function: "github.com/org/repo/pkg/services/pcloud/safes.(*IdsecPCloudSafesService).Get",
			class:    "IdsecPCloudSafesService",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isRequestPlumbing(tt.function, tt.class); got != tt.expected {
				t.Errorf("Reported %v, want %v", got, tt.expected)
			}
		})
	}
}
