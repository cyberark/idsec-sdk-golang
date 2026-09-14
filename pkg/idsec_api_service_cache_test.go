package api

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

var errFailedBuild = errors.New("build failed")

// stubService stands in for a real service, which would authenticate and open
// connections when built.
type stubService struct{}

func (stubService) ServiceConfig() services.IdsecServiceConfig {
	return services.IdsecServiceConfig{ServiceName: "stub"}
}

func (stubService) AddExtraContextField(name, shortName, value string) error {
	return nil
}

func (stubService) ClearExtraContext() error {
	return nil
}

// newTestAPI builds an API with an empty cache and no authenticators.
//
// NewIdsecAPI is avoided because it loads the default profile from disk, which
// these tests do not need.
func newTestAPI() *IdsecAPI {
	return &IdsecAPI{
		services: &serviceCache{services: make(map[string]*services.IdsecService)},
		profile:  &models.IdsecProfile{},
	}
}

// TestServiceCacheIsSafeUnderConcurrentUse asserts that resolving services
// concurrently is safe.
//
// This is the defect the cache was introduced to fix. Every service accessor
// looked the service up in a plain map and then stored the one it built into
// the same map, with nothing synchronising either. Two goroutines resolving
// services through one shared API therefore read and wrote the map at once,
// which the runtime reports as a concurrent map access and aborts the process
// over rather than merely returning a wrong answer.
//
// Run with -race.
func TestServiceCacheIsSafeUnderConcurrentUse(t *testing.T) {
	t.Parallel()

	api := newTestAPI()

	var waitGroup sync.WaitGroup
	for index := range 32 {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			// Distinct names force real inserts rather than cache hits, which
			// is what puts writes and reads on the map at the same time.
			_, _ = api.services.service(
				fmt.Sprintf("service-%d", index),
				func() (services.IdsecService, error) { return stubService{}, nil },
			)
		}(index)
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, _ = api.services.service(
				"shared",
				func() (services.IdsecService, error) { return stubService{}, nil },
			)
		}()
	}
	waitGroup.Wait()
}

// Concurrent first use of one service must yield one instance. Two callers
// racing to build the same service would otherwise each authenticate and
// connect one, and one of those would be silently discarded.
func TestServiceCacheBuildsAServiceOnce(t *testing.T) {
	t.Parallel()

	api := newTestAPI()

	var buildCountLock sync.Mutex
	buildCount := 0

	var waitGroup sync.WaitGroup
	resolved := make([]*services.IdsecService, 32)
	for index := range 32 {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			service, err := api.services.service(
				"shared",
				func() (services.IdsecService, error) {
					buildCountLock.Lock()
					buildCount++
					buildCountLock.Unlock()
					return stubService{}, nil
				},
			)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			resolved[index] = service
		}(index)
	}
	waitGroup.Wait()

	buildCountLock.Lock()
	defer buildCountLock.Unlock()
	if buildCount != 1 {
		t.Errorf("Expected the service to be built once, was built %d times", buildCount)
	}
	for index, service := range resolved {
		if service != resolved[0] {
			t.Errorf("Caller %d received a different instance", index)
		}
	}
}

// A failed build must not be cached, so that a later call can try again.
func TestServiceCacheDoesNotCacheAFailedBuild(t *testing.T) {
	t.Parallel()

	api := newTestAPI()

	_, err := api.services.service("failing", func() (services.IdsecService, error) {
		return nil, errFailedBuild
	})
	if err == nil {
		t.Fatal("Expected the build error to be returned")
	}

	service, err := api.services.service("failing", func() (services.IdsecService, error) {
		return stubService{}, nil
	})
	if err != nil {
		t.Fatalf("Retry after a failed build returned an error: %v", err)
	}
	if service == nil {
		t.Error("Retry after a failed build returned no service")
	}
}

func TestServiceCacheReturnsTheCachedInstance(t *testing.T) {
	t.Parallel()

	api := newTestAPI()

	first, err := api.services.service("svc", func() (services.IdsecService, error) {
		return stubService{}, nil
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	second, err := api.services.service("svc", func() (services.IdsecService, error) {
		t.Error("The service was rebuilt instead of being served from the cache")
		return stubService{}, nil
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if first != second {
		t.Error("The cache returned a different instance on the second call")
	}
}
