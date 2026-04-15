package sessionactivities

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sessionactivitiesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sm/sessionactivities/models"
)

const (
	sessionActivitiesURL = "/api/sessions/%s/activities"
)

// IdsecSMSessionActivitiesPage represents a page of IdsecSMSessionActivity items.
type IdsecSMSessionActivitiesPage = common.IdsecPage[sessionactivitiesmodels.IdsecSMSessionActivity]

// IdsecSMSessionActivitiesService is the implementation of the SM Session Activities service.
type IdsecSMSessionActivitiesService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSMSessionActivitiesService creates a new instance of IdsecSMSessionActivitiesService.
func NewIdsecSMSessionActivitiesService(authenticators ...auth.IdsecAuth) (*IdsecSMSessionActivitiesService, error) {
	activitiesService := &IdsecSMSessionActivitiesService{}
	var activitiesServiceInterface services.IdsecService = activitiesService
	baseService, err := services.NewIdsecBaseService(activitiesServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "sessionmonitoring", ".", "", activitiesService.refreshSMAuth)
	if err != nil {
		return nil, err
	}

	activitiesService.IdsecBaseService = baseService
	activitiesService.IdsecISPBaseService = ispBaseService
	return activitiesService, nil
}

func (s *IdsecSMSessionActivitiesService) refreshSMAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ISPAuth())
	if err != nil {
		return err
	}
	return nil
}

// callListSessionActivities retrieves a list of activities for a session, parameters can be passed to filter the results.
func (s *IdsecSMSessionActivitiesService) callListSessionActivities(sessionID string, params map[string]string) (*sessionactivitiesmodels.IdsecSMSessionActivities, error) {
	if params == nil {
		params = make(map[string]string)
	}
	response, err := s.ISPClient().Get(context.Background(), fmt.Sprintf(sessionActivitiesURL, sessionID), params)
	if err != nil {
		s.Logger.Error("failed to list session activities: %v", err)
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list session activities - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	sessionActivitiesJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}
	var sessionActivities sessionactivitiesmodels.IdsecSMSessionActivities
	err = mapstructure.Decode(sessionActivitiesJSON, &sessionActivities)
	if err != nil {
		return nil, err
	}
	return &sessionActivities, nil
}

// listPagedSessionActivities retrieves the activities by session ID.
func (s *IdsecSMSessionActivitiesService) listPagedSessionActivities(sessionID string) (<-chan *IdsecSMSessionActivitiesPage, error) {
	results := make(chan *IdsecSMSessionActivitiesPage)
	params := make(map[string]string)
	offset := 0
	go func() {
		defer close(results)
		for {
			sessionActivitiesResponse, err := s.callListSessionActivities(sessionID, params)
			if err != nil {
				s.Logger.Error("failed to list session activities: %v", err)
				return
			}
			if sessionActivitiesResponse.ReturnedCount == 0 {
				break
			}
			activities := make([]*sessionactivitiesmodels.IdsecSMSessionActivity, len(sessionActivitiesResponse.Activities))
			for i := range sessionActivitiesResponse.Activities {
				activities[i] = &sessionActivitiesResponse.Activities[i]
			}
			results <- &IdsecSMSessionActivitiesPage{Items: activities}
			offset += sessionActivitiesResponse.ReturnedCount
			params["offset"] = strconv.Itoa(offset)
		}
	}()
	return results, nil
}

// List retrieves the activities of a session by its ID.
func (s *IdsecSMSessionActivitiesService) List(sessionActivities *sessionactivitiesmodels.IdsecSIASMGetSessionActivities) (<-chan *IdsecSMSessionActivitiesPage, error) {
	return s.listPagedSessionActivities(sessionActivities.SessionID)
}

// Count retrieves the count of all session activities by session id.
func (s *IdsecSMSessionActivitiesService) Count(activities *sessionactivitiesmodels.IdsecSIASMGetSessionActivities) (int, error) {
	sessionActivities, err := s.callListSessionActivities(activities.SessionID, nil)
	if err != nil {
		s.Logger.Error("failed counting session activities: %v", err)
		return 0, err
	}
	return sessionActivities.ReturnedCount, err
}

// ListBy retrieves the activities of a session by its ID and applies an optional filter.
func (s *IdsecSMSessionActivitiesService) ListBy(filter *sessionactivitiesmodels.IdsecSMSessionActivitiesFilter) (<-chan *IdsecSMSessionActivitiesPage, error) {
	pagedSessionActivities, err := s.listPagedSessionActivities(filter.SessionID)
	if err != nil {
		s.Logger.Error("failed to list session activities: %v", err)
		return nil, err
	}
	out := make(chan *IdsecSMSessionActivitiesPage)

	go func() {
		defer close(out)

		for page := range pagedSessionActivities {
			filteredItems := make([]*sessionactivitiesmodels.IdsecSMSessionActivity, 0, len(page.Items))

			for _, activity := range page.Items {
				if filter.CommandContains == "" || strings.Contains(activity.Command, filter.CommandContains) {
					filteredItems = append(filteredItems, activity)
				}
			}

			out <- &IdsecSMSessionActivitiesPage{
				Items: filteredItems,
			}
		}
	}()

	return out, nil
}

// CountBy retrieves the count of all session activities by session id and applies an optional filter.
func (s *IdsecSMSessionActivitiesService) CountBy(filter *sessionactivitiesmodels.IdsecSMSessionActivitiesFilter) (int, error) {
	pagedSessionActivities, err := s.ListBy(filter)
	if err != nil {
		s.Logger.Error("failed counting session activities: %v", err)
		return 0, err
	}
	count := 0
	for page := range pagedSessionActivities {
		count += len(page.Items)
	}
	return count, err
}

// ServiceConfig returns the service configuration for the IdsecSMSessionActivitiesService.
func (s *IdsecSMSessionActivitiesService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
