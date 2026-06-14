package internal

import (
	"context"
	"fmt"
	"net/http"

	"github.com/mitchellh/mapstructure"
	idseccommon "github.com/cyberark/idsec-sdk-golang/pkg/common"
)

// PVWAGetter performs authenticated GET requests against PVWA REST endpoints.
type PVWAGetter interface {
	Get(ctx context.Context, path string, query interface{}) (*http.Response, error)
}

// ListLogger logs list-operation errors from paginated PVWA requests.
type ListLogger interface {
	Error(format string, args ...interface{})
}

// ListPaginatedConfig configures generic PVWA list pagination.
type ListPaginatedConfig[T any] struct {
	Logger        ListLogger
	ResourceName  string
	ExtractItems  func(resultMap map[string]interface{}) ([]interface{}, error)
	NormalizeItem func(item map[string]interface{})
	// DecodeItems, when set, decodes raw list entries instead of the default mapstructure.Decode path.
	DecodeItems func(rawItems []interface{}) ([]*T, error)
	AfterDecode func(items []*T)
}

// ListPaginated fetches all pages from a PVWA OData-style list endpoint.
//
// It returns a channel of pages and a buffered error channel (capacity 1). The error channel
// receives at most one error after the page channel is closed.
func ListPaginated[T any](
	client PVWAGetter,
	path string,
	initialQuery map[string]string,
	cfg ListPaginatedConfig[T],
) (<-chan *idseccommon.IdsecPage[T], <-chan error) {
	pageChannel := make(chan *idseccommon.IdsecPage[T])
	errorChannel := make(chan error, 1)
	query := initialQuery

	go func() {
		defer close(errorChannel)
		defer close(pageChannel)

		sendError := func(err error) {
			errorChannel <- err
		}

		for {
			response, err := client.Get(context.Background(), path, query)
			if err != nil {
				if cfg.Logger != nil {
					cfg.Logger.Error("Failed to list %s: %v", cfg.ResourceName, err)
				}
				sendError(fmt.Errorf("failed to list %s: %w", cfg.ResourceName, err))
				return
			}
			if response.StatusCode != http.StatusOK {
				if cfg.Logger != nil {
					cfg.Logger.Error(
						"Failed to list %s - [%d] - [%s]",
						cfg.ResourceName,
						response.StatusCode,
						idseccommon.SerializeResponseToJSON(response.Body),
					)
				}
				listErr := fmt.Errorf(
					"failed to list %s - [%d] - [%s]",
					cfg.ResourceName,
					response.StatusCode,
					idseccommon.SerializeResponseToJSON(response.Body),
				)
				ClosePVWAResponse(response)
				sendError(listErr)
				return
			}

			result, err := idseccommon.DeserializeJSONSnake(response.Body)
			ClosePVWAResponse(response)
			if err != nil {
				if cfg.Logger != nil {
					cfg.Logger.Error("Failed to decode list %s response: %v", cfg.ResourceName, err)
				}
				sendError(fmt.Errorf("failed to decode list %s response: %w", cfg.ResourceName, err))
				return
			}

			resultMap, ok := result.(map[string]interface{})
			if !ok {
				if cfg.Logger != nil {
					cfg.Logger.Error("Failed to list %s, unexpected result type", cfg.ResourceName)
				}
				sendError(fmt.Errorf("failed to list %s: unexpected result type %T", cfg.ResourceName, result))
				return
			}

			rawItems, err := cfg.ExtractItems(resultMap)
			if err != nil {
				sendError(err)
				return
			}

			for i, raw := range rawItems {
				itemMap, ok := raw.(map[string]interface{})
				if !ok {
					sendError(fmt.Errorf("failed to list %s: unexpected entry type %T", cfg.ResourceName, raw))
					return
				}
				if cfg.NormalizeItem != nil {
					cfg.NormalizeItem(itemMap)
				}
				rawItems[i] = itemMap
			}

			var items []*T
			var decodeErr error
			if cfg.DecodeItems != nil {
				items, decodeErr = cfg.DecodeItems(rawItems)
			} else {
				decodeErr = mapstructure.Decode(rawItems, &items)
			}
			if decodeErr != nil {
				if cfg.Logger != nil {
					cfg.Logger.Error("Failed to validate %s: %v", cfg.ResourceName, decodeErr)
				}
				sendError(fmt.Errorf("failed to validate %s: %w", cfg.ResourceName, decodeErr))
				return
			}
			if cfg.AfterDecode != nil {
				cfg.AfterDecode(items)
			}

			pageChannel <- &idseccommon.IdsecPage[T]{Items: items}

			if nextLink, ok := NextLinkFromResultMap(resultMap); ok {
				nextQuery, err := QueryFromNextLink(nextLink)
				if err != nil {
					sendError(err)
					return
				}
				query = nextQuery
			} else {
				break
			}
		}
	}()

	return pageChannel, errorChannel
}
