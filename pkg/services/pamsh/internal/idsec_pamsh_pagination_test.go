package internal

import (
	"testing"

	idseccommon "github.com/cyberark/idsec-sdk-golang/pkg/common"
)

func TestNextLinkFromResultMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		resultMap map[string]interface{}
		wantLink  string
		wantFound bool
	}{
		{
			name:      "success_snake_case_next_link",
			resultMap: map[string]interface{}{"next_link": "https://pvwa.example/next?offset=10"},
			wantLink:  "https://pvwa.example/next?offset=10",
			wantFound: true,
		},
		{
			name:      "success_camel_case_next_link",
			resultMap: map[string]interface{}{"nextLink": "https://pvwa.example/next?offset=20"},
			wantLink:  "https://pvwa.example/next?offset=20",
			wantFound: true,
		},
		{
			name:      "edge_case_empty_next_link",
			resultMap: map[string]interface{}{"next_link": ""},
			wantFound: false,
		},
		{
			name:      "edge_case_missing_next_link",
			resultMap: map[string]interface{}{"value": []interface{}{}},
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			link, found := NextLinkFromResultMap(tt.resultMap)
			if found != tt.wantFound {
				t.Fatalf("found = %v, want %v", found, tt.wantFound)
			}
			if link != tt.wantLink {
				t.Fatalf("link = %q, want %q", link, tt.wantLink)
			}
		})
	}
}

func TestQueryFromNextLink(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		nextLink    string
		wantQuery   map[string]string
		expectedErr bool
	}{
		{
			name:      "success_parses_query_params",
			nextLink:  "https://pvwa.example/PasswordVault/API/Safes?offset=10&limit=50",
			wantQuery: map[string]string{"offset": "10", "limit": "50"},
		},
		{
			name:        "error_invalid_url",
			nextLink:    "://not-a-valid-url",
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			query, err := QueryFromNextLink(tt.nextLink)
			if tt.expectedErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for key, want := range tt.wantQuery {
				if query[key] != want {
					t.Fatalf("query[%q] = %q, want %q", key, query[key], want)
				}
			}
		})
	}
}

func TestDrainPages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		pages     []*idseccommon.IdsecPage[string]
		errChVal  error
		wantItems []string
		wantErr   bool
	}{
		{
			name: "success_drains_all_pages",
			pages: []*idseccommon.IdsecPage[string]{
				{Items: []*string{ptr("a"), ptr("b")}},
				{Items: []*string{ptr("c")}},
			},
			wantItems: []string{"a", "b", "c"},
		},
		{
			name:     "error_returns_error_from_channel",
			pages:    []*idseccommon.IdsecPage[string]{{Items: []*string{ptr("x")}}},
			errChVal: errTestDrain,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pageCh := make(chan *idseccommon.IdsecPage[string])
			errCh := make(chan error, 1)
			go func() {
				for _, page := range tt.pages {
					pageCh <- page
				}
				close(pageCh)
				if tt.errChVal != nil {
					errCh <- tt.errChVal
				}
				close(errCh)
			}()

			items, err := DrainPages(pageCh, errCh)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(items) != len(tt.wantItems) {
				t.Fatalf("len(items) = %d, want %d", len(items), len(tt.wantItems))
			}
			for i, want := range tt.wantItems {
				if *items[i] != want {
					t.Fatalf("items[%d] = %q, want %q", i, *items[i], want)
				}
			}
		})
	}
}

func TestExtractItemsFromResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		resultMap     map[string]interface{}
		resourceName  string
		alternateKeys []string
		wantLen       int
		expectedErr   bool
	}{
		{
			name:         "success_value_field",
			resultMap:    map[string]interface{}{"value": []interface{}{map[string]interface{}{"id": "1"}}},
			resourceName: "pamshaccounts",
			wantLen:      1,
		},
		{
			name:          "success_alternate_safes_field",
			resultMap:     map[string]interface{}{"Safes": []interface{}{map[string]interface{}{"safe_name": "S1"}}},
			resourceName:  "pamshsafes",
			alternateKeys: []string{"Safes"},
			wantLen:       1,
		},
		{
			name:         "error_missing_value",
			resultMap:    map[string]interface{}{"count": 0},
			resourceName: "pamshaccounts",
			expectedErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			items, err := ExtractItemsFromResult(tt.resultMap, tt.resourceName, tt.alternateKeys...)
			if tt.expectedErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(items) != tt.wantLen {
				t.Fatalf("len(items) = %d, want %d", len(items), tt.wantLen)
			}
		})
	}
}

var errTestDrain = errString("drain failed")

type errString string

func (e errString) Error() string { return string(e) }

func ptr(s string) *string { return &s }
