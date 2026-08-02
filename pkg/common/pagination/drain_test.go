package pagination

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

func TestDrainPages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		pages     []*common.IdsecPage[string]
		errChVal  error
		wantItems []string
		wantErr   bool
	}{
		{
			name: "success_drains_all_pages",
			pages: []*common.IdsecPage[string]{
				{Items: []*string{ptr("a"), ptr("b")}},
				{Items: []*string{ptr("c")}},
			},
			wantItems: []string{"a", "b", "c"},
		},
		{
			name:     "error_returns_error_from_channel",
			pages:    []*common.IdsecPage[string]{{Items: []*string{ptr("x")}}},
			errChVal: errTestDrain,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pageCh := make(chan *common.IdsecPage[string])
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

var errTestDrain = errString("drain failed")

type errString string

func (e errString) Error() string { return string(e) }

func ptr(s string) *string { return &s }
