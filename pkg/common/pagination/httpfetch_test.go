package pagination

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
)

// fakeGetter records the arguments it was called with and returns a canned
// response/error pair.
type fakeGetter struct {
	gotCtx   context.Context
	gotPath  string
	gotQuery interface{}

	resp *http.Response
	err  error
}

func (f *fakeGetter) Get(ctx context.Context, path string, query interface{}) (*http.Response, error) {
	f.gotCtx = ctx
	f.gotPath = path
	f.gotQuery = query
	return f.resp, f.err
}

func TestHTTPGetFetch_NilSeedsInitialQuery(t *testing.T) {
	wantResp := &http.Response{StatusCode: http.StatusOK}
	fake := &fakeGetter{resp: wantResp}
	initialQuery := map[string]string{"top": "50"}

	fetch := HTTPGetFetch(fake, "/api/things", initialQuery)

	ctx := context.Background()
	gotResp, gotQuery, err := fetch(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotResp != wantResp {
		t.Errorf("returned response = %v, want %v", gotResp, wantResp)
	}
	if !reflect.DeepEqual(gotQuery, initialQuery) {
		t.Errorf("returned query = %v, want %v", gotQuery, initialQuery)
	}
	if !reflect.DeepEqual(fake.gotQuery, initialQuery) {
		t.Errorf("Getter received query = %v, want %v", fake.gotQuery, initialQuery)
	}
	if fake.gotPath != "/api/things" {
		t.Errorf("Getter received path = %q, want %q", fake.gotPath, "/api/things")
	}
}

func TestHTTPGetFetch_DelegatesAndEchoesQuery(t *testing.T) {
	wantResp := &http.Response{StatusCode: http.StatusOK}
	fake := &fakeGetter{resp: wantResp}
	initialQuery := map[string]string{"top": "50"}
	nextQuery := map[string]string{"skip": "50", "top": "50"}

	fetch := HTTPGetFetch(fake, "/api/things", initialQuery)

	ctx := context.Background()
	gotResp, gotQuery, err := fetch(ctx, nextQuery)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotResp != wantResp {
		t.Errorf("returned response = %v, want %v", gotResp, wantResp)
	}
	if !reflect.DeepEqual(gotQuery, nextQuery) {
		t.Errorf("returned query = %v, want %v", gotQuery, nextQuery)
	}
	if !reflect.DeepEqual(fake.gotQuery, nextQuery) {
		t.Errorf("Getter received query = %v, want %v", fake.gotQuery, nextQuery)
	}
	if fake.gotPath != "/api/things" {
		t.Errorf("Getter received path = %q, want %q", fake.gotPath, "/api/things")
	}
}

func TestHTTPGetFetch_PropagatesError(t *testing.T) {
	wantErr := errors.New("boom")
	fake := &fakeGetter{err: wantErr}

	fetch := HTTPGetFetch(fake, "/api/things", map[string]string{"top": "50"})

	_, _, err := fetch(context.Background(), map[string]string{"skip": "50"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}
