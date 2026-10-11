package tenantsuffixes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	tenantsuffixesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/tenantsuffixes/models"
)

// MockHTTPResponse creates a mock HTTP response with the given status code and body.
func MockHTTPResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

func MockISPAuth() *auth.IdsecISPAuth {
	return &auth.IdsecISPAuth{
		IdsecAuthBase: &auth.IdsecAuthBase{
			Token: &authmodels.IdsecToken{
				Token:      "",
				TokenType:  authmodels.JWT,
				Username:   "mock-username@mock-domain.cyberark.cloud",
				Endpoint:   "https://mock-endpoint",
				AuthMethod: authmodels.Identity,
				Metadata: map[string]interface{}{
					"env": "dev",
				},
			},
		},
	}
}

// recordedCall is one POST the service made, kept so a test can assert the keys it put on the wire.
type recordedCall struct {
	path string
	body map[string]interface{}
}

// mockPoster stands in for the ISP client at the service's DoPost seam.
//
// The sibling packages' MockPostFunc returns one fixed response for every call, which cannot drive
// these operations: Create lists before storing and reads back afterwards, and Delete lists to
// resolve the row key then lists again to confirm the row is gone. So responses are queued per path,
// and the last queued response for a path is reused once its queue is drained.
type mockPoster struct {
	t         *testing.T
	responses map[string][]string
	err       error
	calls     []recordedCall
}

func (m *mockPoster) post(_ context.Context, path string, body interface{}) (*http.Response, error) {
	bodyMap, _ := body.(map[string]interface{})
	m.calls = append(m.calls, recordedCall{path: path, body: bodyMap})
	if m.err != nil {
		return nil, m.err
	}
	queued := m.responses[path]
	if len(queued) == 0 {
		m.t.Fatalf("unexpected POST to %s -- no response queued", path)
		return nil, errors.New("unexpected POST")
	}
	if len(queued) > 1 {
		m.responses[path] = queued[1:]
	}
	return MockHTTPResponse(http.StatusOK, queued[0]), nil
}

// callsTo returns every recorded POST to path.
func (m *mockPoster) callsTo(path string) []recordedCall {
	out := make([]recordedCall, 0, len(m.calls))
	for _, call := range m.calls {
		if call.path == path {
			out = append(out, call)
		}
	}
	return out
}

func newTestService(t *testing.T, poster *mockPoster) *IdsecIdentityTenantSuffixesService {
	t.Helper()
	service, err := NewIdsecIdentityTenantSuffixesService(MockISPAuth())
	if err != nil {
		t.Fatalf("failed to construct service: %v", err)
	}
	service.DoPost = poster.post
	return service
}

// aliasRow renders one grid row. A replaceDomain of "" is emitted as JSON null, which is what the
// grid builder sends for a declared column the row does not carry (UiQueryResponse.cs:113-117) --
// not an empty string.
func aliasRow(id, replaceDomain string) string {
	return aliasRowWith(id, replaceDomain, false, false)
}

// aliasRowWith renders a row with an explicit CdsAlias flag. suffixless adds the DisplaySuffix column,
// which the list endpoint declares only while the suffixless fix is on (CoreController.cs:1267-1280).
func aliasRowWith(id, replaceDomain string, cdsAlias, suffixless bool) string {
	domain := "null"
	if replaceDomain != "" {
		domain = fmt.Sprintf("%q", replaceDomain)
	}
	display := ""
	if suffixless {
		display = fmt.Sprintf(`,"DisplaySuffix":%q`, replaceDomain)
	}
	return fmt.Sprintf(
		`{"Entities":[{"Key":%q,"Type":"TenantAlias"}],"Row":{"ID":%q,"ReplaceDomain":%s,"CdsAlias":%t%s}}`,
		id, id, domain, cdsAlias, display)
}

// aliasListResponse wraps rows in the UiQueryResponse envelope the list endpoint returns
// (CoreController.cs:1255-1260).
func aliasListResponse(rows ...string) string {
	return `{"success":true,"Result":{"Count":` +
		fmt.Sprintf("%d", len(rows)) +
		`,"Results":[` + strings.Join(rows, ",") + `]}}`
}

// Sample JSON responses for testing
const (
	StoreAliasOKResponseJSON        = `{"success":true,"Result":{"State":0}}`
	StoreAliasDuplicateResponseJSON = `{"success":true,"Result":{"State":1}}`
	DeleteAliasResponseJSON         = `{"success":true,"Result":{"State":0}}`
)

func TestGetReturnsTheStoredSpellingAndMatchesAnyCasing(t *testing.T) {
	// The row key is case-folded by the server while ReplaceDomain keeps the caller's spelling
	// (TenantAlias.cs:359, :686-689), so a lookup for any casing must find the row, and the value
	// returned must be the stored one rather than the argument.
	poster := &mockPoster{t: t, responses: map[string][]string{
		readTenantSuffixURL: {aliasListResponse(aliasRow("example.com", "Example.COM"))},
	}}
	service := newTestService(t, poster)

	got, err := service.Get(&tenantsuffixesmodels.IdsecIdentityGetTenantSuffix{ReplaceDomain: "eXaMpLe.com"})
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if got.ReplaceDomain != "Example.COM" {
		t.Errorf("Get returned %q, want the stored spelling %q", got.ReplaceDomain, "Example.COM")
	}
}

func TestGetNotFoundIsSynthesised(t *testing.T) {
	// There is no read-one endpoint, so a missing suffix is an ordinary list that does not contain it.
	poster := &mockPoster{t: t, responses: map[string][]string{
		readTenantSuffixURL: {aliasListResponse(aliasRow("other.com", "other.com"))},
	}}
	service := newTestService(t, poster)

	_, err := service.Get(&tenantsuffixesmodels.IdsecIdentityGetTenantSuffix{ReplaceDomain: "example.com"})
	if err == nil {
		t.Fatal("Get succeeded for a suffix the tenant does not have")
	}
	// The provider's Read drops the resource from state only for errors.Is(err, common.ErrNotFound)
	// (terraform-provider-idsec's internal/provider/idsec_resource.go); any other error fails every
	// plan until a state rm.
	if !errors.Is(err, common.ErrNotFound) {
		t.Errorf("Get not-found error %q does not wrap common.ErrNotFound", err)
	}
}

func TestGetListFailureIsNotReportedAsNotFound(t *testing.T) {
	// The inverse guard: a failed list must NOT wrap ErrNotFound, or a transient server refusal would
	// make the provider drop a live suffix from state and plan to recreate it.
	poster := &mockPoster{t: t, responses: map[string][]string{
		readTenantSuffixURL: {`{"success":false,"Result":null,"Message":"try again later"}`},
	}}
	service := newTestService(t, poster)

	_, err := service.Get(&tenantsuffixesmodels.IdsecIdentityGetTenantSuffix{ReplaceDomain: "example.com"})
	if err == nil {
		t.Fatal("Get succeeded on a failed list")
	}
	if errors.Is(err, common.ErrNotFound) {
		t.Errorf("Get reported a failed list as not found: %q", err)
	}
}

func TestRowWithNullReplaceDomainIsNotManageable(t *testing.T) {
	// A legacy alias can carry no ReplaceDomain at all (CoreController.cs:1277,
	// TenantAlias.cs:702). It must not be listed, and crucially a lookup for the empty string must
	// not match it -- that would delete an arbitrary legacy alias.
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {aliasListResponse(
			aliasRow("legacy-alias", ""),
			aliasRow("example.com", "example.com"),
		)},
	}}
	service := newTestService(t, poster)

	suffixes, err := service.List()
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if len(suffixes) != 1 || suffixes[0].ReplaceDomain != "example.com" {
		t.Fatalf("List returned %+v, want only the manageable row", suffixes)
	}
}

func TestListToleratesATenantWithNoAliases(t *testing.T) {
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {aliasListResponse()},
	}}
	service := newTestService(t, poster)

	suffixes, err := service.List()
	if err != nil {
		t.Fatalf("List returned an error: %v", err)
	}
	if len(suffixes) != 0 {
		t.Errorf("List returned %+v, want empty", suffixes)
	}
}

func TestListByFiltersCaseInsensitively(t *testing.T) {
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {aliasListResponse(
			aliasRow("example.com", "Example.com"),
			aliasRow("other.com", "other.com"),
		)},
	}}
	service := newTestService(t, poster)

	filtered, err := service.ListBy(&tenantsuffixesmodels.IdsecIdentityTenantSuffixFilters{ReplaceDomain: "EXAMPLE.COM"})
	if err != nil {
		t.Fatalf("ListBy returned an error: %v", err)
	}
	if len(filtered) != 1 || filtered[0].ReplaceDomain != "Example.com" {
		t.Fatalf("ListBy returned %+v, want the single case-insensitive match", filtered)
	}
}

func TestListByWithoutAFilterReturnsEverySuffix(t *testing.T) {
	for name, filter := range map[string]*tenantsuffixesmodels.IdsecIdentityTenantSuffixFilters{
		"nil filter":   nil,
		"blank filter": {ReplaceDomain: "  "},
	} {
		t.Run(name, func(t *testing.T) {
			poster := &mockPoster{t: t, responses: map[string][]string{
				listTenantSuffixURL: {aliasListResponse(
					aliasRow("example.com", "example.com"),
					aliasRow("other.com", "other.com"),
				)},
			}}
			service := newTestService(t, poster)

			got, err := service.ListBy(filter)
			if err != nil {
				t.Fatalf("ListBy returned an error: %v", err)
			}
			if len(got) != 2 {
				t.Errorf("ListBy returned %+v, want both suffixes", got)
			}
		})
	}
}

func TestCreateSendsAliasAndDomainNotSuffix(t *testing.T) {
	// Guards the wire keys against genscaffold gap #10: every generated model is tagged
	// `json:"suffix"`, and the endpoint binds `alias` and `domain` (CoreController.cs:1548). If the
	// request model were ever marshalled directly, this is the test that would catch it.
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL:   {aliasListResponse(), aliasListResponse(aliasRow("example.com", "example.com"))},
		createTenantSuffixURL: {StoreAliasOKResponseJSON},
	}}
	service := newTestService(t, poster)

	created, err := service.Create(&tenantsuffixesmodels.IdsecIdentityCreateTenantSuffix{ReplaceDomain: "example.com"})
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}
	if created.ReplaceDomain != "example.com" {
		t.Errorf("Create returned %q, want the read-back value", created.ReplaceDomain)
	}
	stores := poster.callsTo(createTenantSuffixURL)
	if len(stores) != 1 {
		t.Fatalf("expected exactly one store call, got %d", len(stores))
	}
	body := stores[0].body
	if body[wireAlias] != "example.com" {
		t.Errorf("store body %s = %v, want example.com", wireAlias, body[wireAlias])
	}
	if body[wireDomain] != "example.com" {
		t.Errorf("store body %s = %v, want example.com", wireDomain, body[wireDomain])
	}
	// oldName drives the rename path; "suffix"/"ReplaceDomain" are not bound at all.
	for _, absent := range []string{"suffix", "ReplaceDomain", "oldName"} {
		if _, present := body[absent]; present {
			t.Errorf("store body carried %q, which this resource must not send", absent)
		}
	}
}

func TestCreateSendsCdsAliasTheWayThePortalDoes(t *testing.T) {
	// The suffix dialog creates a CDS alias (NewSuffix.js:20) unless the suffixless fix is on, when it
	// sends false (NewSuffix.js:105, :211) -- true would throw there (TenantAlias.cs:210-214).
	for name, tc := range map[string]struct {
		existing []string
		want     bool
	}{
		"classic tenant with no suffixes": {nil, true},
		"classic tenant":                  {[]string{aliasRowWith("other.com", "other.com", true, false)}, true},
		"suffixless tenant":               {[]string{aliasRowWith("aek7723.other.com", "other.com", false, true)}, false},
	} {
		t.Run(name, func(t *testing.T) {
			poster := &mockPoster{t: t, responses: map[string][]string{
				listTenantSuffixURL: {
					aliasListResponse(tc.existing...),
					aliasListResponse(append(tc.existing, aliasRow("example.com", "example.com"))...),
				},
				createTenantSuffixURL: {StoreAliasOKResponseJSON},
			}}
			service := newTestService(t, poster)

			if _, err := service.Create(&tenantsuffixesmodels.IdsecIdentityCreateTenantSuffix{ReplaceDomain: "example.com"}); err != nil {
				t.Fatalf("Create returned an error: %v", err)
			}
			stores := poster.callsTo(createTenantSuffixURL)
			if len(stores) != 1 {
				t.Fatalf("expected exactly one store call, got %d", len(stores))
			}
			if got, ok := stores[0].body[wireCdsAlias].(bool); !ok || got != tc.want {
				t.Errorf("store body %s = %v, want %t", wireCdsAlias, stores[0].body[wireCdsAlias], tc.want)
			}
		})
	}
}

func TestCreateRefusesAnExistingSuffixBecauseStoreIsAnUpsert(t *testing.T) {
	// StoreAlias is documented "Create or update tenant alias" (CoreController.cs:1490), so without
	// the pre-create check an apply would adopt a suffix it did not create -- and the destroy that
	// followed would remove something predating Terraform. Matching is case-insensitive here for the
	// same reason findRow folds case: two spellings address one row.
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {aliasListResponse(aliasRow("example.com", "example.com"))},
	}}
	service := newTestService(t, poster)

	_, err := service.Create(&tenantsuffixesmodels.IdsecIdentityCreateTenantSuffix{ReplaceDomain: "EXAMPLE.com"})
	if err == nil {
		t.Fatal("Create adopted a pre-existing suffix")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("Create error was %q, want it to name the collision", err)
	}
	if got := len(poster.callsTo(createTenantSuffixURL)); got != 0 {
		t.Errorf("Create posted to the store endpoint %d times, want 0", got)
	}
}

func TestCreateRejectsDuplicateAsBothOrdinalAndName(t *testing.T) {
	// The enum arrives as an ordinal -- the controller's own doc block says "OK: 0, Duplicate: 1"
	// (CoreController.cs:1511) and the UI compares State === 1 (NewSuffix.js:60). The name is
	// accepted too, so that installing a global StringEnumConverter later is not a silent regression.
	for _, payload := range []string{
		StoreAliasDuplicateResponseJSON,
		`{"success":true,"Result":{"State":"Duplicate"}}`,
	} {
		poster := &mockPoster{t: t, responses: map[string][]string{
			listTenantSuffixURL:   {aliasListResponse()},
			createTenantSuffixURL: {payload},
		}}
		service := newTestService(t, poster)

		_, err := service.Create(&tenantsuffixesmodels.IdsecIdentityCreateTenantSuffix{ReplaceDomain: "example.com"})
		if err == nil {
			t.Errorf("Create succeeded on a duplicate result: %s", payload)
			continue
		}
		if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("Create error for %s was %q, want it to name the duplicate", payload, err)
		}
	}
}

func TestCreateAcceptsOKAsBothOrdinalAndName(t *testing.T) {
	for _, payload := range []string{
		StoreAliasOKResponseJSON,
		`{"success":true,"Result":{"State":"OK"}}`,
	} {
		poster := &mockPoster{t: t, responses: map[string][]string{
			listTenantSuffixURL:   {aliasListResponse(), aliasListResponse(aliasRow("example.com", "example.com"))},
			createTenantSuffixURL: {payload},
		}}
		service := newTestService(t, poster)

		if _, err := service.Create(&tenantsuffixesmodels.IdsecIdentityCreateTenantSuffix{ReplaceDomain: "example.com"}); err != nil {
			t.Errorf("Create failed on an OK result %s: %v", payload, err)
		}
	}
}

func TestCreateReadBackFailureReturnsPartialState(t *testing.T) {
	// The store has happened by the time the read-back runs, so a failed read-back must hand the
	// provider a partial result to persist. A plain error would leave the suffix out of state, and
	// every retry would then stop at the "already exists" guard.
	for name, readBack := range map[string]string{
		"list refused":     `{"success":false,"Result":null,"Message":"try again later"}`,
		"row not visible":  aliasListResponse(),
		"malformed result": `{"success":true,"Result":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			poster := &mockPoster{t: t, responses: map[string][]string{
				listTenantSuffixURL:   {aliasListResponse(), readBack},
				createTenantSuffixURL: {StoreAliasOKResponseJSON},
			}}
			service := newTestService(t, poster)

			created, err := service.Create(&tenantsuffixesmodels.IdsecIdentityCreateTenantSuffix{ReplaceDomain: "example.com"})
			if err == nil {
				t.Fatal("Create succeeded although the read-back failed")
			}
			if created != nil {
				t.Errorf("Create returned %+v alongside the error, want nil", created)
			}
			var partial *common.IdsecPartialStateError
			if !errors.As(err, &partial) {
				t.Fatalf("Create error %q is not an IdsecPartialStateError", err)
			}
			result, ok := partial.PartialResult.(*tenantsuffixesmodels.IdsecIdentityTenantSuffix)
			if !ok {
				t.Fatalf("PartialResult is %T, want the state model", partial.PartialResult)
			}
			if result.ReplaceDomain != "example.com" {
				t.Errorf("PartialResult suffix = %q, want example.com", result.ReplaceDomain)
			}
			if !strings.Contains(err.Error(), "could not be read back") {
				t.Errorf("Create error %q does not say the read-back failed", err)
			}
		})
	}
}

func TestCreateFailureBeforeTheStoreIsNotPartial(t *testing.T) {
	// Nothing was stored, so there is nothing to persist: reporting partial state here would record a
	// suffix that does not exist.
	for name, poster := range map[string]*mockPoster{
		"pre-check list refused": {responses: map[string][]string{
			listTenantSuffixURL: {`{"success":false,"Result":null,"Message":"try again later"}`},
		}},
		"store refused": {responses: map[string][]string{
			listTenantSuffixURL:   {aliasListResponse()},
			createTenantSuffixURL: {`{"success":false,"Result":null,"Message":"domain is invalid"}`},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			poster.t = t
			service := newTestService(t, poster)

			_, err := service.Create(&tenantsuffixesmodels.IdsecIdentityCreateTenantSuffix{ReplaceDomain: "example.com"})
			if err == nil {
				t.Fatal("Create succeeded on a refused request")
			}
			var partial *common.IdsecPartialStateError
			if errors.As(err, &partial) {
				t.Errorf("Create reported partial state although nothing was stored: %q", err)
			}
		})
	}
}

func TestCreateRejectsAnUnrecognisedStoreResult(t *testing.T) {
	// A State this code does not know must not be read as success -- an unmapped enum member would
	// otherwise be recorded in state as a created suffix.
	for _, payload := range []string{
		`{"success":true,"Result":{"State":7}}`,
		`{"success":true,"Result":{}}`,
		`{"success":true,"Result":true}`,
	} {
		poster := &mockPoster{t: t, responses: map[string][]string{
			listTenantSuffixURL:   {aliasListResponse()},
			createTenantSuffixURL: {payload},
		}}
		service := newTestService(t, poster)

		if _, err := service.Create(&tenantsuffixesmodels.IdsecIdentityCreateTenantSuffix{ReplaceDomain: "example.com"}); err == nil {
			t.Errorf("Create accepted an unrecognised store result: %s", payload)
		}
	}
}

func TestDeletePostsTheRowKeyNotTheSuffix(t *testing.T) {
	// The decisive test. On a suffixless tenant the row key is recomputed as <CustomerID>.<domain>
	// (CoreController.cs:1566) and DeleteAlias matches on the sanitized key (CoreController.cs:1719),
	// so posting the suffix would match nothing, return early at TenantAlias.cs:823-826, and still
	// report success:true.
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {
			aliasListResponse(aliasRow("abc1234.example.com", "example.com")),
			aliasListResponse(),
		},
		deleteTenantSuffixURL: {DeleteAliasResponseJSON},
	}}
	service := newTestService(t, poster)

	if err := service.Delete(&tenantsuffixesmodels.IdsecIdentityDeleteTenantSuffix{ReplaceDomain: "example.com"}); err != nil {
		t.Fatalf("Delete returned an error: %v", err)
	}
	deletes := poster.callsTo(deleteTenantSuffixURL)
	if len(deletes) != 1 {
		t.Fatalf("expected exactly one delete call, got %d", len(deletes))
	}
	if got := deletes[0].body[wireAlias]; got != "abc1234.example.com" {
		t.Errorf("delete body %s = %v, want the row key abc1234.example.com", wireAlias, got)
	}
}

func TestDeleteFailsWhenTheRowSurvivesASuccessfulResponse(t *testing.T) {
	// TenantAlias.DeleteAlias returns early for a key it cannot find (TenantAlias.cs:823-826) and the
	// envelope still says success:true, so the read-back is the only evidence of removal.
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL:   {aliasListResponse(aliasRow("example.com", "example.com"))},
		deleteTenantSuffixURL: {DeleteAliasResponseJSON},
	}}
	service := newTestService(t, poster)

	err := service.Delete(&tenantsuffixesmodels.IdsecIdentityDeleteTenantSuffix{ReplaceDomain: "example.com"})
	if err == nil {
		t.Fatal("Delete reported success while the row was still present")
	}
	if !strings.Contains(err.Error(), "still present") {
		t.Errorf("Delete error was %q, want it to name the surviving row", err)
	}
}

func TestDeleteRefusesASuffixThatIsNotPresent(t *testing.T) {
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {aliasListResponse()},
	}}
	service := newTestService(t, poster)

	err := service.Delete(&tenantsuffixesmodels.IdsecIdentityDeleteTenantSuffix{ReplaceDomain: "example.com"})
	if err == nil {
		t.Fatal("Delete succeeded for a suffix the tenant does not have")
	}
	if !errors.Is(err, common.ErrNotFound) {
		t.Errorf("Delete error %q does not wrap common.ErrNotFound", err)
	}
	if got := len(poster.callsTo(deleteTenantSuffixURL)); got != 0 {
		t.Errorf("Delete posted to the delete endpoint %d times, want 0", got)
	}
}

func TestDeleteRefusesARowWithNoUsableRowKey(t *testing.T) {
	// Without the ID guard, a row whose ID column came back null would post {alias: ""}, which
	// SanitizeAlias turns into a lookup that matches nothing and reports success.
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {`{"success":true,"Result":{"Results":[` +
			`{"Row":{"ID":null,"ReplaceDomain":"example.com"}}]}}`},
	}}
	service := newTestService(t, poster)

	err := service.Delete(&tenantsuffixesmodels.IdsecIdentityDeleteTenantSuffix{ReplaceDomain: "example.com"})
	if err == nil {
		t.Fatal("Delete proceeded without a row key")
	}
	if got := len(poster.callsTo(deleteTenantSuffixURL)); got != 0 {
		t.Errorf("Delete posted to the delete endpoint %d times, want 0", got)
	}
}

func TestDeleteSurfacesAnInUseRejection(t *testing.T) {
	// A suffix still in use throws TenantAliasInUseException, a single failure is rethrown
	// (CoreController.cs:1830-1832), and StandardJsonResult turns that into success:false at HTTP 200.
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL:   {aliasListResponse(aliasRow("example.com", "example.com"))},
		deleteTenantSuffixURL: {`{"success":false,"Result":null,"Message":"Tenant alias is in use","ErrorID":"abc123"}`},
	}}
	service := newTestService(t, poster)

	err := service.Delete(&tenantsuffixesmodels.IdsecIdentityDeleteTenantSuffix{ReplaceDomain: "example.com"})
	if err == nil {
		t.Fatal("Delete ignored an in-use rejection")
	}
	// Must report the server's reason, not the read-back's "still present" -- the operator needs to
	// know the suffix is in use, which is the difference between a fixable destroy and a mystery.
	if !strings.Contains(err.Error(), "in use") {
		t.Errorf("Delete error was %q, want it to surface the server's reason", err)
	}
}

func TestGetByIDMatchesTheRowKeyAndReturnsIt(t *testing.T) {
	// On a suffixless tenant the row key is <CustomerID>.<domain> (CoreController.cs:1566). The id is
	// what the resource's Read looks up by, so it must match the key and be returned in the state.
	poster := &mockPoster{t: t, responses: map[string][]string{
		readTenantSuffixURL: {aliasListResponse(
			aliasRow("aek7723.example.org", "example.org"),
			aliasRow("aek7723.example.com", "example.com"))},
	}}
	service := newTestService(t, poster)

	got, err := service.Get(&tenantsuffixesmodels.IdsecIdentityGetTenantSuffix{ID: "AEK7723.example.com"})
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if got.ID != "aek7723.example.com" || got.ReplaceDomain != "example.com" {
		t.Errorf("Get returned %+v, want id aek7723.example.com and suffix example.com", got)
	}
}

func TestGetByIDAcceptsTheSuffixSoImportNeedsNoNamespacedKey(t *testing.T) {
	// An import sets only the id, and users know the suffix, not <CustomerID>.<suffix>.
	poster := &mockPoster{t: t, responses: map[string][]string{
		readTenantSuffixURL: {aliasListResponse(aliasRow("aek7723.example.com", "example.com"))},
	}}
	service := newTestService(t, poster)

	got, err := service.Get(&tenantsuffixesmodels.IdsecIdentityGetTenantSuffix{ID: "example.com"})
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if got.ID != "aek7723.example.com" {
		t.Errorf("Get returned id %q, want the stored row key", got.ID)
	}
}

func TestGetFallsBackToTheSuffixWhenTheIDIsUnknown(t *testing.T) {
	// A partial create persists only the suffix, so the next Read has no usable id.
	poster := &mockPoster{t: t, responses: map[string][]string{
		readTenantSuffixURL: {aliasListResponse(aliasRow("aek7723.example.com", "example.com"))},
	}}
	service := newTestService(t, poster)

	got, err := service.Get(&tenantsuffixesmodels.IdsecIdentityGetTenantSuffix{ID: "stale.example.net", ReplaceDomain: "example.com"})
	if err != nil {
		t.Fatalf("Get returned an error: %v", err)
	}
	if got.ID != "aek7723.example.com" {
		t.Errorf("Get returned id %q, want aek7723.example.com", got.ID)
	}
}

func TestUpdateRenamesByPostingTheRowKeyAsOldName(t *testing.T) {
	// oldName must be the stored key: with the suffixless fix on, the suffix itself matches no row and
	// EnforceOldAliasValidation rejects it (TenantAlias.cs:264-290).
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {
			aliasListResponse(aliasRow("aek7723.example.com", "example.com")),
			aliasListResponse(aliasRow("aek7723.example.org", "example.org")),
		},
		updateTenantSuffixURL: {StoreAliasOKResponseJSON},
	}}
	service := newTestService(t, poster)

	renamed, err := service.Update(&tenantsuffixesmodels.IdsecIdentityUpdateTenantSuffix{
		ID: "aek7723.example.com", ReplaceDomain: "example.org",
	})
	if err != nil {
		t.Fatalf("Update returned an error: %v", err)
	}
	if renamed.ID != "aek7723.example.org" || renamed.ReplaceDomain != "example.org" {
		t.Errorf("Update returned %+v, want the new row", renamed)
	}
	stores := poster.callsTo(updateTenantSuffixURL)
	if len(stores) != 1 {
		t.Fatalf("expected exactly one store call, got %d", len(stores))
	}
	body := stores[0].body
	for key, want := range map[string]string{
		wireAlias: "example.org", wireDomain: "example.org", wireOldName: "aek7723.example.com",
	} {
		if body[key] != want {
			t.Errorf("store body %s = %v, want %s", key, body[key], want)
		}
	}
}

func TestUpdatePreservesTheRowsCdsAlias(t *testing.T) {
	// The rename stores cdsAlias from the argument rather than the old row (TenantAlias.cs:360, :449),
	// so it must be restated: the dialog sends the row's own flag (NewSuffix.js:20), or false once the
	// suffixless fix is on (NewSuffix.js:105, :211).
	for name, tc := range map[string]struct {
		cdsAlias, suffixless, want bool
	}{
		"classic CDS alias":            {cdsAlias: true, want: true},
		"classic non-CDS alias":        {cdsAlias: false, want: false},
		"suffixless tenant, CDS row":   {cdsAlias: true, suffixless: true, want: false},
		"suffixless tenant, plain row": {suffixless: true, want: false},
	} {
		t.Run(name, func(t *testing.T) {
			poster := &mockPoster{t: t, responses: map[string][]string{
				listTenantSuffixURL: {
					aliasListResponse(aliasRowWith("example.com", "example.com", tc.cdsAlias, tc.suffixless)),
					aliasListResponse(aliasRowWith("example.org", "example.org", tc.want, tc.suffixless)),
				},
				updateTenantSuffixURL: {StoreAliasOKResponseJSON},
			}}
			service := newTestService(t, poster)

			if _, err := service.Update(&tenantsuffixesmodels.IdsecIdentityUpdateTenantSuffix{
				ID: "example.com", ReplaceDomain: "example.org",
			}); err != nil {
				t.Fatalf("Update returned an error: %v", err)
			}
			stores := poster.callsTo(updateTenantSuffixURL)
			if len(stores) != 1 {
				t.Fatalf("expected exactly one store call, got %d", len(stores))
			}
			if got, ok := stores[0].body[wireCdsAlias].(bool); !ok || got != tc.want {
				t.Errorf("store body %s = %v, want %t", wireCdsAlias, stores[0].body[wireCdsAlias], tc.want)
			}
		})
	}
}

func TestCdsAliasColumnAcceptsAStringSpelling(t *testing.T) {
	for raw, want := range map[interface{}]bool{
		true: true, false: false, "True": true, "false": false, nil: false, 1.0: false,
	} {
		if got := flagValue(raw); got != want {
			t.Errorf("flagValue(%#v) = %t, want %t", raw, got, want)
		}
	}
}

func TestUpdateResolvesASuffixGivenAsTheID(t *testing.T) {
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {
			aliasListResponse(aliasRow("aek7723.example.com", "example.com")),
			aliasListResponse(aliasRow("aek7723.example.org", "example.org")),
		},
		updateTenantSuffixURL: {StoreAliasOKResponseJSON},
	}}
	service := newTestService(t, poster)

	if _, err := service.Update(&tenantsuffixesmodels.IdsecIdentityUpdateTenantSuffix{
		ID: "example.com", ReplaceDomain: "example.org",
	}); err != nil {
		t.Fatalf("Update returned an error: %v", err)
	}
	if got := poster.callsTo(updateTenantSuffixURL)[0].body[wireOldName]; got != "aek7723.example.com" {
		t.Errorf("oldName = %v, want the row key aek7723.example.com", got)
	}
}

func TestUpdateOfAnUnknownSuffixIsNotFoundAndStoresNothing(t *testing.T) {
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {aliasListResponse(aliasRow("aek7723.example.org", "example.org"))},
	}}
	service := newTestService(t, poster)

	_, err := service.Update(&tenantsuffixesmodels.IdsecIdentityUpdateTenantSuffix{
		ID: "aek7723.example.com", ReplaceDomain: "example.net",
	})
	if !errors.Is(err, common.ErrNotFound) {
		t.Errorf("Update error = %v, want one wrapping common.ErrNotFound", err)
	}
	if n := len(poster.callsTo(updateTenantSuffixURL)); n != 0 {
		t.Errorf("Update posted %d store calls for a suffix that does not exist", n)
	}
}

func TestUpdateToTheSameSuffixStoresNothing(t *testing.T) {
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {aliasListResponse(aliasRow("aek7723.example.com", "example.com"))},
	}}
	service := newTestService(t, poster)

	got, err := service.Update(&tenantsuffixesmodels.IdsecIdentityUpdateTenantSuffix{
		ID: "aek7723.example.com", ReplaceDomain: "example.com",
	})
	if err != nil {
		t.Fatalf("Update returned an error: %v", err)
	}
	if got.ID != "aek7723.example.com" {
		t.Errorf("Update returned %+v, want the existing row", got)
	}
	if n := len(poster.callsTo(updateTenantSuffixURL)); n != 0 {
		t.Errorf("Update posted %d store calls for an unchanged suffix", n)
	}
}

func TestUpdateOntoAnExistingSuffixIsRefused(t *testing.T) {
	// The server throws DuplicateTenantAliasException for a rename onto a row that already exists
	// (TenantAlias.cs:320-330), reported as State 1. Nothing was stored, so this is not partial.
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {aliasListResponse(
			aliasRow("aek7723.example.com", "example.com"),
			aliasRow("aek7723.example.org", "example.org"))},
		updateTenantSuffixURL: {StoreAliasDuplicateResponseJSON},
	}}
	service := newTestService(t, poster)

	_, err := service.Update(&tenantsuffixesmodels.IdsecIdentityUpdateTenantSuffix{
		ID: "aek7723.example.com", ReplaceDomain: "example.org",
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Update error = %v, want an already-exists error", err)
	}
	var partial *common.IdsecPartialStateError
	if errors.As(err, &partial) {
		t.Error("a refused rename was reported as a partial success")
	}
}

func TestUpdateWhoseOldRowSurvivesIsPartial(t *testing.T) {
	// The old row is deleted only when every user on it was moved; otherwise it stays and the call
	// still reports OK (TenantAlias.cs:801-816). The new row exists, so Terraform must track it.
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {
			aliasListResponse(aliasRow("aek7723.example.com", "example.com")),
			aliasListResponse(
				aliasRow("aek7723.example.com", "example.com"),
				aliasRow("aek7723.example.org", "example.org")),
		},
		updateTenantSuffixURL: {StoreAliasOKResponseJSON},
	}}
	service := newTestService(t, poster)

	_, err := service.Update(&tenantsuffixesmodels.IdsecIdentityUpdateTenantSuffix{
		ID: "aek7723.example.com", ReplaceDomain: "example.org",
	})
	var partial *common.IdsecPartialStateError
	if !errors.As(err, &partial) {
		t.Fatalf("Update error %v is not an IdsecPartialStateError", err)
	}
	result, ok := partial.PartialResult.(*tenantsuffixesmodels.IdsecIdentityTenantSuffix)
	if !ok || result.ID != "aek7723.example.org" || result.ReplaceDomain != "example.org" {
		t.Errorf("PartialResult = %+v, want the new row", partial.PartialResult)
	}
	if !strings.Contains(err.Error(), "still present") {
		t.Errorf("Update error %q does not say the old suffix survived", err)
	}
}

func TestUpdateWhoseNewRowIsMissingIsPartial(t *testing.T) {
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {
			aliasListResponse(aliasRow("aek7723.example.com", "example.com")),
			aliasListResponse(aliasRow("aek7723.example.com", "example.com")),
		},
		updateTenantSuffixURL: {StoreAliasOKResponseJSON},
	}}
	service := newTestService(t, poster)

	_, err := service.Update(&tenantsuffixesmodels.IdsecIdentityUpdateTenantSuffix{
		ID: "aek7723.example.com", ReplaceDomain: "example.org",
	})
	var partial *common.IdsecPartialStateError
	if !errors.As(err, &partial) {
		t.Fatalf("Update error %v is not an IdsecPartialStateError", err)
	}
	if result, ok := partial.PartialResult.(*tenantsuffixesmodels.IdsecIdentityTenantSuffix); !ok || result.ReplaceDomain != "example.org" {
		t.Errorf("PartialResult = %+v, want the new suffix", partial.PartialResult)
	}
}

func TestUpdateCaseOnlyRenameKeepsTheRowKey(t *testing.T) {
	// The key is case-folded (TenantAlias.cs:686-689), so a case-only rename updates the same row and
	// its surviving key is not a failed delete.
	poster := &mockPoster{t: t, responses: map[string][]string{
		listTenantSuffixURL: {
			aliasListResponse(aliasRow("example.com", "example.com")),
			aliasListResponse(aliasRow("example.com", "Example.com")),
		},
		updateTenantSuffixURL: {StoreAliasOKResponseJSON},
	}}
	service := newTestService(t, poster)

	got, err := service.Update(&tenantsuffixesmodels.IdsecIdentityUpdateTenantSuffix{
		ID: "example.com", ReplaceDomain: "Example.com",
	})
	if err != nil {
		t.Fatalf("Update returned an error: %v", err)
	}
	if got.ReplaceDomain != "Example.com" {
		t.Errorf("Update returned suffix %q, want Example.com", got.ReplaceDomain)
	}
}

func TestFailureArrivesAsHTTP200WithSuccessFalse(t *testing.T) {
	// JsonRest.Failure writes success:false at HTTP 200 (CoreController.cs:1563, :1573), so the status
	// code alone would read a server-side refusal as a success with an empty result -- and an empty
	// read is what makes Terraform drop a resource from state.
	//
	// Both Failure overloads are covered. Failure(message) leaves Result null
	// (JsonResponse.cs:187), which a parse guard would also happen to catch; Failure(result, message)
	// carries a payload (JsonResponse.cs:212), and THAT one decodes cleanly, so only the success flag
	// distinguishes it from a real answer. The assertion is on the server's message, not merely on
	// non-nil error, so that a parse failure cannot stand in for the flag check.
	for _, payload := range []string{
		`{"success":false,"Result":null,"Message":"domain cannot be empty","ErrorID":"abc123"}`,
		`{"success":false,"Result":{"Count":0,"Results":[]},"Message":"domain cannot be empty","ErrorID":"abc123"}`,
	} {
		poster := &mockPoster{t: t, responses: map[string][]string{
			listTenantSuffixURL: {payload},
		}}
		service := newTestService(t, poster)

		_, err := service.List()
		if err == nil {
			t.Errorf("List treated success:false at HTTP 200 as a success: %s", payload)
			continue
		}
		if !strings.Contains(err.Error(), "domain cannot be empty") {
			t.Errorf("List error for %s was %q, want it to surface the server's message", payload, err)
		}
	}
}

func TestNonOKStatusIsAnError(t *testing.T) {
	service, err := NewIdsecIdentityTenantSuffixesService(MockISPAuth())
	if err != nil {
		t.Fatalf("failed to construct service: %v", err)
	}
	service.DoPost = func(_ context.Context, _ string, _ interface{}) (*http.Response, error) {
		return MockHTTPResponse(http.StatusUnauthorized, `{"success":false}`), nil
	}

	if _, err := service.List(); err == nil {
		t.Fatal("List ignored a non-200 status")
	}
}

func TestTransportErrorPropagates(t *testing.T) {
	poster := &mockPoster{t: t, responses: map[string][]string{}, err: errors.New("connection refused")}
	service := newTestService(t, poster)

	_, err := service.List()
	if err == nil {
		t.Fatal("List swallowed a transport error")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("List error was %q, want the transport error", err)
	}
}

func TestMalformedListResponseIsAnError(t *testing.T) {
	// A payload that is not the grid envelope must be reported rather than read as an empty tenant --
	// an empty read is what makes Terraform delete a resource from state.
	for _, payload := range []string{
		`{"success":true,"Result":[]}`,
		`{"success":true,"Result":{"Results":{}}}`,
		`{"success":true,"Result":{"Results":[{"ID":"example.com"}]}}`,
	} {
		poster := &mockPoster{t: t, responses: map[string][]string{
			listTenantSuffixURL: {payload},
		}}
		service := newTestService(t, poster)

		if _, err := service.List(); err == nil {
			t.Errorf("List accepted a malformed response: %s", payload)
		}
	}
}

func TestBlankSuffixIsRejectedBeforeAnyRequest(t *testing.T) {
	poster := &mockPoster{t: t, responses: map[string][]string{}}
	service := newTestService(t, poster)

	if _, err := service.Create(&tenantsuffixesmodels.IdsecIdentityCreateTenantSuffix{ReplaceDomain: "   "}); err == nil {
		t.Error("Create accepted a blank suffix")
	}
	if _, err := service.Get(&tenantsuffixesmodels.IdsecIdentityGetTenantSuffix{ReplaceDomain: ""}); err == nil {
		t.Error("Get accepted a blank suffix")
	}
	if err := service.Delete(&tenantsuffixesmodels.IdsecIdentityDeleteTenantSuffix{ReplaceDomain: ""}); err == nil {
		t.Error("Delete accepted a blank suffix")
	}
	if _, err := service.Update(&tenantsuffixesmodels.IdsecIdentityUpdateTenantSuffix{ID: "example.com", ReplaceDomain: " "}); err == nil {
		t.Error("Update accepted a blank suffix")
	}
	if _, err := service.Update(&tenantsuffixesmodels.IdsecIdentityUpdateTenantSuffix{ID: "", ReplaceDomain: "example.org"}); err == nil {
		t.Error("Update accepted a blank id")
	}
	if len(poster.calls) != 0 {
		t.Errorf("a blank suffix reached the wire: %+v", poster.calls)
	}
}

func TestServiceConfigIsWired(t *testing.T) {
	// The constructor assigns the service to services.IdsecService, so a missing ServiceConfig would
	// not compile; this asserts it returns the package-level config rather than a zero value.
	service, err := NewIdsecIdentityTenantSuffixesService(MockISPAuth())
	if err != nil {
		t.Fatalf("failed to construct service: %v", err)
	}
	if got := service.ServiceConfig().ServiceName; got != ServiceConfig.ServiceName {
		t.Errorf("ServiceConfig().ServiceName = %q, want %q", got, ServiceConfig.ServiceName)
	}
}
