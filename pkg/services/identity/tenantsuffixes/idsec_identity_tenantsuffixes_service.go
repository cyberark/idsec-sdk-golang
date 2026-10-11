// Package tenantsuffixes provides the Identity tenant suffixes service, which creates, reads, lists, renames and deletes tenant login suffixes.
package tenantsuffixes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	identitycommon "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/common"
	tenantsuffixesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/tenantsuffixes/models"
)

// Citations. The server behaviour this service depends on is documented only in the Identity Cloud
// source, so the comments in this package cite it as file:line. Every such citation is against the
// `cloud` repository at origin/dev 2ce410a6 (2026-09-08) -- *.cs files are the server, and *.js files
// under Lib/ui are the admin portal. Read them at that revision: the line numbers drift as `cloud`
// moves. Paths under internal/ are in terraform-provider-idsec.

// Endpoint paths, relative to the api/idadmin base.
const (
	createTenantSuffixURL = "Core/StoreAlias"
	updateTenantSuffixURL = "Core/StoreAlias"
	deleteTenantSuffixURL = "Core/DeleteAlias"
	listTenantSuffixURL   = "Core/GetAliasesForTenant"
	readTenantSuffixURL   = "Core/GetAliasesForTenant"
)

// Wire keys.
//
// The generated models tag every field `json:"suffix"` because genscaffold's jsonTag()
// (helpers.go:147) emits the Mapstructure value and discards FieldSpec.Name -- which spec.go:131
// documents as "PascalCase, as in the C# controller", i.e. the actual wire spelling. The generator
// therefore holds the wire key and throws it away, so it has to be restated here. Nothing on this
// wire is called "suffix".
// Request keys. StoreAlias(string alias, string domain, string oldName, bool? cdsAlias)
// (CoreController.cs:1548) and DeleteAlias(string alias) (CoreController.cs:1702) bind by parameter
// name, and both are confirmed against the product's own posts: the suffix form submits its field
// values to core/StoreAlias (Lib/ui/Core/view/loginSuffix/NewSuffix.js:50) and the support screen
// posts {alias: ...} to core/DeleteAlias (Lib/ui/Core/view/SupportSetting.js:349).
//
// Note DeleteAlias's own <bodyargs> doc block (CoreController.cs:1693) documents this key as
// "Suffix". That is stale: the bound parameter is `alias`, and `alias` is what the product sends.
const (
	wireAlias    = "alias"
	wireDomain   = "domain"
	wireOldName  = "oldName"
	wireCdsAlias = "cdsAlias"
)

// Response columns, declared by the list endpoint's grid schema (CoreController.cs:1255-1260).
//
// ID is the stored row key: MakeQueryResponse promotes the entity's _RowKey to a column named "ID"
// (UiQueryResponse.cs:49-53, :102). ReplaceDomain is the suffix as the caller wrote it. CdsAlias is the
// row's stored flag. DisplaySuffix is declared only while the suffixless fix is on
// (CoreController.cs:1267-1280), so its presence is what tells the two tenant modes apart.
const (
	wireReplaceDomain  = "ReplaceDomain"
	wireID             = "ID"
	wireCdsAliasColumn = "CdsAlias"
	wireDisplaySuffix  = "DisplaySuffix"
)

// StoreAlias reports its outcome as a StoreAliasResult (CoreController.cs:1470-1474) and the enum
// arrives as an ORDINAL, not a name: no JsonConvert.DefaultSettings assignment exists anywhere in
// the cloud tree, so Newtonsoft's default holds. The controller's own doc block states the mapping
// outright -- "StoreAliasResult. OK: 0, Duplicate: 1" (CoreController.cs:1511) -- and the product's
// UI compares result.Result.State === 1 for the duplicate case (NewSuffix.js:60).
const (
	storeAliasResultOK        = 0
	storeAliasResultDuplicate = 1
)

// IdsecIdentityTenantSuffixesService is the service for managing tenant suffix.
type IdsecIdentityTenantSuffixesService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService

	DoPost func(ctx context.Context, path string, body interface{}) (*http.Response, error)
}

// NewIdsecIdentityTenantSuffixesService creates a new instance of IdsecIdentityTenantSuffixesService.
func NewIdsecIdentityTenantSuffixesService(authenticators ...auth.IdsecAuth) (*IdsecIdentityTenantSuffixesService, error) {
	service := &IdsecIdentityTenantSuffixesService{}
	var serviceInterface services.IdsecService = service
	baseService, err := services.NewIdsecBaseService(serviceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "", "", "api/idadmin", service.refreshIdentityTenantSuffixesAuth)
	if err != nil {
		return nil, err
	}

	ispBaseService.ISPClient().UpdateHeaders(map[string]string{
		"X-IDAP-NATIVE-CLIENT": "true",
	})

	baseURL, err := identitycommon.ResolveIdentityServiceURL(ispAuth, ispBaseService.ISPClient().BaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve identity service URL: %w", err)
	}
	ispBaseService.ISPClient().BaseURL = baseURL

	service.IdsecBaseService = baseService
	service.IdsecISPBaseService = ispBaseService
	return service, nil
}

func (s *IdsecIdentityTenantSuffixesService) postOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.DoPost != nil {
		return s.DoPost
	}
	return s.ISPClient().Post
}

func (s *IdsecIdentityTenantSuffixesService) refreshIdentityTenantSuffixesAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// call posts to path and returns the payload carried inside the JsonRest envelope.
//
// Every CyberArk Identity endpoint wraps its payload as {"success": <bool>, "Result": <payload>},
// and a refusal is written with success:false at HTTP 200, so the status code alone reports a
// server-side rejection as a success with an empty result. There is no shared helper for this --
// pkg/services/identity/common is 57 lines and holds only the URL resolver -- so this follows the
// sibling idiom at authprofiles/idsec_identity_authprofiles_service.go:269-283, factored once here
// rather than repeated per operation.
func (s *IdsecIdentityTenantSuffixesService) call(operation, path string, body interface{}) (interface{}, error) {
	response, err := s.postOperation()(context.Background(), path, body)
	if err != nil {
		s.Logger.Error("Error %s identity tenant suffix: %s", operation, err.Error())
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		if err := Body.Close(); err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to %s identity tenant suffix - [%d] - [%s]",
			operation, response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	var result map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}
	if res, ok := result["success"].(bool); !ok || !res {
		return nil, fmt.Errorf("failed to %s identity tenant suffix - [%v]", operation, result)
	}
	return result["Result"], nil
}

// suffixRow is one row of the alias list response.
//
// Both columns are pointers because the grid builder fills every column declared in the schema that
// a row does not actually carry with an explicit null -- `if (!row.Has(coldesc.Name))
// row.Set(coldesc.Name, null)` (UiQueryResponse.cs:113-117). So "this row has no ReplaceDomain"
// arrives as JSON null rather than as an empty string, and the two must stay distinguishable.
//
// The same fill is why hasDisplaySuffix is set on every row or on none: the column is present in the
// schema exactly when the suffixless fix is on, and absent from every row otherwise.
type suffixRow struct {
	id               *string
	replaceDomain    *string
	cdsAlias         bool
	hasDisplaySuffix bool
}

// optionalString narrows a decoded JSON value to a string, yielding nil for null or a non-string.
func optionalString(v interface{}) *string {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}

// flagValue narrows a decoded JSON value to a bool. The entity stores CdsAlias as a bool
// (TenantAlias.cs:360), but a string spelling is accepted too; null and anything else read as false,
// which is also the server's own default for the column (CoreController.cs:1275).
func flagValue(v interface{}) bool {
	switch value := v.(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "true")
	default:
		return false
	}
}

// suffixlessMode reports whether the tenant runs with the suffixless fix on, i.e. both
// AllowUsersWithoutSuffix and EnableSuffixlessFix (CoreController.cs:1480-1483). That is exactly the
// condition the product's suffix dialog tests before choosing cdsAlias (NewSuffix.js:105), and the list
// response reveals it by declaring the DisplaySuffix column. A tenant with no rows reads as classic.
func suffixlessMode(rows []suffixRow) bool {
	for _, row := range rows {
		if row.hasDisplaySuffix {
			return true
		}
	}
	return false
}

// listRows returns every alias row the tenant has, as the server presents them.
//
// The list response is the standard identity grid envelope -- Result.Results[], each element
// carrying its columns under "Row" -- which is the same shape the sibling walks at
// authprofiles/idsec_identity_authprofiles_service.go:357-379.
func (s *IdsecIdentityTenantSuffixesService) listRows(operation, path string) ([]suffixRow, error) {
	raw, err := s.call(operation, path, map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	resultMap, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse identity tenant suffix result - [%v]", raw)
	}
	results, ok := resultMap["Results"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to parse identity tenant suffix results - [%v]", resultMap)
	}
	rows := make([]suffixRow, 0, len(results))
	for _, entry := range results {
		entryMap, ok := entry.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to parse identity tenant suffix entry - [%v]", entry)
		}
		rowMap, ok := entryMap["Row"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("failed to parse identity tenant suffix row - [%v]", entryMap)
		}
		_, hasDisplaySuffix := rowMap[wireDisplaySuffix]
		rows = append(rows, suffixRow{
			id:               optionalString(rowMap[wireID]),
			replaceDomain:    optionalString(rowMap[wireReplaceDomain]),
			cdsAlias:         flagValue(rowMap[wireCdsAliasColumn]),
			hasDisplaySuffix: hasDisplaySuffix,
		})
	}
	return rows, nil
}

// manageableRows drops the rows this resource cannot address by suffix.
//
// A legacy alias may carry no ReplaceDomain at all: the controller guards its own use of the column
// with !string.IsNullOrEmpty (CoreController.cs:1277) and reads it with a "" default
// (TenantAlias.cs:702). Such a row has no suffix to identify it, so leaving it in would let a lookup
// for the empty string match -- and then delete -- an arbitrary legacy alias.
func manageableRows(rows []suffixRow) []suffixRow {
	out := make([]suffixRow, 0, len(rows))
	for _, row := range rows {
		if row.replaceDomain == nil || *row.replaceDomain == "" {
			continue
		}
		out = append(out, row)
	}
	return out
}

// findRow returns the manageable row whose ReplaceDomain matches suffix.
//
// Matched with strings.EqualFold rather than by reproducing the server's normalisation. The store
// addresses rows by a case-folded key -- SanitizeAlias is SanitizeRowKey(alias).ToLowerInvariant()
// (TenantAlias.cs:686-689) -- so two spellings of one suffix are one row, and the product compares
// these values with InvariantCultureIgnoreCase (TenantAlias.cs:952). Folding case only, instead of
// applying SanitizeRowKey too, keeps a difference that is NOT case-only visible rather than
// silently matching it.
func findRow(rows []suffixRow, suffix string) (suffixRow, bool) {
	for _, row := range manageableRows(rows) {
		if strings.EqualFold(*row.replaceDomain, suffix) {
			return row, true
		}
	}
	return suffixRow{}, false
}

// findRowByKey returns the manageable row addressed by key, which may be either the stored row key
// or the suffix itself.
//
// The row key is tried first because it is the resource's id and is unique by construction. Falling
// back to the suffix is what keeps `terraform import ... example.com` working on a tenant where the
// key is <CustomerID>.example.com (CoreController.cs:1566): nobody should have to know the namespaced
// form to import a suffix they can see in the portal. Case is folded for both, for the reason findRow
// gives.
func findRowByKey(rows []suffixRow, key string) (suffixRow, bool) {
	for _, row := range manageableRows(rows) {
		if row.id != nil && strings.EqualFold(*row.id, key) {
			return row, true
		}
	}
	return findRow(rows, key)
}

// toModel converts a manageable row to the state model.
func toModel(row suffixRow) *tenantsuffixesmodels.IdsecIdentityTenantSuffix {
	model := &tenantsuffixesmodels.IdsecIdentityTenantSuffix{ReplaceDomain: *row.replaceDomain}
	if row.id != nil {
		model.ID = *row.id
	}
	return model
}

// checkStoreAliasResult reads the StoreAliasResult that StoreAlias reports inside its envelope.
//
// The payload is the anonymous object `new { State = StoreAliasResult.OK }`
// (CoreController.cs:1593-1595), so the outcome sits under "State" rather than being the Result
// itself. Both the ordinal and the name are accepted: the ordinal is what arrives today (see the
// storeAliasResult constants), and tolerating the name means installing a global
// StringEnumConverter later would not silently turn every create into an unrecognised outcome.
func checkStoreAliasResult(raw interface{}, suffix string) error {
	resultMap, ok := raw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("failed to parse store result for identity tenant suffix [%s] - [%v]", suffix, raw)
	}
	state, present := resultMap["State"]
	if !present {
		return fmt.Errorf("store result for identity tenant suffix [%s] carried no State - [%v]", suffix, resultMap)
	}
	switch value := state.(type) {
	case float64:
		switch int(value) {
		case storeAliasResultOK:
			return nil
		case storeAliasResultDuplicate:
			return fmt.Errorf("identity tenant suffix [%s] already exists", suffix)
		}
	case string:
		switch value {
		case "OK":
			return nil
		case "Duplicate":
			return fmt.Errorf("identity tenant suffix [%s] already exists", suffix)
		}
	}
	return fmt.Errorf("unexpected store result for identity tenant suffix [%s] - [%v]", suffix, state)
}

// Create creates a new tenant suffix.
//
// The signature takes no context.Context, and that is not an omission. The Terraform provider
// invokes these methods by reflection and passes exactly one argument, the request model --
// terraform-provider-idsec's internal/provider/idsec_resource.go builds actionArgs from
// operationSchemaInput alone and then calls actionMethod.Call(actionArgs). A leading ctx parameter
// makes the arity disagree, and reflect.Value.Call panics rather than returning an error.
func (s *IdsecIdentityTenantSuffixesService) Create(arg *tenantsuffixesmodels.IdsecIdentityCreateTenantSuffix) (*tenantsuffixesmodels.IdsecIdentityTenantSuffix, error) {
	suffix := strings.TrimSpace(arg.ReplaceDomain)
	if suffix == "" {
		return nil, fmt.Errorf("suffix must be provided")
	}
	s.Logger.Debug("Creating identity tenant suffix [%s]", suffix)

	// Create is an UPSERT, so the server cannot be relied on to refuse an existing suffix. The
	// method's own doc comment is "Create or update tenant alias" (CoreController.cs:1490), and
	// StoreAliasResult.Duplicate is returned only when TenantAlias throws
	// DuplicateTenantAliasException (CoreController.cs:1591-1594) -- storing over a row the caller
	// already owns is a successful update. Without this check `terraform apply` would silently adopt
	// a suffix it did not create, and the `terraform destroy` that follows would remove something
	// that predates Terraform. The product's UI performs the same guard client-side against the grid
	// it already holds (NewSuffix.js:39-43). genscaffold cannot emit this.
	//
	// The guard catches only a suffix that already exists when Create starts. It does not close the
	// window between this list and the StoreAlias below: a concurrent create of the same suffix (another
	// Terraform run, the CLI, or the product UI) is not detected, and the upsert lets the later store
	// overwrite the earlier one. The API has no atomic check-and-store, so this cannot be closed here.
	existing, err := s.listRows("create", listTenantSuffixURL)
	if err != nil {
		return nil, err
	}
	if _, found := findRow(existing, suffix); found {
		return nil, fmt.Errorf("identity tenant suffix [%s] already exists", suffix)
	}

	// alias and domain both carry the suffix.
	//
	// Every in-product caller sets them equal, and the UI says why: it back-fills
	// `formVals.domain = formVals.alias` with the comment "domain always equal to alias since only
	// cus alias can be created" (NewSuffix.js:33-35). The two are not interchangeable on the server,
	// though -- when the suffixless fix is on, the alias argument is DISCARDED and recomputed as
	// <CustomerID>.<domain> (CoreController.cs:1559-1566), so `domain` is the only one of the pair
	// that always reaches the stored ReplaceDomain column, which is the value this resource exposes.
	//
	// oldName is omitted because it turns the store into a rename, which is Update's job.
	//
	// cdsAlias follows the product's suffix dialog: a new suffix is a CDS alias
	// (`this.getIsCUSSuffix() || true`, NewSuffix.js:20) unless the suffixless fix is on, when it is
	// sent as false (NewSuffix.js:105, :211). Both halves matter. Omitting it stores false on a classic
	// tenant (CoreController.cs:1553), and the row is then skipped by consumers that look for a CDS
	// alias, such as inbound provisioning (Synchronizer.cs:1186). Sending true on a suffixless tenant
	// throws (TenantAlias.cs:210-214). On a tenant with AllowUsersWithoutSuffix on but the fix off, the
	// server refuses the create either way (TenantAlias.cs:224-242), just as the dialog hides Add there.
	raw, err := s.call("create", createTenantSuffixURL, map[string]interface{}{
		wireAlias:    suffix,
		wireDomain:   suffix,
		wireCdsAlias: !suffixlessMode(existing),
	})
	if err != nil {
		return nil, err
	}
	if err := checkStoreAliasResult(raw, suffix); err != nil {
		return nil, err
	}

	// Read back rather than echoing the request: the server trims both arguments
	// (CoreController.cs:1550-1552) and derives the row key itself, so what it stored is not
	// necessarily what was sent.
	//
	// A failed read-back is a partial success, not a failure: the store has already happened. Returned
	// as a plain error, nothing would reach Terraform state, and every retry would then stop at the
	// "already exists" guard above -- the suffix could only be recovered by `terraform import`. The
	// provider persists PartialResult and surfaces the error as a warning; the next refresh reads the
	// row properly, or drops it from state via ErrNotFound if it really is absent.
	created, err := s.Get(&tenantsuffixesmodels.IdsecIdentityGetTenantSuffix{ReplaceDomain: suffix})
	if err != nil {
		return nil, common.NewPartialStateError(
			fmt.Errorf("identity tenant suffix [%s] was stored but could not be read back: %w", suffix, err),
			&tenantsuffixesmodels.IdsecIdentityTenantSuffix{ReplaceDomain: suffix})
	}
	return created, nil
}

// Delete removes a tenant suffix.
//
// See Create for why there is no context.Context parameter.
func (s *IdsecIdentityTenantSuffixesService) Delete(arg *tenantsuffixesmodels.IdsecIdentityDeleteTenantSuffix) error {
	suffix := strings.TrimSpace(arg.ReplaceDomain)
	if suffix == "" {
		return fmt.Errorf("suffix must be provided")
	}
	s.Logger.Debug("Deleting identity tenant suffix [%s]", suffix)

	// Delete is the ONE operation that needs the stored row key rather than the suffix.
	//
	// DeleteAlias sanitizes whatever it is handed -- SanitizeAlias(rawAlias ?? string.Empty)
	// (CoreController.cs:1719) -- and looks the row up by that key. When nothing matches,
	// TenantAlias.DeleteAlias returns early at `if (existDE == null) { return; }`
	// (TenantAlias.cs:819-826), and because that is an ordinary return rather than a throw the
	// envelope still reports success:true. On a suffixless tenant the row key is
	// <CustomerID>.<domain> (CoreController.cs:1566), so passing the suffix would match nothing and
	// report a successful delete having removed nothing at all.
	//
	// So resolve the key first. It is the ID column, which the grid builder promotes from the
	// entity's _RowKey (UiQueryResponse.cs:49-53, :102). This is the same shape the sibling uses to
	// delete an auth profile known only by name, resolving it to a Uuid via a list call before
	// posting the delete (authprofiles/idsec_identity_authprofiles_service.go:292-303).
	rows, err := s.listRows("delete", listTenantSuffixURL)
	if err != nil {
		return err
	}
	row, found := findRow(rows, suffix)
	if !found {
		// Wraps common.ErrNotFound, like Get, so a caller can tell "already gone" from a failed delete.
		return fmt.Errorf("identity tenant suffix [%s] not found: %w", suffix, common.ErrNotFound)
	}
	if row.id == nil || *row.id == "" {
		return fmt.Errorf("identity tenant suffix [%s] has no row key to delete by", suffix)
	}
	if _, err := s.call("delete", deleteTenantSuffixURL, map[string]interface{}{
		wireAlias: *row.id,
	}); err != nil {
		return err
	}

	// Confirm the row is gone instead of trusting the success flag. The delete path reports success
	// for a key it never found (TenantAlias.cs:823-826), so a read-back is the only evidence the row
	// was actually removed. An in-use suffix does surface as an error rather than reaching here: a
	// single failure is rethrown at CoreController.cs:1830-1832, which StandardJsonResult turns into
	// success:false, and `call` rejects that.
	remaining, err := s.listRows("delete", listTenantSuffixURL)
	if err != nil {
		return err
	}
	if _, stillPresent := findRow(remaining, suffix); stillPresent {
		return fmt.Errorf("identity tenant suffix [%s] still present after delete reported success", suffix)
	}
	return nil
}

// Update renames a tenant suffix.
//
// StoreAlias is both the create and the rename: given oldName it stores the new row, moves every
// Cloud Directory user whose login is on the old suffix to the new one, repoints the default suffix
// if it was the old one, and then deletes the old row (TenantAlias.cs:308, :362, :364-378, :495,
// :771-807). The product's suffix dialog renames the same way, posting the row's ID as oldName
// (Lib/ui/Core/view/loginSuffix/NewSuffix.js:212-216).
//
// oldName must be the stored row key, not the suffix, for the same reason Delete needs it: on a
// suffixless tenant the key is <CustomerID>.<domain>, and with EnforceOldAliasValidation on, a key that
// matches nothing is rejected (TenantAlias.cs:264-290) -- or, with it off, silently turns the rename
// into a create that leaves the old row behind. So the old row is resolved by list first.
//
// See Create for why there is no context.Context parameter.
func (s *IdsecIdentityTenantSuffixesService) Update(arg *tenantsuffixesmodels.IdsecIdentityUpdateTenantSuffix) (*tenantsuffixesmodels.IdsecIdentityTenantSuffix, error) {
	key := strings.TrimSpace(arg.ID)
	if key == "" {
		return nil, fmt.Errorf("id of the suffix to rename must be provided")
	}
	suffix := strings.TrimSpace(arg.ReplaceDomain)
	if suffix == "" {
		return nil, fmt.Errorf("suffix must be provided")
	}
	s.Logger.Debug("Renaming identity tenant suffix [%s] to [%s]", key, suffix)

	rows, err := s.listRows("update", listTenantSuffixURL)
	if err != nil {
		return nil, err
	}
	old, found := findRowByKey(rows, key)
	if !found {
		return nil, fmt.Errorf("identity tenant suffix [%s] not found: %w", key, common.ErrNotFound)
	}
	if old.id == nil || *old.id == "" {
		return nil, fmt.Errorf("identity tenant suffix [%s] has no row key to rename by", key)
	}
	if *old.replaceDomain == suffix {
		return toModel(old), nil
	}

	// A rename onto a suffix the tenant already has is refused by the server as a duplicate
	// (TenantAlias.cs:320-330), which checkStoreAliasResult reports as "already exists". An in-use
	// refusal (TenantAliasDomainChangeNotAllowedException, TenantAlias.cs:293-305) arrives as
	// success:false and is rejected by call.
	//
	// cdsAlias must be restated, because the rename stores the flag from this argument rather than
	// carrying it over from the old row (TenantAlias.cs:360, :449). The product's dialog sends the row's
	// own CdsAlias (NewSuffix.js:20), or false once the suffixless fix is on (NewSuffix.js:105, :211),
	// and so does this.
	raw, err := s.call("update", updateTenantSuffixURL, map[string]interface{}{
		wireAlias:    suffix,
		wireDomain:   suffix,
		wireOldName:  *old.id,
		wireCdsAlias: !suffixlessMode(rows) && old.cdsAlias,
	})
	if err != nil {
		return nil, err
	}
	if err := checkStoreAliasResult(raw, suffix); err != nil {
		return nil, err
	}

	// Confirm both halves of the rename rather than trusting State. The old row is deleted only if
	// every user was moved; a single failure leaves it in place and is only logged, while the call
	// still reports OK (TenantAlias.cs:801-816). Either shortfall is a partial success: the new row
	// may already exist, so it is what Terraform must track from here on.
	after, err := s.listRows("update", listTenantSuffixURL)
	if err != nil {
		return nil, common.NewPartialStateError(
			fmt.Errorf("identity tenant suffix [%s] was renamed to [%s] but could not be read back: %w", key, suffix, err),
			&tenantsuffixesmodels.IdsecIdentityTenantSuffix{ReplaceDomain: suffix})
	}
	renamed, found := findRow(after, suffix)
	if !found {
		return nil, common.NewPartialStateError(
			fmt.Errorf("identity tenant suffix [%s] was renamed to [%s] but the new suffix is not present", key, suffix),
			&tenantsuffixesmodels.IdsecIdentityTenantSuffix{ReplaceDomain: suffix})
	}
	// A case-only rename keeps the same row key, so the old key is expected to survive.
	if !strings.EqualFold(*old.id, derefOrEmpty(renamed.id)) {
		for _, row := range after {
			if row.id != nil && strings.EqualFold(*row.id, *old.id) {
				return nil, common.NewPartialStateError(
					fmt.Errorf("identity tenant suffix [%s] was renamed to [%s] but the old suffix is still present; "+
						"the server keeps it when a user on it could not be moved to the new suffix", key, suffix),
					toModel(renamed))
			}
		}
	}
	return toModel(renamed), nil
}

// derefOrEmpty returns the pointed-to string, or "" for nil.
func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// List returns every tenant suffix.
//
// See Create for why there is no context.Context parameter.
func (s *IdsecIdentityTenantSuffixesService) List() ([]*tenantsuffixesmodels.IdsecIdentityTenantSuffix, error) {
	s.Logger.Debug("Listing identity tenant suffixes")
	rows, err := s.listRows("list", listTenantSuffixURL)
	if err != nil {
		return nil, err
	}
	manageable := manageableRows(rows)
	suffixes := make([]*tenantsuffixesmodels.IdsecIdentityTenantSuffix, 0, len(manageable))
	for _, row := range manageable {
		suffixes = append(suffixes, toModel(row))
	}
	return suffixes, nil
}

// ListBy returns the tenant suffixes matching the supplied filters.
//
// See Create for why there is no context.Context parameter.
func (s *IdsecIdentityTenantSuffixesService) ListBy(arg *tenantsuffixesmodels.IdsecIdentityTenantSuffixFilters) ([]*tenantsuffixesmodels.IdsecIdentityTenantSuffix, error) {
	s.Logger.Debug("Listing identity tenant suffixes by filters")
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	if arg == nil || strings.TrimSpace(arg.ReplaceDomain) == "" {
		return all, nil
	}
	// Case-insensitively, for the reason findRow gives: one suffix is one row regardless of spelling.
	filter := strings.TrimSpace(arg.ReplaceDomain)
	filtered := make([]*tenantsuffixesmodels.IdsecIdentityTenantSuffix, 0, len(all))
	for _, suffix := range all {
		if strings.EqualFold(suffix.ReplaceDomain, filter) {
			filtered = append(filtered, suffix)
		}
	}
	return filtered, nil
}

// Get returns a single tenant suffix.
//
// There is no read-one endpoint, so the read lists and filters, and "not found" is synthesised here.
//
// See Create for why there is no context.Context parameter.
func (s *IdsecIdentityTenantSuffixesService) Get(arg *tenantsuffixesmodels.IdsecIdentityGetTenantSuffix) (*tenantsuffixesmodels.IdsecIdentityTenantSuffix, error) {
	key := strings.TrimSpace(arg.ID)
	suffix := strings.TrimSpace(arg.ReplaceDomain)
	if key == "" && suffix == "" {
		return nil, fmt.Errorf("id or suffix must be provided")
	}
	s.Logger.Debug("Retrieving identity tenant suffix [id=%s suffix=%s]", key, suffix)
	rows, err := s.listRows("get", readTenantSuffixURL)
	if err != nil {
		return nil, err
	}
	// The id is Terraform's handle and the only thing an import sets, so it is tried first. The suffix
	// is the fallback for a lookup that has no id: the data source, and the state a partial create
	// leaves behind.
	var row suffixRow
	found := false
	if key != "" {
		row, found = findRowByKey(rows, key)
	}
	if !found && suffix != "" {
		row, found = findRow(rows, suffix)
	}
	if !found {
		if suffix == "" {
			suffix = key
		}
		// Wraps common.ErrNotFound so the provider's Read removes the resource from state and the next
		// plan schedules a recreate, instead of every plan failing on a suffix deleted outside Terraform.
		return nil, fmt.Errorf("identity tenant suffix [%s] not found: %w", suffix, common.ErrNotFound)
	}
	// The STORED spelling is returned, not the caller's. ReplaceDomain is written verbatim -- the
	// store sets it from the raw domain argument (TenantAlias.cs:359, :448, :614) while sanitizing
	// only the separate row key -- so no case echo is needed here, and returning the stored value is
	// what lets a suffix that drifted on the server show up as a diff instead of being masked by the
	// request. Case-only differences are absorbed on the provider side by the resource's
	// SemanticEqualityCaseInsensitive entry, which is registered runsBeforeImmutability.
	return toModel(row), nil
}

// ServiceConfig returns the service configuration for the IdsecIdentityTenantSuffixesService.
//
// Required, not optional: services.IdsecService includes ServiceConfig(), and the constructor
// assigns the service to that interface, so omitting this does not compile. The returned value is
// the package-level var from the service_config file.
func (s *IdsecIdentityTenantSuffixesService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
