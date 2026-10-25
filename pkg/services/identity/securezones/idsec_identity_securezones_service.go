// Package securezones provides the SDK service for managing Identity Cloud secure zones
// (also referred to as on-premises detection ranges). It wraps the Core/UpdatePremDetectRange,
// Core/DeletePremDetectRange, Core/GetPremDetectRanges, Core/EnablePremDetectRange, and
// Core/DisablePremDetectRange endpoints on the CyberArk Identity Service Provider.
package securezones

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	identitycommon "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/common"
	securezonesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/securezones/models"
)

// Endpoint paths, relative to the api/idadmin base.
// Source: Core/Cloud/Controllers/CoreController.cs
const (
	createSecureZoneURL  = "Core/UpdatePremDetectRange"  // CoreController.cs line 4701 — uuid="" → create
	deleteSecureZoneURL  = "Core/DeletePremDetectRange"  // CoreController.cs line 4905
	disableSecureZoneURL = "Core/DisablePremDetectRange" // CoreController.cs line 4757 — sets status=inactive
	enableSecureZoneURL  = "Core/EnablePremDetectRange"  // CoreController.cs line 4772 — sets status=active
	listSecureZoneURL    = "Core/GetPremDetectRanges"    // CoreController.cs line 4581
	updateSecureZoneURL  = "Core/UpdatePremDetectRange"  // CoreController.cs line 4701 — uuid set → update
)

// IdsecIdentitySecureZonesService is the service for managing secure zone.
type IdsecIdentitySecureZonesService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService

	DoPost func(ctx context.Context, path string, body interface{}) (*http.Response, error)
}

// NewIdsecIdentitySecureZonesService creates a new instance of IdsecIdentitySecureZonesService.
func NewIdsecIdentitySecureZonesService(authenticators ...auth.IdsecAuth) (*IdsecIdentitySecureZonesService, error) {
	service := &IdsecIdentitySecureZonesService{}
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

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "", "", "api/idadmin", service.refreshIdentitySecureZonesAuth)
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

func (s *IdsecIdentitySecureZonesService) postOperation() func(ctx context.Context, path string, body interface{}) (*http.Response, error) {
	if s.DoPost != nil {
		return s.DoPost
	}
	return s.ISPClient().Post
}

func (s *IdsecIdentitySecureZonesService) refreshIdentitySecureZonesAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// ServiceConfig returns the service configuration for the IdsecIdentitySecureZonesService.
func (s *IdsecIdentitySecureZonesService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}

// parseSecureZoneFromMap converts a wire map into an IdsecIdentitySecureZone.
// Uses an explicit JSON round-trip with a local wire struct (same pattern as
// authprofiles.parseAuthProfileFromMap) because the server's key names
// ("ID", "Label", "Range", "Status") differ from the model's mapstructure tags
// ("secure_zone_id", "label", "ip_range", "status").
//
// Wire key sources (PremDetect.GetRangesQuery):
//
//	de.Set("ID",     range.Get(RangeFields.Uuid))    // CoreController.cs ~4993
//	de.Set("Label",  range.Get(RangeFields.Label))
//	de.Set("Range",  range.Get(RangeFields.Range))
//	de.Set("Status", range.Get(RangeFields.Status, "active"))
func (s *IdsecIdentitySecureZonesService) parseSecureZoneFromMap(data map[string]interface{}) (*securezonesmodels.IdsecIdentitySecureZone, error) {
	type secureZoneWire struct {
		ID     string `json:"ID"`     //nolint:tagliatelle
		Label  string `json:"Label"`  //nolint:tagliatelle
		Range  string `json:"Range"`  //nolint:tagliatelle
		Status string `json:"Status"` //nolint:tagliatelle
	}
	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("parse secure zone: marshal: %w", err)
	}
	var w secureZoneWire
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("parse secure zone: unmarshal: %w", err)
	}
	status := w.Status
	if status == "" {
		// Server defaults to "active" when the field is absent.
		// PremDetect.GetRangesQuery line 100: range.Get(RangeFields.Status, SECURE_ZONE_ACTIVE)
		status = "active"
	}
	return &securezonesmodels.IdsecIdentitySecureZone{
		ID:     w.ID,
		Label:  w.Label,
		Range:  w.Range,
		Status: status,
	}, nil
}

// readBody JSON-decodes an HTTP response body. The caller is responsible for closing resp.Body.
func readBody(resp *http.Response) (map[string]interface{}, error) {
	var envelope map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return envelope, nil
}

// checkSuccess validates the success field and returns a descriptive error.
func checkSuccess(envelope map[string]interface{}, op string) error {
	if success, _ := envelope["success"].(bool); !success {
		msg, _ := envelope["Message"].(string)
		if msg == "" {
			msg = fmt.Sprintf("%v", envelope)
		}
		return fmt.Errorf("failed to %s: API error: %s", op, msg)
	}
	return nil
}

// call performs a POST request, checks the HTTP status and API success flag, and returns
// the decoded response envelope. op is used verbatim in error messages, e.g.
// "list identity secure zones" → "failed to list identity secure zones: ...".
func (s *IdsecIdentitySecureZonesService) call(op, path string, body interface{}) (map[string]interface{}, error) {
	resp, err := s.postOperation()(context.Background(), path, body)
	if err != nil {
		s.Logger.Error("Error %s: %s", op, err.Error())
		return nil, fmt.Errorf("failed to %s: %w", op, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to %s: unexpected status %d", op, resp.StatusCode)
	}
	envelope, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if err := checkSuccess(envelope, op); err != nil {
		return nil, err
	}
	return envelope, nil
}

// List returns every secure zone visible to the tenant.
// Source: Core/GetPremDetectRanges → GetRangesQuery(PREM_RANGE_CONFIG, "ID").
func (s *IdsecIdentitySecureZonesService) List() ([]*securezonesmodels.IdsecIdentitySecureZone, error) {
	s.Logger.Debug("Listing secure zones")
	envelope, err := s.call("list identity secure zones", listSecureZoneURL, map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	result, _ := envelope["Result"].(map[string]interface{})
	resultsRaw, _ := result["Results"].([]interface{})

	var out []*securezonesmodels.IdsecIdentitySecureZone
	for _, rw := range resultsRaw {
		entry, ok := rw.(map[string]interface{})
		if !ok {
			continue // skip malformed row rather than panic
		}
		rowMap, ok := entry["Row"].(map[string]interface{})
		if !ok {
			continue // skip entries missing or with a non-map "Row"
		}
		zone, err := s.parseSecureZoneFromMap(rowMap)
		if err != nil {
			return nil, err
		}
		out = append(out, zone)
	}
	return out, nil
}

// ListBy filters the full list client-side by Label, Range, and/or Status.
// Any filter field left empty is ignored (not applied).
func (s *IdsecIdentitySecureZonesService) ListBy(filters *securezonesmodels.IdsecIdentitySecureZoneFilters) ([]*securezonesmodels.IdsecIdentitySecureZone, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	if filters == nil {
		return all, nil
	}
	var out []*securezonesmodels.IdsecIdentitySecureZone
	for _, z := range all {
		if filters.Label != "" && z.Label != filters.Label {
			continue
		}
		if filters.Range != "" && z.Range != filters.Range {
			continue
		}
		if filters.Status != "" && z.Status != filters.Status {
			continue
		}
		out = append(out, z)
	}
	return out, nil
}

// Get returns a single secure zone by ID, using list-and-filter.
// There is no read-one API endpoint; reads always go through GetPremDetectRanges.
// Source: spec — read endpoint omitted; CoreController.cs has no GetPremDetectRange(uuid) method.
func (s *IdsecIdentitySecureZonesService) Get(req *securezonesmodels.IdsecIdentityGetSecureZone) (*securezonesmodels.IdsecIdentitySecureZone, error) {
	s.Logger.Debug("Getting secure zone by ID [%s]", req.ID)
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	for _, z := range all {
		if z.ID == req.ID {
			return z, nil
		}
	}
	return nil, fmt.Errorf("secure zone %q not found: %w", req.ID, common.ErrNotFound)
}

// Create creates a new secure zone via Core/UpdatePremDetectRange with uuid="".
//
// Wire params (CoreController.cs line 4701 — UpdatePremDetectRange signature):
//
//	value  = IP range (called "Range" in storage; "value" on the wire)
//	label  = display name
//	uuid   = "" → server assigns a new UUID and returns it as Result string
//	action = "" (only "copy" is meaningful; skips duplicate-label check)
//
// Create response: Result is a bare string (the UUID), not a map.
// Source: CoreController.cs line 4706: AddOrModifyRange returns uuid string.
//
// Status: server always creates as "active" (PremDetect.cs line ~254).
// If caller wants "inactive", call Disable after create.
func (s *IdsecIdentitySecureZonesService) Create(req *securezonesmodels.IdsecIdentityCreateSecureZone) (*securezonesmodels.IdsecIdentitySecureZone, error) {
	s.Logger.Debug("Creating secure zone [%s]", req.Label)
	body := map[string]interface{}{
		"value":  req.Range, // CoreController.cs line 4701: param name is "value"
		"label":  req.Label, // CoreController.cs line 4701: param name is "label"
		"uuid":   "",        // empty → create path in AddOrModifyRange
		"action": "",
	}
	envelope, err := s.call("create identity secure zone", createSecureZoneURL, body)
	if err != nil {
		return nil, err
	}

	// Result is the UUID string, not a map.
	// CoreController.cs line 4706: return retVal (the uuid from AddOrModifyRange)
	uuid, ok := envelope["Result"].(string)
	if !ok || uuid == "" {
		return nil, fmt.Errorf("failed to create identity secure zone: expected UUID string in Result, got %T: %v", envelope["Result"], envelope["Result"])
	}

	// Server always creates zones as "active".
	// PremDetect.cs line ~254: newRange.Set(RangeFields.Status, SECURE_ZONE_ACTIVE)
	if req.Status == "inactive" {
		if err := s.disable(uuid); err != nil {
			// The zone was created successfully but could not be disabled. Return a
			// PartialStateError so the provider can persist the partial result to state
			// (matching the tenantsuffixes convention) rather than silently orphaning it.
			partial, _ := s.Get(&securezonesmodels.IdsecIdentityGetSecureZone{ID: uuid})
			if partial == nil {
				partial = &securezonesmodels.IdsecIdentitySecureZone{ID: uuid}
			}
			return nil, common.NewPartialStateError(
				fmt.Errorf("failed to create identity secure zone %q as inactive: disable failed: %w", uuid, err), partial)
		}
	}

	// Read back for canonical state (server may normalise the ip_range to lowercase).
	zone, err := s.Get(&securezonesmodels.IdsecIdentityGetSecureZone{ID: uuid})
	if err != nil {
		return nil, fmt.Errorf("failed to read back created identity secure zone %q: %w", uuid, err)
	}
	return zone, nil
}

// Update modifies label and/or ip_range, then reconciles status if changed.
//
// Wire params (CoreController.cs line 4701):
//
//	value  = new IP range
//	label  = new label
//	uuid   = existing zone UUID → update path in AddOrModifyRange (ModifyRange)
//
// ModifyRange preserves the existing status — it does NOT accept a new status.
// Source: PremDetect.cs line 371: newRange.Set(RangeFields.Status, match.Get(RangeFields.Status, SECURE_ZONE_ACTIVE))
// Status changes must go through Enable / Disable.
func (s *IdsecIdentitySecureZonesService) Update(req *securezonesmodels.IdsecIdentityUpdateSecureZone) (*securezonesmodels.IdsecIdentitySecureZone, error) {
	s.Logger.Debug("Updating secure zone [%s]", req.ID)

	// Read current state to detect status drift.
	existing, err := s.Get(&securezonesmodels.IdsecIdentityGetSecureZone{ID: req.ID})
	if err != nil {
		return nil, fmt.Errorf("failed to update identity secure zone: read before write: %w", err)
	}

	body := map[string]interface{}{
		"value":  req.Range, // CoreController.cs line 4701
		"label":  req.Label, // CoreController.cs line 4701
		"uuid":   req.ID,    // non-empty uuid → ModifyRange path
		"action": "",
	}
	if _, err = s.call("update identity secure zone", updateSecureZoneURL, body); err != nil {
		return nil, err
	}

	// Reconcile status if it changed. Status is NOT part of UpdatePremDetectRange;
	// requires separate Enable/Disable calls.
	// PremDetect.cs line 371 — ModifyRange preserves existing status.
	if req.Status != "" && req.Status != existing.Status {
		switch req.Status {
		case "active":
			if err := s.enable(req.ID); err != nil { // CoreController.cs line 4772
				// label/range already updated. Return a PartialStateError so the provider
				// can persist the partial result to state rather than silently orphaning it.
				partial, _ := s.Get(&securezonesmodels.IdsecIdentityGetSecureZone{ID: req.ID})
				if partial == nil {
					partial = &securezonesmodels.IdsecIdentitySecureZone{ID: req.ID}
				}
				return nil, common.NewPartialStateError(
					fmt.Errorf("failed to update identity secure zone: enable: %w", err), partial)
			}
		case "inactive":
			if err := s.disable(req.ID); err != nil { // CoreController.cs line 4757
				// label/range already updated. Return a PartialStateError so the provider
				// can persist the partial result to state rather than silently orphaning it.
				partial, _ := s.Get(&securezonesmodels.IdsecIdentityGetSecureZone{ID: req.ID})
				if partial == nil {
					partial = &securezonesmodels.IdsecIdentitySecureZone{ID: req.ID}
				}
				return nil, common.NewPartialStateError(
					fmt.Errorf("failed to update identity secure zone: disable: %w", err), partial)
			}
		}
	}

	zone, err := s.Get(&securezonesmodels.IdsecIdentityGetSecureZone{ID: req.ID})
	if err != nil {
		return nil, fmt.Errorf("failed to read back updated identity secure zone %q: %w", req.ID, err)
	}
	return zone, nil
}

// Delete removes a secure zone by UUID.
//
// Wire param (CoreController.cs line 4905 — DeletePremDetectRange):
//
//	uuid = zone UUID to delete
//
// Performs a preflight Get so that callers can distinguish "already gone" from a
// failed delete via errors.Is(err, common.ErrNotFound).
func (s *IdsecIdentitySecureZonesService) Delete(req *securezonesmodels.IdsecIdentityDeleteSecureZone) error {
	s.Logger.Debug("Deleting secure zone [%s]", req.ID)
	// Preflight get — wraps common.ErrNotFound so callers can tell "already gone"
	// from a failed delete, matching the tenantsuffixes.Delete convention.
	if _, err := s.Get(&securezonesmodels.IdsecIdentityGetSecureZone{ID: req.ID}); err != nil {
		return err
	}
	body := map[string]interface{}{
		"uuid": req.ID, // CoreController.cs line 4905: param name is "uuid"
	}
	_, err := s.call("delete identity secure zone", deleteSecureZoneURL, body)
	return err
}

// disable sets a secure zone's status to "inactive".
// Internal helper — called only by Create and Update; not part of the CLI/CRUD framework.
//
// Wire param (CoreController.cs line 4757 — DisablePremDetectRange):
//
//	uuid = zone UUID to disable
func (s *IdsecIdentitySecureZonesService) disable(uuid string) error {
	s.Logger.Debug("Disabling secure zone [%s]", uuid)
	body := map[string]interface{}{
		"uuid": uuid, // CoreController.cs line 4757: param name is "uuid"
	}
	_, err := s.call("disable identity secure zone", disableSecureZoneURL, body)
	return err
}

// enable sets a secure zone's status to "active".
// Internal helper — called only by Update; not part of the CLI/CRUD framework.
//
// Wire param (CoreController.cs line 4772 — EnablePremDetectRange):
//
//	uuid = zone UUID to enable
func (s *IdsecIdentitySecureZonesService) enable(uuid string) error {
	s.Logger.Debug("Enabling secure zone [%s]", uuid)
	body := map[string]interface{}{
		"uuid": uuid, // CoreController.cs line 4772: param name is "uuid"
	}
	_, err := s.call("enable identity secure zone", enableSecureZoneURL, body)
	return err
}
