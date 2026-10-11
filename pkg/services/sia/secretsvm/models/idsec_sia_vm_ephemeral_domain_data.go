package models

import (
	"fmt"
	"strings"
)

// EphemeralDomainUserParams holds the parameters for ephemeral domain user creation validation.
type EphemeralDomainUserParams struct {
	DomainControllerName                        string
	DomainControllerNetbios                     string
	DomainControllerAutomaticDiscovery          bool
	EphemeralDomainUserLocation                 string
	DomainControllerUseLdaps                    bool
	DomainControllerEnableCertificateValidation bool
	DomainControllerLdapsCertificate            string
	DomainControllerLdapsLoadAllCertificates    bool
	UseWinrmForHTTPS                            bool
	WinrmEnableCertificateValidation            bool
	WinrmCertificate                            string
	WinrmLoadAllCertificates                    bool
}

// BuildEphemeralDomainUserDataMap builds the ephemeral_domain_user_data map from EphemeralDomainUserParams.
// This is used by both AddSecret and ChangeSecret when ephemeral domain user creation is enabled.
func BuildEphemeralDomainUserDataMap(params EphemeralDomainUserParams) map[string]interface{} {
	return map[string]interface{}{
		"domain_controller": map[string]interface{}{
			"domain_controller_name":                          params.DomainControllerName,
			"domain_controller_netbios":                       params.DomainControllerNetbios,
			"domain_controller_automatic_discovery":           params.DomainControllerAutomaticDiscovery,
			"domain_controller_use_ldaps":                     params.DomainControllerUseLdaps,
			"domain_controller_enable_certificate_validation": params.DomainControllerEnableCertificateValidation,
			"domain_controller_ldaps_certificate":             params.DomainControllerLdapsCertificate,
			"domain_controller_ldaps_load_all_certificates":   params.DomainControllerLdapsLoadAllCertificates,
		},
		"ephemeral_domain_user_location": params.EphemeralDomainUserLocation,
		"winrm_info": map[string]interface{}{
			"use_winrm_for_https":                 params.UseWinrmForHTTPS,
			"winrm_enable_certificate_validation": params.WinrmEnableCertificateValidation,
			"winrm_certificate":                   params.WinrmCertificate,
			"winrm_load_all_certificates":         params.WinrmLoadAllCertificates,
		},
	}
}

// ValidateEphemeralDomainUserParams validates the ephemeral domain user creation parameters.
// This validates the interdependencies between ephemeral domain user fields.
// Returns an error if validation fails, nil otherwise.
func ValidateEphemeralDomainUserParams(params EphemeralDomainUserParams) error {
	// DomainControllerEnableCertificateValidation requires DomainControllerUseLdaps and exactly one of
	// DomainControllerLdapsCertificate or DomainControllerLdapsLoadAllCertificates
	if params.DomainControllerEnableCertificateValidation {
		if !params.DomainControllerUseLdaps {
			return fmt.Errorf("domain-controller-enable-certificate-validation requires domain-controller-use-ldaps to be true")
		}
		if params.DomainControllerLdapsCertificate == "" && !params.DomainControllerLdapsLoadAllCertificates {
			return fmt.Errorf("domain-controller-enable-certificate-validation requires domain-controller-ldaps-certificate or domain-controller-ldaps-load-all-certificates to be provided")
		}
		if params.DomainControllerLdapsCertificate != "" && params.DomainControllerLdapsLoadAllCertificates {
			return fmt.Errorf("domain-controller-ldaps-certificate and domain-controller-ldaps-load-all-certificates cannot be used together")
		}
	}

	// WinrmEnableCertificateValidation requires UseWinrmForHTTPS and exactly one of WinrmCertificate or WinrmLoadAllCertificates
	if params.WinrmEnableCertificateValidation {
		if !params.UseWinrmForHTTPS {
			return fmt.Errorf("winrm-enable-certificate-validation requires use-winrm-for-https to be true")
		}
		if params.WinrmCertificate == "" && !params.WinrmLoadAllCertificates {
			return fmt.Errorf("winrm-enable-certificate-validation requires winrm-certificate or winrm-load-all-certificates to be provided")
		}
		if params.WinrmCertificate != "" && params.WinrmLoadAllCertificates {
			return fmt.Errorf("winrm-certificate and winrm-load-all-certificates cannot be used together")
		}
	}

	return nil
}

// getBoolValue returns the value of a *bool pointer, or the default value if nil.
func getBoolValue(ptr *bool, defaultValue bool) bool {
	if ptr == nil {
		return defaultValue
	}
	return *ptr
}

// getStringFromMap returns user value if non-empty, otherwise existing value from map, otherwise empty.
func getStringFromMap(userValue string, existingMap map[string]interface{}, key string) string {
	if userValue != "" {
		return userValue
	}
	if existingMap != nil {
		if v, ok := existingMap[key].(string); ok {
			return v
		}
	}
	return ""
}

// getBoolPtrFromMap returns user value if non-nil, otherwise existing value from map, otherwise default.
func getBoolPtrFromMap(userPtr *bool, existingMap map[string]interface{}, key string, defaultVal bool) bool {
	if userPtr != nil {
		return *userPtr
	}
	if existingMap != nil {
		if v, ok := existingMap[key].(bool); ok {
			return v
		}
	}
	return defaultVal
}

// ExtractEphemeralParamsFromAddSecret extracts EphemeralDomainUserParams from IdsecSIAVMAddSecret.
// Applies default values: DomainControllerUseLdaps=true, UseWinrmForHTTPS=true.
// Other boolean fields default to false.
func ExtractEphemeralParamsFromAddSecret(addSecret *IdsecSIAVMAddSecret) EphemeralDomainUserParams {
	return EphemeralDomainUserParams{
		DomainControllerName:                        addSecret.DomainControllerName,
		DomainControllerNetbios:                     addSecret.DomainControllerNetbios,
		DomainControllerAutomaticDiscovery:          getBoolValue(addSecret.DomainControllerAutomaticDiscovery, false),
		EphemeralDomainUserLocation:                 addSecret.EphemeralDomainUserLocation,
		DomainControllerUseLdaps:                    getBoolValue(addSecret.DomainControllerUseLdaps, true),
		DomainControllerEnableCertificateValidation: getBoolValue(addSecret.DomainControllerEnableCertificateValidation, false),
		DomainControllerLdapsCertificate:            addSecret.DomainControllerLdapsCertificate,
		DomainControllerLdapsLoadAllCertificates:    getBoolValue(addSecret.DomainControllerLdapsLoadAllCertificates, false),
		UseWinrmForHTTPS:                            getBoolValue(addSecret.UseWinrmForHTTPS, true),
		WinrmEnableCertificateValidation:            getBoolValue(addSecret.WinrmEnableCertificateValidation, false),
		WinrmCertificate:                            addSecret.WinrmCertificate,
		WinrmLoadAllCertificates:                    getBoolValue(addSecret.WinrmLoadAllCertificates, false),
	}
}

// EphemeralDomainUserDataMapFromSecret builds the ephemeral_domain_user_data map from an IdsecSIAVMSecret.
// Used when merging existing secret state (e.g. in ChangeSecret) after secret_details has been flattened.
func EphemeralDomainUserDataMapFromSecret(secret *IdsecSIAVMSecret) map[string]interface{} {
	if secret == nil || secret.EnableEphemeralDomainUserCreation == nil || !*secret.EnableEphemeralDomainUserCreation {
		return map[string]interface{}{}
	}
	params := EphemeralDomainUserParams{
		DomainControllerName:                        secret.DomainControllerName,
		DomainControllerNetbios:                     secret.DomainControllerNetbios,
		DomainControllerAutomaticDiscovery:          getBoolValue(secret.DomainControllerAutomaticDiscovery, false),
		EphemeralDomainUserLocation:                 secret.EphemeralDomainUserLocation,
		DomainControllerUseLdaps:                    getBoolValue(secret.DomainControllerUseLdaps, true),
		DomainControllerEnableCertificateValidation: getBoolValue(secret.DomainControllerEnableCertificateValidation, false),
		DomainControllerLdapsCertificate:            secret.DomainControllerLdapsCertificate,
		DomainControllerLdapsLoadAllCertificates:    getBoolValue(secret.DomainControllerLdapsLoadAllCertificates, false),
		UseWinrmForHTTPS:                            getBoolValue(secret.UseWinrmForHTTPS, true),
		WinrmEnableCertificateValidation:            getBoolValue(secret.WinrmEnableCertificateValidation, false),
		WinrmCertificate:                            secret.WinrmCertificate,
		WinrmLoadAllCertificates:                    getBoolValue(secret.WinrmLoadAllCertificates, false),
	}
	return BuildEphemeralDomainUserDataMap(params)
}

// ExtractEphemeralParamsFromChangeSecret extracts EphemeralDomainUserParams from IdsecSIAVMChangeSecret,
// merging with existing ephemeral data from the current secret.
// For each field: if user provided a value, use it; otherwise use existing value; otherwise use default.
// Defaults: DomainControllerUseLdaps=true, UseWinrmForHTTPS=true, and the rest of the fields are empty or false.
// Automatic discovery vs a named domain controller, and loading all certificates vs a single certificate, are
// mutually exclusive: see resolveMutuallyExclusiveFlag.
func ExtractEphemeralParamsFromChangeSecret(changeSecret *IdsecSIAVMChangeSecret, existingData map[string]interface{}) EphemeralDomainUserParams {
	// Extract nested maps from existing data
	var dcMap, winrmMap map[string]interface{}
	var existingLocation string

	if existingData != nil {
		dcMap, _ = existingData["domain_controller"].(map[string]interface{})
		winrmMap, _ = existingData["winrm_info"].(map[string]interface{})
		existingLocation, _ = existingData["ephemeral_domain_user_location"].(string)
	}

	// Build params using helper functions
	location := changeSecret.EphemeralDomainUserLocation
	if location == "" {
		location = existingLocation
	}

	dcName := getStringFromMap(changeSecret.DomainControllerName, dcMap, "domain_controller_name")
	dcNetbios := getStringFromMap(changeSecret.DomainControllerNetbios, dcMap, "domain_controller_netbios")
	automaticDiscovery := getBoolPtrFromMap(changeSecret.DomainControllerAutomaticDiscovery, dcMap, "domain_controller_automatic_discovery", false)
	dcNamed := strings.TrimSpace(changeSecret.DomainControllerName) != "" || strings.TrimSpace(changeSecret.DomainControllerNetbios) != ""
	automaticDiscovery = resolveMutuallyExclusiveFlag(changeSecret.DomainControllerAutomaticDiscovery, automaticDiscovery, dcNamed, &dcName, &dcNetbios)

	ldapsCertificate := getStringFromMap(changeSecret.DomainControllerLdapsCertificate, dcMap, "domain_controller_ldaps_certificate")
	ldapsLoadAll := getBoolPtrFromMap(changeSecret.DomainControllerLdapsLoadAllCertificates, dcMap, "domain_controller_ldaps_load_all_certificates", false)
	ldapsCertificateGiven := changeSecret.DomainControllerLdapsCertificate != ""
	ldapsLoadAll = resolveMutuallyExclusiveFlag(changeSecret.DomainControllerLdapsLoadAllCertificates, ldapsLoadAll, ldapsCertificateGiven, &ldapsCertificate)

	winrmCertificate := getStringFromMap(changeSecret.WinrmCertificate, winrmMap, "winrm_certificate")
	winrmLoadAll := getBoolPtrFromMap(changeSecret.WinrmLoadAllCertificates, winrmMap, "winrm_load_all_certificates", false)
	winrmCertificateGiven := changeSecret.WinrmCertificate != ""
	winrmLoadAll = resolveMutuallyExclusiveFlag(changeSecret.WinrmLoadAllCertificates, winrmLoadAll, winrmCertificateGiven, &winrmCertificate)

	return EphemeralDomainUserParams{
		DomainControllerName:                        dcName,
		DomainControllerNetbios:                     dcNetbios,
		DomainControllerAutomaticDiscovery:          automaticDiscovery,
		EphemeralDomainUserLocation:                 location,
		DomainControllerUseLdaps:                    getBoolPtrFromMap(changeSecret.DomainControllerUseLdaps, dcMap, "domain_controller_use_ldaps", true),
		DomainControllerEnableCertificateValidation: getBoolPtrFromMap(changeSecret.DomainControllerEnableCertificateValidation, dcMap, "domain_controller_enable_certificate_validation", false),
		DomainControllerLdapsCertificate:            ldapsCertificate,
		DomainControllerLdapsLoadAllCertificates:    ldapsLoadAll,
		UseWinrmForHTTPS:                            getBoolPtrFromMap(changeSecret.UseWinrmForHTTPS, winrmMap, "use_winrm_for_https", true),
		WinrmEnableCertificateValidation:            getBoolPtrFromMap(changeSecret.WinrmEnableCertificateValidation, winrmMap, "winrm_enable_certificate_validation", false),
		WinrmCertificate:                            winrmCertificate,
		WinrmLoadAllCertificates:                    winrmLoadAll,
	}
}

// resolveMutuallyExclusiveFlag merges a boolean setting with the values it conflicts with, returning the merged setting.
// flagFromRequest is the setting as sent in this change (nil when omitted), effectiveFlag is its value after merging
// with the stored state, and requestSetsValues reports whether this change sends any of the conflicting values.
// Setting one side in this change clears the other side's inherited state, and when neither side is set an inherited
// true wins over inherited values, as jit-ui does. A change that sets both is left intact to be rejected.
func resolveMutuallyExclusiveFlag(flagFromRequest *bool, effectiveFlag bool, requestSetsValues bool, conflictingValues ...*string) bool {
	if requestSetsValues && flagFromRequest == nil {
		return false
	}
	if effectiveFlag && !requestSetsValues {
		for _, value := range conflictingValues {
			*value = ""
		}
	}
	return effectiveFlag
}
