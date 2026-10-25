//go:build (e2e && identity) || e2e

// Package identity contains the end-to-end tests for the IDSEC Identity services.
package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // The server identifies a certificate by its SHA-1 thumbprint.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity/federations"
	federationsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/federations/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

const (
	// e2eOIDCMetadataURL is a public discovery document the tenant can fetch.
	e2eOIDCMetadataURL = "https://accounts.google.com/.well-known/openid-configuration"
	// e2eSAMLMetadataURL is a public SAML identity provider metadata document the tenant can fetch.
	e2eSAMLMetadataURL = "https://mocksaml.com/api/saml/metadata"
	// e2eFederatedGroup is the group the mapping tests map to. The server creates it on first use
	// and there is no API to delete it, so a fixed name keeps reruns from leaving a new group each.
	e2eFederatedGroup = "e2e-federation-group"
	// e2eCloudDirectory is the CyberArk Cloud Directory, the only directory attribute mappings apply to.
	e2eCloudDirectory = "09B9A9B0-6CE8-465F-AB03-65766D33B05E"
)

// e2eCertificate is a self-signed identity provider signing certificate. Each test makes its own:
// two SAML federations on a tenant cannot share one.
type e2eCertificate struct {
	pem        string
	base64DER  string
	thumbprint string
}

func newE2ECertificate(t *testing.T, commonName string) e2eCertificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	thumbprint := sha1.Sum(der) //nolint:gosec // See the import.
	return e2eCertificate{
		pem:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		base64DER:  base64.StdEncoding.EncodeToString(der),
		thumbprint: strings.ToUpper(hex.EncodeToString(thumbprint[:])),
	}
}

// e2eSAMLMetadata returns an identity provider metadata document for host, signed by cert.
func e2eSAMLMetadata(host string, cert e2eCertificate) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://%[1]s/entity">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>%[2]s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://%[1]s/slo"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://%[1]s/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
`, host, cert.base64DER)
}

func federationsService(t *testing.T, ctx *framework.TestContext) *federations.IdsecIdentityFederationsService {
	t.Helper()
	svc, err := ctx.API.IdentityFederations()
	require.NoError(t, err, "Failed to get Identity Federations service")
	return svc
}

// trackFederation registers the federation for cleanup. Delete treats a federation that is
// already gone as deleted, so the cleanup is safe after the test deletes it itself.
func trackFederation(t *testing.T, ctx *framework.TestContext, svc *federations.IdsecIdentityFederationsService, federation *federationsmodels.IdsecIdentityFederation) {
	t.Helper()
	ctx.TrackResourceByType("IdentityFederation", federation.FederationUUID, func() error {
		t.Logf("Cleaning up federation: %s (%s)", federation.FederationName, federation.FederationUUID)
		return svc.Delete(&federationsmodels.IdsecIdentityDeleteFederation{FederationUUID: federation.FederationUUID})
	})
}

func requireFederationDeleted(t *testing.T, svc *federations.IdsecIdentityFederationsService, federationID string) {
	t.Helper()
	require.NoError(t, svc.Delete(&federationsmodels.IdsecIdentityDeleteFederation{FederationUUID: federationID}), "Delete federation failed")
	// GetFederation keeps returning a deleted federation for a few seconds.
	err := framework.WaitForCondition(time.Minute, 3*time.Second, func() (bool, error) {
		_, err := svc.Get(&federationsmodels.IdsecIdentityGetFederation{FederationUUID: federationID})
		if errors.Is(err, common.ErrNotFound) {
			return true, nil
		}
		return false, err
	})
	require.NoError(t, err, "Get should report not found after delete")
	require.NoError(t, svc.Delete(&federationsmodels.IdsecIdentityDeleteFederation{FederationUUID: federationID}), "Deleting a deleted federation should succeed")
}

func listedFederation(t *testing.T, svc *federations.IdsecIdentityFederationsService, name string) *federationsmodels.IdsecIdentityFederation {
	t.Helper()
	listed, err := svc.ListBy(&federationsmodels.IdsecIdentityFederationFilters{FederationName: name})
	require.NoError(t, err, "ListBy failed")
	for i := range listed {
		if listed[i].FederationName == name {
			return &listed[i]
		}
	}
	return nil
}

// TestIdentityFederationsOIDCLifecycle creates, reads, lists, updates and deletes an OIDC
// federation, including the user, group and attribute mappings and the routing rules.
func TestIdentityFederationsOIDCLifecycle(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Identity OIDC Federation Lifecycle")
		svc := federationsService(t, ctx)

		name := framework.RandomResourceName("e2e-fed-oidc")
		domain := name + ".example.com"
		secret := "e2e-not-a-real-secret"
		t.Logf("Creating OIDC federation: %s", name)
		created, err := svc.Create(&federationsmodels.IdsecIdentityCreateFederation{
			FederationName:   name,
			FederationType:   "OIDC",
			Active:           true,
			Domains:          []string{domain},
			OIDCMetadataURL:  e2eOIDCMetadataURL,
			OIDCClientID:     "e2e-client",
			OIDCClientSecret: &secret,
			OIDCScopes:       []string{"openid", "profile", "email"},
			GroupMappings:    []federationsmodels.IdsecIdentityFederationGroupMapping{{AttributeValue: name + "-admins", GroupName: e2eFederatedGroup}},
		})
		require.NoError(t, err, "Create OIDC federation failed")
		require.NotNil(t, created)
		require.NotEmpty(t, created.FederationUUID)
		trackFederation(t, ctx, svc, created)

		assert.Equal(t, name, created.FederationName)
		assert.Equal(t, "OIDC", created.FederationType)
		assert.True(t, created.Active)
		assert.ElementsMatch(t, []string{domain}, created.Domains)
		assert.Equal(t, e2eOIDCMetadataURL, created.OIDCMetadataURL)
		assert.Equal(t, "e2e-client", created.OIDCClientID)
		assert.ElementsMatch(t, []string{"openid", "profile", "email"}, created.OIDCScopes)
		assert.NotEmpty(t, created.OIDCGrantType, "the server defaults the grant type")
		assert.NotEmpty(t, created.SPRedirectURL, "the redirect URL is derived by the server")
		assert.NotEmpty(t, created.SPInitiateLoginURL, "the initiate login URL is derived by the server")
		assert.Equal(t, []federationsmodels.IdsecIdentityFederationGroupMapping{{AttributeValue: name + "-admins", GroupName: e2eFederatedGroup}}, created.GroupMappings)

		t.Log("Get federation...")
		fetched, err := svc.Get(&federationsmodels.IdsecIdentityGetFederation{FederationUUID: created.FederationUUID})
		require.NoError(t, err, "Get federation failed")
		assert.Equal(t, created.FederationUUID, fetched.FederationUUID)
		assert.Equal(t, created.SPRedirectURL, fetched.SPRedirectURL)
		assert.Equal(t, created.GroupMappings, fetched.GroupMappings)

		t.Log("ListBy name...")
		listed := listedFederation(t, svc, name)
		require.NotNil(t, listed, "created federation should be listed")
		assert.Equal(t, created.FederationUUID, listed.FederationUUID)

		t.Log("Update: rename, deactivate, map users with attribute mappings, route browsers...")
		newName := name + "-renamed"
		createIfNotFound := true
		updated, err := svc.Update(&federationsmodels.IdsecIdentityUpdateFederation{
			FederationUUID:          created.FederationUUID,
			FederationName:          newName,
			Active:                  false,
			MapUsers:                "Required",
			MapUserAttribute:        "email",
			MapUserDirectoryService: e2eCloudDirectory,
			MapUserCreateIfNotFound: &createIfNotFound,
			AttributeMappings:       &[]federationsmodels.IdsecIdentityFederationAttributeMapping{{Target: "DisplayName", Source: "name"}},
			UserAgents:              &[]string{"Browser"},
		})
		require.NoError(t, err, "Update federation failed")
		assert.Equal(t, newName, updated.FederationName)
		assert.False(t, updated.Active)
		assert.Equal(t, "Required", updated.MapUsers)
		assert.Equal(t, "email", updated.MapUserAttribute)
		assert.True(t, updated.MapUserCreateIfNotFound)
		// The server drops attribute mappings without an error when the tenant turns off the
		// Core.ExternalIdpAttributeMapping.Enable flag (tenant config IsExternalIdpAttributeMapping).
		// It is on by default; the unit tests cover what the SDK sends either way.
		if len(updated.AttributeMappings) == 0 {
			t.Log("The tenant does not keep attribute mappings: IsExternalIdpAttributeMapping is off, so they are not checked")
		} else {
			assert.Equal(t, []federationsmodels.IdsecIdentityFederationAttributeMapping{{Target: "DisplayName", Source: "name"}}, updated.AttributeMappings)
		}
		assert.Equal(t, []string{"Browser"}, updated.UserAgents)

		t.Log("Update kept what it did not set...")
		assert.ElementsMatch(t, []string{domain}, updated.Domains)
		assert.Equal(t, e2eOIDCMetadataURL, updated.OIDCMetadataURL)
		assert.Equal(t, "e2e-client", updated.OIDCClientID)
		assert.ElementsMatch(t, []string{"openid", "profile", "email"}, updated.OIDCScopes)
		assert.Equal(t, created.GroupMappings, updated.GroupMappings)

		t.Log("Update: clear the group and attribute mappings...")
		cleared, err := svc.Update(&federationsmodels.IdsecIdentityUpdateFederation{
			FederationUUID:    created.FederationUUID,
			FederationName:    newName,
			GroupMappings:     &[]federationsmodels.IdsecIdentityFederationGroupMapping{},
			AttributeMappings: &[]federationsmodels.IdsecIdentityFederationAttributeMapping{},
		})
		require.NoError(t, err, "Clearing the mappings failed")
		assert.Empty(t, cleared.GroupMappings)
		assert.Empty(t, cleared.AttributeMappings)
		assert.Equal(t, "Required", cleared.MapUsers)

		t.Log("Changing the federation type is rejected...")
		_, err = svc.Update(&federationsmodels.IdsecIdentityUpdateFederation{
			FederationUUID: created.FederationUUID,
			FederationName: newName,
			FederationType: "SAML 2.0",
		})
		require.Error(t, err, "Changing the federation type should fail")

		t.Log("Delete federation...")
		requireFederationDeleted(t, svc, created.FederationUUID)
		t.Log("OIDC lifecycle completed successfully")
	}, federations.ServiceConfig)
}

// TestIdentityFederationsSAMLLifecycle creates a SAML 2.0 federation from each kind of identity
// provider configuration (manual, metadata document and metadata URL) and moves between them on
// update.
func TestIdentityFederationsSAMLLifecycle(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Identity SAML 2.0 Federation Lifecycle")
		svc := federationsService(t, ctx)

		name := framework.RandomResourceName("e2e-fed-saml")
		domain := name + ".example.com"
		manualCert := newE2ECertificate(t, name+"-manual")
		t.Logf("Creating manually configured SAML federation: %s", name)
		created, err := svc.Create(&federationsmodels.IdsecIdentityCreateFederation{
			FederationName:         name,
			FederationType:         "SAML 2.0",
			Active:                 true,
			Domains:                []string{domain},
			SAMLSignInURL:          "https://manual." + domain + "/sso",
			SAMLLogoutURL:          "https://manual." + domain + "/slo",
			SAMLSigningCertificate: &manualCert.pem,
		})
		require.NoError(t, err, "Create SAML federation failed")
		require.NotNil(t, created)
		require.NotEmpty(t, created.FederationUUID)
		trackFederation(t, ctx, svc, created)

		assert.Equal(t, "SAML 2.0", created.FederationType)
		assert.Equal(t, "https://manual."+domain+"/sso", created.SAMLSignInURL)
		assert.Equal(t, "https://manual."+domain+"/slo", created.SAMLLogoutURL)
		assert.Empty(t, created.SAMLMetadataURL)
		assert.Equal(t, "SHA256", created.SAMLSignAlgorithm, "the SDK defaults the signing algorithm")
		assert.Equal(t, manualCert.thumbprint, strings.ToUpper(created.SAMLCertificateThumbprint))
		assert.Contains(t, created.SAMLCertificateSubject, name+"-manual")
		assert.NotEmpty(t, created.SAMLCertificateExpires)
		assert.NotEmpty(t, created.SAMLSPMetadataURL, "the service provider metadata URL is derived by the server")
		assert.NotEmpty(t, created.SAMLSPACSURL, "the ACS URL is derived by the server")
		assert.NotEmpty(t, created.SAMLSPSigningCertificateURL, "the signing certificate URL is derived by the server")

		t.Log("Update without a certificate keeps the stored one...")
		enabled := true
		kept, err := svc.Update(&federationsmodels.IdsecIdentityUpdateFederation{
			FederationUUID:         created.FederationUUID,
			FederationName:         name,
			Active:                 true,
			SAMLSignInURL:          "https://manual." + domain + "/sso2",
			SAMLSignAlgorithm:      "SHA1",
			SAMLURLRedirectEnabled: &enabled,
			SAMLURLRedirectPattern: "https://app*.example.com/*",
		})
		require.NoError(t, err, "Manual update failed")
		assert.Equal(t, "https://manual."+domain+"/sso2", kept.SAMLSignInURL)
		assert.Equal(t, "SHA1", kept.SAMLSignAlgorithm)
		assert.True(t, kept.SAMLURLRedirectEnabled)
		assert.Equal(t, "https://app*.example.com/*", kept.SAMLURLRedirectPattern)
		assert.Equal(t, manualCert.thumbprint, strings.ToUpper(kept.SAMLCertificateThumbprint))

		t.Log("Update to a metadata document...")
		xmlCert := newE2ECertificate(t, name+"-xml")
		xmlHost := "xml." + domain
		metadata := e2eSAMLMetadata(xmlHost, xmlCert)
		fromXML, err := svc.Update(&federationsmodels.IdsecIdentityUpdateFederation{
			FederationUUID:  created.FederationUUID,
			FederationName:  name,
			Active:          true,
			SAMLMetadataXML: &metadata,
		})
		require.NoError(t, err, "Update to a metadata document failed")
		assert.Equal(t, "https://"+xmlHost+"/sso", fromXML.SAMLSignInURL, "the sign-in URL is read from the document")
		assert.Equal(t, "https://"+xmlHost+"/slo", fromXML.SAMLLogoutURL, "the logout URL is read from the document")
		assert.Equal(t, xmlCert.thumbprint, strings.ToUpper(fromXML.SAMLCertificateThumbprint))
		assert.Empty(t, fromXML.SAMLMetadataURL)
		assert.Equal(t, "SHA1", fromXML.SAMLSignAlgorithm, "fields not set are kept")
		assert.Equal(t, "https://app*.example.com/*", fromXML.SAMLURLRedirectPattern, "fields not set are kept")

		t.Log("Update a document-created federation without a document keeps its certificate...")
		renamed, err := svc.Update(&federationsmodels.IdsecIdentityUpdateFederation{
			FederationUUID: created.FederationUUID,
			FederationName: name + "-renamed",
			Active:         true,
		})
		require.NoError(t, err, "Rename failed")
		assert.Equal(t, name+"-renamed", renamed.FederationName)
		assert.Equal(t, xmlCert.thumbprint, strings.ToUpper(renamed.SAMLCertificateThumbprint))
		assert.Equal(t, "https://"+xmlHost+"/sso", renamed.SAMLSignInURL)

		t.Log("Update to a metadata URL...")
		fromURL, err := svc.Update(&federationsmodels.IdsecIdentityUpdateFederation{
			FederationUUID:  created.FederationUUID,
			FederationName:  name + "-renamed",
			Active:          true,
			SAMLMetadataURL: e2eSAMLMetadataURL,
		})
		require.NoError(t, err, "Update to a metadata URL failed")
		assert.Equal(t, e2eSAMLMetadataURL, fromURL.SAMLMetadataURL)
		assert.NotEmpty(t, fromURL.SAMLCertificateThumbprint)
		assert.NotEqual(t, xmlCert.thumbprint, strings.ToUpper(fromURL.SAMLCertificateThumbprint), "the certificate is read from the URL")

		t.Log("Update without metadata refetches the stored URL...")
		refetched, err := svc.Update(&federationsmodels.IdsecIdentityUpdateFederation{
			FederationUUID: created.FederationUUID,
			FederationName: name + "-renamed",
			Active:         false,
		})
		require.NoError(t, err, "Update after a metadata URL failed")
		assert.False(t, refetched.Active)
		assert.Equal(t, e2eSAMLMetadataURL, refetched.SAMLMetadataURL)
		assert.Equal(t, fromURL.SAMLCertificateThumbprint, refetched.SAMLCertificateThumbprint)

		t.Log("Delete federation...")
		requireFederationDeleted(t, svc, created.FederationUUID)
		t.Log("SAML lifecycle completed successfully")
	}, federations.ServiceConfig)
}

// TestIdentityFederationsSAMLFromMetadata creates SAML 2.0 federations from a metadata document and
// from a metadata URL.
func TestIdentityFederationsSAMLFromMetadata(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Identity SAML 2.0 Federation From Metadata")
		svc := federationsService(t, ctx)

		name := framework.RandomResourceName("e2e-fed-samlxml")
		cert := newE2ECertificate(t, name)
		host := "idp." + name + ".example.com"
		metadata := e2eSAMLMetadata(host, cert)
		t.Logf("Creating SAML federation from a metadata document: %s", name)
		fromXML, err := svc.Create(&federationsmodels.IdsecIdentityCreateFederation{
			FederationName:  name,
			FederationType:  "SAML 2.0",
			Active:          true,
			Domains:         []string{name + ".example.com"},
			SAMLMetadataXML: &metadata,
		})
		require.NoError(t, err, "Create from a metadata document failed")
		trackFederation(t, ctx, svc, fromXML)
		assert.Equal(t, "https://"+host+"/sso", fromXML.SAMLSignInURL)
		assert.Equal(t, "https://"+host+"/slo", fromXML.SAMLLogoutURL)
		assert.Equal(t, cert.thumbprint, strings.ToUpper(fromXML.SAMLCertificateThumbprint))

		t.Log("A second federation with the same certificate is rejected...")
		duplicateName := name + "-dup"
		duplicate, err := svc.Create(&federationsmodels.IdsecIdentityCreateFederation{
			FederationName:  duplicateName,
			FederationType:  "SAML 2.0",
			Active:          true,
			Domains:         []string{duplicateName + ".example.com"},
			SAMLMetadataXML: &metadata,
		})
		if duplicate != nil {
			trackFederation(t, ctx, svc, duplicate)
		}
		require.Error(t, err, "Two federations should not share a signing certificate")

		urlName := framework.RandomResourceName("e2e-fed-samlurl")
		t.Logf("Creating SAML federation from a metadata URL: %s", urlName)
		fromURL, err := svc.Create(&federationsmodels.IdsecIdentityCreateFederation{
			FederationName:  urlName,
			FederationType:  "SAML 2.0",
			Active:          true,
			Domains:         []string{urlName + ".example.com"},
			SAMLMetadataURL: e2eSAMLMetadataURL,
		})
		require.NoError(t, err, "Create from a metadata URL failed")
		trackFederation(t, ctx, svc, fromURL)
		assert.Equal(t, e2eSAMLMetadataURL, fromURL.SAMLMetadataURL)
		assert.NotEmpty(t, fromURL.SAMLSignInURL, "the sign-in URL is read from the metadata")
		assert.NotEmpty(t, fromURL.SAMLCertificateThumbprint, "the certificate is read from the metadata")

		t.Log("Both are listed with their type...")
		for _, federation := range []*federationsmodels.IdsecIdentityFederation{fromXML, fromURL} {
			listed := listedFederation(t, svc, federation.FederationName)
			require.NotNil(t, listed, "%s should be listed", federation.FederationName)
			assert.Equal(t, "SAML 2.0", listed.FederationType)
		}

		requireFederationDeleted(t, svc, fromXML.FederationUUID)
		requireFederationDeleted(t, svc, fromURL.FederationUUID)
		t.Log("SAML metadata federations completed successfully")
	}, federations.ServiceConfig)
}

// TestIdentityFederationsGlobalGroupMappingLifecycle adds, reads and removes a group mapping that
// applies to every federation.
func TestIdentityFederationsGlobalGroupMappingLifecycle(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: Identity Federation Global Group Mapping Lifecycle")
		svc := federationsService(t, ctx)

		attributeValue := framework.RandomResourceName("e2e-fed-global")
		t.Logf("Adding global group mapping: %s -> %s", attributeValue, e2eFederatedGroup)
		added, err := svc.AddGlobalGroupMapping(&federationsmodels.IdsecIdentityAddFederationGlobalGroupMapping{
			AttributeValue: attributeValue,
			GroupName:      e2eFederatedGroup,
		})
		require.NoError(t, err, "AddGlobalGroupMapping failed")
		ctx.TrackResourceByType("IdentityFederationGlobalGroupMapping", attributeValue, func() error {
			t.Logf("Cleaning up global group mapping: %s -> %s", attributeValue, e2eFederatedGroup)
			return svc.RemoveGlobalGroupMapping(&federationsmodels.IdsecIdentityRemoveFederationGlobalGroupMapping{
				AttributeValue: attributeValue,
				GroupName:      e2eFederatedGroup,
			})
		})
		assert.Equal(t, attributeValue, added.AttributeValue)
		assert.Equal(t, e2eFederatedGroup, added.GroupName)

		t.Log("Get matches without regard to case...")
		fetched, err := svc.GetGlobalGroupMapping(&federationsmodels.IdsecIdentityGetFederationGlobalGroupMapping{
			AttributeValue: strings.ToUpper(attributeValue),
			GroupName:      strings.ToUpper(e2eFederatedGroup),
		})
		require.NoError(t, err, "GetGlobalGroupMapping failed")
		assert.Equal(t, attributeValue, fetched.AttributeValue, "the stored spelling is returned")

		t.Log("List includes the mapping...")
		mappings, err := svc.ListGlobalGroupMappings()
		require.NoError(t, err, "ListGlobalGroupMappings failed")
		assert.Contains(t, mappings, federationsmodels.IdsecIdentityFederationGlobalGroupMapping{AttributeValue: attributeValue, GroupName: e2eFederatedGroup})

		t.Log("Adding the same mapping again is rejected...")
		_, err = svc.AddGlobalGroupMapping(&federationsmodels.IdsecIdentityAddFederationGlobalGroupMapping{
			AttributeValue: attributeValue,
			GroupName:      e2eFederatedGroup,
		})
		require.Error(t, err, "Adding an existing mapping should fail")
		assert.Contains(t, err.Error(), "already exists")

		t.Log("Remove the mapping...")
		require.NoError(t, svc.RemoveGlobalGroupMapping(&federationsmodels.IdsecIdentityRemoveFederationGlobalGroupMapping{
			AttributeValue: attributeValue,
			GroupName:      e2eFederatedGroup,
		}), "RemoveGlobalGroupMapping failed")
		_, err = svc.GetGlobalGroupMapping(&federationsmodels.IdsecIdentityGetFederationGlobalGroupMapping{
			AttributeValue: attributeValue,
			GroupName:      e2eFederatedGroup,
		})
		require.True(t, errors.Is(err, common.ErrNotFound), "Get should report not found after remove, got %v", err)
		require.NoError(t, svc.RemoveGlobalGroupMapping(&federationsmodels.IdsecIdentityRemoveFederationGlobalGroupMapping{
			AttributeValue: attributeValue,
			GroupName:      e2eFederatedGroup,
		}), "Removing a removed mapping should succeed")

		t.Log("Global group mapping lifecycle completed successfully")
	}, federations.ServiceConfig)
}
