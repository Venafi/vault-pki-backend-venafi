//go:build ngts
// +build ngts

package pki

import (
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/util"
)

// These tests exercise NGTS (Strata Cloud Manager) end-to-end and require a live tenant plus
// the NGTS_* environment variables (see docs/vault-pki-backend-venafi/NGTS Vault PKI Backend -
// Issuance Test Procedure.md). They are build-tagged `ngts` and do not run in normal CI — the
// same model as the TPP/VaaS suites. Run with: make test_ngts
//
// Both auth variants are covered: service account (venafiConfigNGTS) and a pre-issued bearer
// token (venafiConfigNGTSToken).

var ngtsConfigVariants = []venafiConfigString{venafiConfigNGTS, venafiConfigNGTSToken}

func TestNGTSissueReadRevoke(t *testing.T) {
	for _, cfg := range ngtsConfigVariants {
		cfg := cfg
		t.Run(string(cfg), func(t *testing.T) {
			integrationTestEnv, err := NewIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}

			data := testData{
				cn:        randSeq(9) + ".venafi.example.com",
				storeBy:   "serial",
				storePkey: true,
			}
			integrationTestEnv.writeVenafiToBackend(t, cfg)
			integrationTestEnv.writeRoleToBackendWithData(t, cfg, data)

			t.Run("issue", func(t *testing.T) {
				integrationTestEnv.IssueCertificateAndSaveSerial(t, data, cfg)
			})
			t.Run("read", func(t *testing.T) {
				ngtsReadCertificate(t, integrationTestEnv, util.NormalizeSerial(integrationTestEnv.CertificateSerial))
			})
			t.Run("revoke", func(t *testing.T) {
				// NGTS revokes by locally-computed thumbprint of the stored cert (no SearchCertificates).
				ngtsRevokeCertificate(t, integrationTestEnv, util.NormalizeSerial(integrationTestEnv.CertificateSerial))
			})
		})
	}
}

func TestNGTSsign(t *testing.T) {
	for _, cfg := range ngtsConfigVariants {
		cfg := cfg
		t.Run(string(cfg), func(t *testing.T) {
			integrationTestEnv, err := NewIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}

			data := testData{cn: randSeq(9) + ".venafi.example.com", signCSR: true}
			integrationTestEnv.writeVenafiToBackend(t, cfg)
			integrationTestEnv.writeRoleToBackendWithData(t, cfg, data)
			integrationTestEnv.SignCertificate(t, data, cfg)
		})
	}
}

// ngtsRevokeCertificate asserts the revoke path is correctly wired for NGTS. Unlike the shared
// RevokeCertificate helper (which only checks the Go error), this inspects the logical response:
//   - success                          → revoke worked (CA supports revocation);
//   - "...not supported for CA type..." → the CIT's CA (e.g. the built-in CA on some dev tenants)
//     doesn't support revocation, but the path is still proven correct (thumbprint computed,
//     API called, no panic / no "thumbprint required"). Accepted.
//   - anything else (panic, "thumbprint is required", DN errors) → the wiring regressed → fail.
func ngtsRevokeCertificate(t *testing.T, e *testEnv, certId string) {
	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "revoke/" + e.RoleName,
		Storage:   e.Storage,
		Data:      map[string]interface{}{"certificate_uid": certId},
	})
	if err != nil {
		t.Fatalf("revoke returned a Go error (expected a clean logical response): %v", err)
	}
	if resp != nil && resp.IsError() {
		msg := resp.Error().Error()
		if strings.Contains(msg, "not supported for CA type") {
			t.Logf("revoke not supported by this CIT's CA (expected on built-in-CA tenants); "+
				"path is correctly wired: %s", msg)
			return
		}
		t.Fatalf("revoke failed unexpectedly: %s", msg)
	}
}

// ngtsReadCertificate verifies the issued certificate can be read back. It intentionally does
// not require private_key in the response — the certificate read path no longer returns it.
func ngtsReadCertificate(t *testing.T, e *testEnv, certId string) {
	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "cert/" + certId,
		Storage:   e.Storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("failed to read NGTS certificate: %#v", resp)
	}
	if resp.Data["certificate"] == nil || resp.Data["certificate"] == "" {
		t.Fatalf("expected a certificate in read data, got: %#v", resp.Data)
	}
}
