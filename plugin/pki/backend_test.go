package pki

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFakeRolesConfigurations(t *testing.T) {
	integrationTestEnv, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("create role with no venafi secret", integrationTestEnv.CreateRoleEmptyVenafi)

}

func TestFakeVenafiSecretsConfigurations(t *testing.T) {
	integrationTestEnv, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("create wrong venafi secret (TPP/Cloud)", integrationTestEnv.CreateVenafiMixedTppAndCloud)
	t.Run("delete venafi secret", integrationTestEnv.DeleteVenafi)

	t.Run("create wrong venafi secret (TPP/Token)", integrationTestEnv.CreateVenafiMixedTppAndToken)
	t.Run("delete venafi secret", integrationTestEnv.DeleteVenafi)

	t.Run("create wrong venafi secret (Token/Cloud)", integrationTestEnv.CreateVenafiMixedTokenAndCloud)
	t.Run("delete venafi secret", integrationTestEnv.DeleteVenafi)

	t.Run("create venafi secret TPP", integrationTestEnv.CreateVenafiTPP)
	t.Run("read venafi secret TPP", integrationTestEnv.ReadVenafiTPP)
	t.Run("delete venafi secret", integrationTestEnv.DeleteVenafi)

	t.Run("create venafi secret Cloud", integrationTestEnv.CreateVenafiCloud)
	t.Run("read venafi secret Cloud", integrationTestEnv.ReadVenafiCloud)
	t.Run("delete venafi secret", integrationTestEnv.DeleteVenafi)

	t.Run("create venafi secret TPP Token", integrationTestEnv.CreateVenafiToken)
	t.Run("read venafi secret TPP Token", integrationTestEnv.ReadVenafiToken)
	t.Run("delete venafi secret", integrationTestEnv.DeleteVenafi)
}

//Testing all endpoints with fake vcert CA
func TestFakeEndpoints(t *testing.T) {
	integrationTestEnv, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("fake create venafi secret", integrationTestEnv.FakeCreateVenafi)
	t.Run("fake list venafi secrets", integrationTestEnv.FakeListVenafi)
	t.Run("fake read venafi secrets", integrationTestEnv.FakeReadVenafi)
	t.Run("fake create role", integrationTestEnv.FakeCreateRole)
	t.Run("fake list roles", integrationTestEnv.FakeListRole)
	t.Run("fake read roles", integrationTestEnv.FakeReadRole)
	t.Run("fake issue", integrationTestEnv.FakeIssueCertificateAndSaveSerial)
	t.Run("fake list certificates", integrationTestEnv.FakeListCertificate)
	t.Run("fake read certificate by serial", integrationTestEnv.FakeReadCertificateBySerial)
	t.Run("fake sign", integrationTestEnv.FakeSignCertificate)

}

//testing store_by no_store and deprecated store_by_cn and store_by_serial options
func TestFakeStoreByOptions(t *testing.T) {
	integrationTestEnv, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	//test store_by_serial deprecated option
	t.Run("create venafi secret", integrationTestEnv.FakeCreateVenafi)
	t.Run("create role deprecated store_by_serial", integrationTestEnv.FakeCreateRoleDeprecatedStoreBySerial)
	t.Run("issue", integrationTestEnv.FakeIssueCertificateAndSaveSerial)
	t.Run("read certificate by serial", integrationTestEnv.FakeReadCertificateBySerial)
	t.Run("delete role", integrationTestEnv.DeleteRole)
	t.Run("delete venafi", integrationTestEnv.DeleteVenafi)

	//test store_by_cn deprecated option
	t.Run("create venafi secret", integrationTestEnv.FakeCreateVenafi)
	t.Run("create role deprecated store_by_cn", integrationTestEnv.FakeCreateRoleDeprecatedStoreByCN)
	t.Run("issue", integrationTestEnv.FakeIssueCertificateAndSaveSerial)
	t.Run("read certificate by cn", integrationTestEnv.FakeReadCertificateByCN)
	t.Run("delete role", integrationTestEnv.DeleteRole)
	t.Run("delete venafi", integrationTestEnv.DeleteVenafi)

	//test store_by cn
	t.Run("create venafi secret", integrationTestEnv.FakeCreateVenafi)
	t.Run("create role store_by cn", integrationTestEnv.FakeCreateRoleStoreByCN)
	t.Run("issue", integrationTestEnv.FakeIssueCertificateAndSaveSerial)
	t.Run("read certificate by cn", integrationTestEnv.FakeReadCertificateByCN)
	t.Run("delete role", integrationTestEnv.DeleteRole)
	t.Run("delete venafi", integrationTestEnv.DeleteVenafi)

	//test store_by default
	t.Run("create venafi secret", integrationTestEnv.FakeCreateVenafi)
	t.Run("create role store_by serial", integrationTestEnv.FakeCreateRoleStoreBySerial)
	t.Run("issue", integrationTestEnv.FakeIssueCertificateAndSaveSerial)
	t.Run("read certificate by serial", integrationTestEnv.FakeReadCertificateBySerial)
	t.Run("delete role", integrationTestEnv.DeleteRole)
	t.Run("delete venafi", integrationTestEnv.DeleteVenafi)

	//test no_store
	t.Run("create venafi secret", integrationTestEnv.FakeCreateVenafi)
	t.Run("create role no_store true", integrationTestEnv.FakeCreateRoleNoStore)
	t.Run("issue", integrationTestEnv.FakeIssueCertificateAndSaveSerial)
	t.Run("check that there is no certificate", integrationTestEnv.FakeCheckThatThereIsNoCertificate)
	t.Run("delete role", integrationTestEnv.DeleteRole)
	t.Run("delete venafi", integrationTestEnv.DeleteVenafi)

	//test store_pkey false
	t.Run("create venafi secret", integrationTestEnv.FakeCreateVenafi)
	t.Run("create role store_pkey false", integrationTestEnv.FakeCreateRoleNoStorePKey)
	t.Run("issue", integrationTestEnv.FakeIssueCertificateAndSaveSerial)
	t.Run("check that there is no private key", integrationTestEnv.FakeCheckThatThereIsNoPKey)
	t.Run("delete role", integrationTestEnv.DeleteRole)
	t.Run("delete venafi", integrationTestEnv.DeleteVenafi)

}

//Testing Venafi Platform integration
func TestTPPIntegration(t *testing.T) {

	integrationTestEnv, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("TPP base enroll", integrationTestEnv.TPPIntegrationIssueCertificate)
	t.Run("TPP base enroll with password", integrationTestEnv.TPPIntegrationIssueCertificateWithPassword)
	t.Run("TPP restricted enroll", integrationTestEnv.TPPIntegrationIssueCertificateRestricted)
	t.Run("TPP sign certificate", integrationTestEnv.TPPIntegrationSignCertificate)

}

//Testing Venafi Cloud integration
func TestCloudIntegration(t *testing.T) {

	integrationTestEnv, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Cloud base enroll", integrationTestEnv.CloudIntegrationIssueCertificate)
	t.Run("Cloud base enroll and verify ttl", integrationTestEnv.CloudIntegrationIssueCertificateAndVerifyTTL)
	t.Run("Cloud restricted enroll", integrationTestEnv.CloudIntegrationIssueCertificateRestricted)
	t.Run("Cloud issue certificate with password", integrationTestEnv.CloudIntegrationIssueCertificateWithPassword)
	t.Run("Cloud sign certificate", integrationTestEnv.CloudIntegrationSignCertificate)

}

//Testing Venafi TPP Token integration
func TestTokenIntegration(t *testing.T) {

	integrationTestEnv, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("TPP Token base enroll", integrationTestEnv.TokenIntegrationIssueCertificate)
	t.Run("TPP Token base enroll with custom fields", integrationTestEnv.TokenIntegrationIssueCertificateWithCustomFields)
	t.Run("TPP Token base enroll and verify ttl", integrationTestEnv.TokenIntegrationIssueCertificateAndValidateTTL)
	t.Run("TPP Token base enroll with ttl on request", integrationTestEnv.TokenIntegrationIssueCertificateWithTTLOnIssueData)
	t.Run("TPP Token base enroll with password", integrationTestEnv.TokenIntegrationIssueCertificateWithPassword)
	t.Run("TPP Token restricted enroll", integrationTestEnv.TokenIntegrationIssueCertificateRestricted)
	t.Run("TPP Token sign certificate", integrationTestEnv.TokenIntegrationSignCertificate)
	t.Run("TPP Token sign certificate with custom fields", integrationTestEnv.TokenIntegrationSignCertificateWithCustomFields)
	t.Run("TPP Token sign certificate and ttl attribute", integrationTestEnv.TokenIntegrationSignWithTTLCertificate)
	t.Run("TPP Token revoke certificate by cn", integrationTestEnv.TokenIntegrationRevokeCertificateCN)
	t.Run("TPP Token revoke certificate by serial", integrationTestEnv.TokenIntegrationRevokeCertificateSerial)

}

func TestTPPpreventReissuance(t *testing.T) {
	// regular duration for testing
	regDuration := time.Duration(24) * time.Hour
	// CASE: should be the SAME - same CN and SAN
	t.Run("TPP Token enroll same certificate and prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuance(t, data, venafiConfigToken)
	})
	// CASE: should be different - same CN but 1 additional SAN
	t.Run("TPP Token second enroll certificate with extra SAN DNS and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceCNwithExtraSANDNS(t, data, venafiConfigToken)
	})
	// CASE: should be different - same CN and missing 1 SAN of 3
	t.Run("TPP Token second enroll certificate and removing one SAN DNS from list and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceCNandRemovingSANDNS(t, data, venafiConfigToken)
	})
	// CASE: should be the SAME - same CN and no SANs
	t.Run("TPP Token certificate with CN only and no SAN DNS second enroll should be prevented", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceCNnoSANSDNS(t, data, venafiConfigToken)
	})
	// CASE: should be different - same CN and SAN but just barely not sufficiently valid
	t.Run("TPP Token second enroll same certificate with TTL that is not sufficient for set valid time and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				minCertTimeLeft: time.Duration(24) * time.Hour,
				ttl:             time.Duration(23) * time.Hour,
			}
			integrationTestEnv.PreventReissuanceTTLnotValid(t, data, venafiConfigToken)
		})
	// CASE: should be the SAME - same CN and SAN and just barely sufficiently valid
	t.Run("TPP Token second enroll same certificate wit TTL with barely sufficient valid time and should prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		// we set a TLL less than a time we consider a certificate to be valid, so we always issue a new one
		data := testData{
			minCertTimeLeft: time.Duration(24) * time.Hour,
			ttl:             time.Duration(25) * time.Hour,
		}
		integrationTestEnv.PreventReissuanceTTLvalid(t, data, venafiConfigToken)
	})
	// CASE: should be the SAME - same CN and same 3 SANs
	t.Run("TPP Token second enroll certificate with three SAN DNS and should prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceCNwithThreeSANDNS(t, data, venafiConfigToken)
	})
	// CASE: should be different - different CN and same 3 SANs
	t.Run("TPP Token second enroll certificate with three SAN DNS but different CN and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceCNwithDifferentCNandThreeSANDNS(t, data, venafiConfigToken)
	})
	// CASE: should be the SAME - no CN and same 3 SANs
	t.Run("TPP Token second enroll certificate with three SAN DNS but no CN and should prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceCNwithNoCNandThreeSANDNS(t, data, venafiConfigToken)
	})
	// Service generated CSR
	// CASE: should be the SAME - same CN and SAN
	t.Run("Service Generated CSR - TPP Token enroll same certificate and prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			serviceGeneratedCert: true,
			minCertTimeLeft:      regDuration,
		}
		integrationTestEnv.PreventReissuance(t, data, venafiConfigToken)
	})
	// CASE: should be different - same CN but 1 additional SAN
	t.Run("Service Generated CSR - TPP Token second enroll certificate with extra SAN DNS and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceCNwithExtraSANDNS(t, data, venafiConfigToken)
		})
	// CASE: should be different - same CN and missing 1 SAN of 3
	t.Run("Service Generated CSR - TPP Token second enroll certificate and removing one SAN DNS from list and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceCNandRemovingSANDNS(t, data, venafiConfigToken)
		})
	// CASE: should be the SAME - same CN and no SANs
	t.Run("Service Generated CSR - TPP Token certificate with CN only and no SAN DNS second enroll should be prevented",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceCNnoSANSDNS(t, data, venafiConfigToken)
		})
	// CASE: should be different - same CN and SAN but just barely not sufficiently valid
	t.Run("Service Generated CSR - TPP Token second enroll same certificate with TTL that is not sufficient for set valid time and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      time.Duration(24) * time.Hour,
				ttl:                  time.Duration(23) * time.Hour,
			}
			integrationTestEnv.PreventReissuanceTTLnotValid(t, data, venafiConfigToken)
		})
	// CASE: should be the SAME - same CN and SAN and just barely sufficiently valid
	t.Run("Service Generated CSR - TPP Token second enroll same certificate wit TTL with barely sufficient valid time and should prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      time.Duration(24) * time.Hour,
				ttl:                  time.Duration(25) * time.Hour,
			}
			integrationTestEnv.PreventReissuanceTTLvalid(t, data, venafiConfigToken)
		})
	// CASE: should be the SAME - same CN and same 3 SANs
	t.Run("Service Generated CSR - TPP Token second enroll certificate with three SAN DNS and should prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceCNwithThreeSANDNS(t, data, venafiConfigToken)
		})
	// CASE: should be different - different CN and same 3 SANs
	t.Run("Service Generated CSR - TPP Token second enroll certificate with three SAN DNS but different CN and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceCNwithDifferentCNandThreeSANDNS(t, data, venafiConfigToken)
		})
	// CASE: should be the SAME - no CN and same 3 SANs
	t.Run("Service Generated CSR - TPP Token second enroll certificate with three SAN DNS but no CN and should prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceCNwithNoCNandThreeSANDNS(t, data, venafiConfigToken)
		})

	// CASE: should be the SAME - same CN and SAN
	// no cert time left set in roll, role's cert minimum time left defaults to 30 days, should still be valid on next validation
	t.Run("TPP Token enroll same certificate and prevent-reissue - no min time specified", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			ignoreLocalStorage: false,
		}
		integrationTestEnv.PreventReissuance(t, data, venafiConfigToken)
	})

	// CASE: should be the SAME - same CN and SAN
	// turn off prevent-reissue, we specify certificate's minimum time left but still should not prevent reissue
	t.Run("TPP Token enroll same certificate and should not prevent-reissue - cache turned off - min time specified", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			ignoreLocalStorage: true,
			minCertTimeLeft:    regDuration,
		}
		integrationTestEnv.NotPreventReissuance(t, data, venafiConfigToken)
	})
}

func TestVaasPreventReissuance(t *testing.T) {
	// regular duration for testing
	regDuration := time.Duration(24) * time.Hour
	// CASE: should be the SAME - same CN and SAN
	t.Run("VaaS enroll same certificate and prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuance(t, data, venafiConfigCloud)
	})
	// CASE: should be different - same CN but 1 additional SAN
	t.Run("VaaS second enroll certificate with extra SAN DNS and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceCNwithExtraSANDNS(t, data, venafiConfigCloud)
	})
	// CASE: should be different - same CN and missing 1 SAN of 3
	t.Run("VaaS second enroll certificate and removing one SAN DNS from list and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceCNandRemovingSANDNS(t, data, venafiConfigCloud)
	})
	// CASE: should be the SAME - same CN and no SANs
	t.Run("VaaS certificate with CN only and no SAN DNS second enroll should be prevented", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceCNnoSANSDNS(t, data, venafiConfigCloud)
	})
	t.Run("VaaS second enroll same certificate with TTL that is not sufficient for set valid time and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				// for VaaS use case we need to set and extra 24 hours since value is truncated (2184hrs = 91 days)
				minCertTimeLeft: time.Duration(2184) * time.Hour,
			}
			integrationTestEnv.PreventReissuanceTTLnotValid(t, data, venafiConfigCloud)
		})
	// CASE: should be the SAME - same CN and SAN and just barely sufficiently valid
	t.Run("VaaS second enroll same certificate wit TTL with barely sufficient valid time and should prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: time.Duration(2159) * time.Hour,
		}
		integrationTestEnv.PreventReissuanceTTLvalid(t, data, venafiConfigCloud)
	})
	// CASE: should be the SAME - same CN and same 3 SANs
	t.Run("VaaS second enroll certificate with three SAN DNS and should prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceCNwithThreeSANDNS(t, data, venafiConfigCloud)
	})
	// CASE: should be different - different CN and same 3 SANs
	t.Run("VaaS second enroll certificate with three SAN DNS but different CN and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceCNwithDifferentCNandThreeSANDNS(t, data, venafiConfigCloud)
	})
	// CASE: should be the SAME - no CN and same 3 SANs
	t.Run("VaaS second enroll certificate with three SAN DNS but no CN and should prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceCNwithNoCNandThreeSANDNS(t, data, venafiConfigCloud)
	})
	// Service generated CSR
	// CASE: should be the SAME - same CN and SAN
	t.Run("Service Generated CSR - VaaS enroll same certificate and prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			serviceGeneratedCert: true,
			minCertTimeLeft:      regDuration,
		}
		integrationTestEnv.PreventReissuance(t, data, venafiConfigCloud)
	})
	// CASE: should be different - same CN but 1 additional SAN
	t.Run("Service Generated CSR - VaaS second enroll certificate with extra SAN DNS and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceCNwithExtraSANDNS(t, data, venafiConfigCloud)
		})
	// CASE: should be different - same CN and missing 1 SAN of 3
	t.Run("Service Generated CSR - VaaS second enroll certificate and removing one SAN DNS from list and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceCNandRemovingSANDNS(t, data, venafiConfigCloud)
		})
	// CASE: should be the SAME - same CN and no SANs
	t.Run("Service Generated CSR - VaaS certificate with CN only and no SAN DNS second enroll should be prevented",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceCNnoSANSDNS(t, data, venafiConfigCloud)
		})
	t.Run("Service Generated CSR - VaaS second enroll same certificate with TTL that is not sufficient for set valid time and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				// for VaaS use case we need to set and extra 24 hours since value is truncated (2184hrs = 91 days)
				minCertTimeLeft: time.Duration(2184) * time.Hour,
			}
			integrationTestEnv.PreventReissuanceTTLnotValid(t, data, venafiConfigCloud)
		})
	// CASE: should be the SAME - same CN and SAN and just barely sufficiently valid
	t.Run("Service Generated CSR - VaaS second enroll same certificate wit TTL with barely sufficient valid time and should prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      time.Duration(2159) * time.Hour,
			}
			integrationTestEnv.PreventReissuanceTTLvalid(t, data, venafiConfigCloud)
		})
	// CASE: should be the SAME - same CN and same 3 SANs
	t.Run("Service Generated CSR - VaaS second enroll certificate with three SAN DNS and should prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceCNwithThreeSANDNS(t, data, venafiConfigCloud)
		})
	// CASE: should be different - different CN and same 3 SANs
	t.Run("Service Generated CSR - VaaS second enroll certificate with three SAN DNS but different CN and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceCNwithDifferentCNandThreeSANDNS(t, data, venafiConfigCloud)
		})
	// CASE: should be the SAME - no CN and same 3 SANs
	t.Skip("Currently we skip this scenario as VaaS currently doesn't support it (probable bug)")
	t.Run("Service Generated CSR - VaaS second enroll certificate with three SAN DNS but no CN and should prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceCNwithNoCNandThreeSANDNS(t, data, venafiConfigCloud)
		})
}

func TestTPPpreventLocal(t *testing.T) {
	// regular duration for testing
	regDuration := time.Duration(168) * time.Hour // one week
	// CASE: should be the SAME - same CN and SAN
	t.Run("TPP Token enroll same certificate and prevent-reissue locally", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceLocal(t, data, venafiConfigToken)
	})
	// CASE: should be different - same CN but 1 additional SAN
	t.Run("TPP Token second enroll certificate with extra SAN DNS and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceLocalCNwithExtraSANDNS(t, data, venafiConfigToken)
	})
	// CASE: should be different - same CN and missing 1 SAN of 3
	t.Run("TPP Token second enroll certificate and removing one SAN DNS from list and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceLocalCNandRemovingSANDNS(t, data, venafiConfigToken)
	})
	// CASE: should be the SAME - same CN and no SANs
	t.Run("TPP Token certificate with CN only and no SAN DNS second enroll should be prevented", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceLocalCNandNoSANSDNS(t, data, venafiConfigToken)
	})
	// CASE: should be different - same CN and SAN but just barely not sufficiently valid
	t.Run("TPP Token second enroll same certificate with TTL that is not sufficient for set valid time and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				minCertTimeLeft: time.Duration(24) * time.Hour,
				ttl:             time.Duration(23) * time.Hour,
			}
			integrationTestEnv.PreventReissuanceLocalTTLnotValid(t, data, venafiConfigToken)
		})
	// CASE: should be the SAME - same CN and SAN and just barely sufficiently valid
	t.Run("TPP Token second enroll same certificate wit TTL with barely sufficient valid time and should prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		// we set a TLL less than a time we consider a certificate to be valid, so we always issue a new one
		data := testData{
			minCertTimeLeft: time.Duration(24) * time.Hour,
			ttl:             time.Duration(25) * time.Hour,
		}
		integrationTestEnv.PreventReissuanceLocalTTLvalid(t, data, venafiConfigToken)
	})
	// CASE: should be the SAME - same CN and same 3 SANs
	t.Run("TPP Token second enroll certificate with three SAN DNS and should prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceLocalCNwithThreeSANDNS(t, data, venafiConfigToken)
	})
	// CASE: should be different - different CN and same 3 SANs
	t.Run("TPP Token second enroll certificate with three SAN DNS but different CN and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceLocalCNwithDifferentCNandThreeSANDNS(t, data, venafiConfigToken)
	})
	// CASE: should be the SAME - no CN and same 3 SANs
	t.Run("TPP Token second enroll certificate with three SAN DNS but no CN and should prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceLocalCNwithNoCNandThreeSANDNS(t, data, venafiConfigToken)
	})
	// Service generated CSR
	// CASE: should be the SAME - same CN and SAN
	t.Run("Service Generated CSR - TPP Token enroll same certificate and prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			serviceGeneratedCert: true,
			minCertTimeLeft:      regDuration,
		}
		integrationTestEnv.PreventReissuanceLocal(t, data, venafiConfigToken)
	})
	// CASE: should be different - same CN but 1 additional SAN
	t.Run("Service Generated CSR - TPP Token second enroll certificate with extra SAN DNS and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceLocalCNwithExtraSANDNS(t, data, venafiConfigToken)
		})
	// CASE: should be different - same CN and missing 1 SAN of 3
	t.Run("Service Generated CSR - TPP Token second enroll certificate and removing one SAN DNS from list and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceLocalCNandRemovingSANDNS(t, data, venafiConfigToken)
		})
	// CASE: should be the SAME - same CN and no SANs
	t.Run("Service Generated CSR - TPP Token certificate with CN only and no SAN DNS second enroll should be prevented",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceLocalCNandNoSANSDNS(t, data, venafiConfigToken)
		})
	// CASE: should be different - same CN and SAN but just barely not sufficiently valid
	t.Run("Service Generated CSR - TPP Token second enroll same certificate with TTL that is not sufficient for set valid time and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      time.Duration(24) * time.Hour,
				ttl:                  time.Duration(23) * time.Hour,
			}
			integrationTestEnv.PreventReissuanceLocalTTLnotValid(t, data, venafiConfigToken)
		})
	// CASE: should be the SAME - same CN and SAN and just barely sufficiently valid
	t.Run("Service Generated CSR - TPP Token second enroll same certificate wit TTL with barely sufficient valid time and should prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      time.Duration(24) * time.Hour,
				ttl:                  time.Duration(25) * time.Hour,
			}
			integrationTestEnv.PreventReissuanceLocalTTLvalid(t, data, venafiConfigToken)
		})
	// CASE: should be the SAME - same CN and same 3 SANs
	t.Run("Service Generated CSR - TPP Token second enroll certificate with three SAN DNS and should prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceLocalCNwithThreeSANDNS(t, data, venafiConfigToken)
		})
	// CASE: should be different - different CN and same 3 SANs
	t.Run("Service Generated CSR - TPP Token second enroll certificate with three SAN DNS but different CN and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceLocalCNwithDifferentCNandThreeSANDNS(t, data, venafiConfigToken)
		})
	// CASE: should be the SAME - no CN and same 3 SANs
	t.Run("Service Generated CSR - TPP Token second enroll certificate with three SAN DNS but no CN and should prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceLocalCNwithNoCNandThreeSANDNS(t, data, venafiConfigToken)
		})
}

func TestVaasPreventLocalReissuance(t *testing.T) {
	// regular duration for testing
	regDuration := time.Duration(24) * time.Hour
	// CASE: should be the SAME - same CN and SAN
	t.Run("VaaS enroll same certificate and prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: regDuration}
		integrationTestEnv.PreventReissuanceLocal(t, data, venafiConfigCloud)
	})
	// CASE: should be different - same CN but 1 additional SAN
	t.Run("VaaS second enroll certificate with extra SAN DNS and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: regDuration}
		integrationTestEnv.PreventReissuanceLocalCNwithExtraSANDNS(t, data, venafiConfigCloud)
	})
	// CASE: should be different - same CN and missing 1 SAN of 3
	t.Run("VaaS second enroll certificate and removing one SAN DNS from list and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: regDuration}
		integrationTestEnv.PreventReissuanceLocalCNandRemovingSANDNS(t, data, venafiConfigCloud)
	})
	// CASE: should be the SAME - same CN and no SANs
	t.Run("VaaS certificate with CN only and no SAN DNS second enroll should be prevented", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: regDuration}
		integrationTestEnv.PreventReissuanceLocalCNandNoSANSDNS(t, data, venafiConfigCloud)
	})
	t.Run("VaaS second enroll same certificate with TTL that is not sufficient for set valid time and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				// for VaaS use case we need to set and extra 24 hours since value is truncated (2184hrs = 91 days)
				minCertTimeLeft: time.Duration(2184) * time.Hour,
			}
			integrationTestEnv.PreventReissuanceLocalTTLnotValid(t, data, venafiConfigCloud)
		})
	// CASE: should be the SAME - same CN and SAN and just barely sufficiently valid
	t.Run("VaaS second enroll same certificate wit TTL with barely sufficient valid time and should prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: time.Duration(2159) * time.Hour}
		integrationTestEnv.PreventReissuanceLocalTTLvalid(t, data, venafiConfigCloud)
	})
	// CASE: should be the SAME - same CN and same 3 SANs
	t.Run("VaaS second enroll certificate with three SAN DNS and should prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: regDuration}
		integrationTestEnv.PreventReissuanceLocalCNwithThreeSANDNS(t, data, venafiConfigCloud)
	})
	// CASE: should be different - different CN and same 3 SANs
	t.Run("VaaS second enroll certificate with three SAN DNS but different CN and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: regDuration}
		integrationTestEnv.PreventReissuanceLocalCNwithDifferentCNandThreeSANDNS(t, data, venafiConfigCloud)
	})
	// CASE: should be the SAME - no CN and same 3 SANs
	t.Run("VaaS second enroll certificate with three SAN DNS but no CN and should prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: regDuration}
		integrationTestEnv.PreventReissuanceLocalCNwithNoCNandThreeSANDNS(t, data, venafiConfigCloud)
	})
	// Service generated CSR
	// CASE: should be the SAME - same CN and SAN
	t.Run("Service Generated CSR - VaaS enroll same certificate and prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			serviceGeneratedCert: true,
			minCertTimeLeft:      regDuration,
		}
		integrationTestEnv.PreventReissuanceLocal(t, data, venafiConfigCloud)
	})
	// CASE: should be different - same CN but 1 additional SAN
	t.Run("Service Generated CSR - VaaS second enroll certificate with extra SAN DNS and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceLocalCNwithExtraSANDNS(t, data, venafiConfigCloud)
		})
	// CASE: should be different - same CN and missing 1 SAN of 3
	t.Run("Service Generated CSR - VaaS second enroll certificate and removing one SAN DNS from list and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceLocalCNandRemovingSANDNS(t, data, venafiConfigCloud)
		})
	// CASE: should be the SAME - same CN and no SANs
	t.Run("Service Generated CSR - VaaS certificate with CN only and no SAN DNS second enroll should be prevented",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceLocalCNandNoSANSDNS(t, data, venafiConfigCloud)
		})
	t.Run("Service Generated CSR - VaaS second enroll same certificate with TTL that is not sufficient for set valid time and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				// for VaaS use case we need to set and extra 24 hours since value is truncated (2184hrs = 91 days)
				minCertTimeLeft: time.Duration(2184) * time.Hour,
			}
			integrationTestEnv.PreventReissuanceLocalTTLnotValid(t, data, venafiConfigCloud)
		})
	// CASE: should be the SAME - same CN and SAN and just barely sufficiently valid
	t.Run("Service Generated CSR - VaaS second enroll same certificate wit TTL with barely sufficient valid time and should prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      time.Duration(2159) * time.Hour,
			}
			integrationTestEnv.PreventReissuanceLocalTTLvalid(t, data, venafiConfigCloud)
		})
	// CASE: should be the SAME - same CN and same 3 SANs
	t.Run("Service Generated CSR - VaaS second enroll certificate with three SAN DNS and should prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceLocalCNwithThreeSANDNS(t, data, venafiConfigCloud)
		})
	// CASE: should be different - different CN and same 3 SANs
	t.Run("Service Generated CSR - VaaS second enroll certificate with three SAN DNS but different CN and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceLocalCNwithDifferentCNandThreeSANDNS(t, data, venafiConfigCloud)
		})
	// CASE: should be the SAME - no CN and same 3 SANs
	t.Skip("Currently we skip this scenario as VaaS currently doesn't support it (probable bug)")
	t.Run("Service Generated CSR - VaaS second enroll certificate with three SAN DNS but no CN and should prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := newIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}
			data := testData{
				serviceGeneratedCert: true,
				minCertTimeLeft:      regDuration,
			}
			integrationTestEnv.PreventReissuanceLocalCNwithNoCNandThreeSANDNS(t, data, venafiConfigCloud)
		})

	// CASE: should be the SAME - same CN and SAN
	// no cert time left set in roll, role's cert minimum time left defaults to 30 days, should still be valid on next validation
	t.Run("TPP Token enroll same certificate and prevent-reissue locally - no min time specified", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			ignoreLocalStorage: false,
		}
		integrationTestEnv.PreventReissuanceLocal(t, data, venafiConfigToken)
	})

	// CASE: should be the SAME - same CN and SAN
	// turn off prevent-reissue-local, we specify certificate's minimum time left but still should not prevent reissue
	t.Run("TPP Token enroll same certificate and should not prevent-reissue locally - cache turned off - min time specified", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			ignoreLocalStorage: true,
			minCertTimeLeft:    regDuration,
		}
		integrationTestEnv.NotPreventReissuanceLocal(t, data, venafiConfigToken)
	})
}

func TestZoneOverride(t *testing.T) {

	integrationTestEnv, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Token enroll with role zone", integrationTestEnv.TokenEnrollWithRoleZone)
	t.Run("Token enroll with Venafi secret zone", integrationTestEnv.TokenEnrollWithVenafiSecretZone)
}

func TestTPPparallelism(t *testing.T) {
	mu := sync.Mutex{}
	regDuration := time.Duration(24) * time.Hour
	t.Run("execute 20 certificates with same CN", func(t *testing.T) {
		t.Parallel()
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := &testData{minCertTimeLeft: regDuration}
		integrationTestEnv.TPPparallelism(t, data, venafiConfigToken)
		count := 20
		var certSerials []string
		t.Run("executing", func(t *testing.T) {
			for i := 1; i <= count; i++ {
				index := i
				t.Run(fmt.Sprintf("executing cert number: %d", index), func(t *testing.T) {
					t.Parallel()
					integrationTestEnv.IssueCertificateAndSaveSerial(t, *data, venafiConfigToken)
					mu.Lock()
					certSerials = append(certSerials, integrationTestEnv.CertificateSerial)
					mu.Unlock()
				})
			}
		})
		removeDuplicateStr(&certSerials)
		output := "'" + strings.Join(certSerials, "',\n'") + `'`
		t.Log(fmt.Sprintf("certificate serials:\n%s", output))
		// If the amount of distinct serials is different than the amount of certificates names, means we got
		if len(certSerials) != 1 {
			t.Fatal("The distinct amount of certificate serials is different that the distinct certificates we requested")
		}
	})

	t.Run("execute 50 certificates with some of them having different CN", func(t *testing.T) {
		integrationTestEnv, err := newIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := &testData{minCertTimeLeft: regDuration}
		integrationTestEnv.TPPparallelism(t, data, venafiConfigToken)
		count := 10
		countCertNames := 5
		var certSerials []string
		t.Run("executing", func(t *testing.T) {
			for i := 1; i <= countCertNames; i++ {
				var dataCertReq *testData
				rand := randSeq(9)
				domain := "venafi.example.com"
				dataCertReq = &testData{
					cn: rand + "." + domain,
				}
				for j := 1; j <= count; j++ {
					index := j
					t.Run(fmt.Sprintf("executing cert number: %d and CN: %s", index, (*dataCertReq).cn), func(t *testing.T) {
						t.Parallel()
						integrationTestEnv.IssueCertificateAndSaveSerial(t, *dataCertReq, venafiConfigToken)
						mu.Lock()
						certSerials = append(certSerials, integrationTestEnv.CertificateSerial)
						mu.Unlock()
					})
				}
			}
		})
		removeDuplicateStr(&certSerials)
		output := "'" + strings.Join(certSerials, "',\n'") + `'`
		t.Log(fmt.Sprintf("certificate serials:\n%s", output))
		// If the amount of distinct serials is different than the amount of certificates names, means we got
		if len(certSerials) != countCertNames {
			t.Fatal("The distinct amount of certificate serials is different that the distinct certificates we requested")
		}
	})
}
