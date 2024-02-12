//go:build tpp
// +build tpp

package pki

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// **Important**
// All TPP tests should start with "TestTPP" as defined in the Makefile
// otherwise they will be ignored

func TestTPPdeprecratedAuth(t *testing.T) {
	t.Parallel()
	integrationTestEnv, err := NewIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("TPP base enroll", integrationTestEnv.TPPIntegrationIssueCertificate)
	t.Run("TPP base enroll with password", integrationTestEnv.TPPIntegrationIssueCertificateWithPassword)
	t.Run("TPP restricted enroll", integrationTestEnv.TPPIntegrationIssueCertificateRestricted)
	t.Run("TPP sign certificate", integrationTestEnv.TPPIntegrationSignCertificate)

}

// Testing Venafi TPP Token integration
func TestTPPintegration(t *testing.T) {
	t.Parallel()
	integrationTestEnv, err := NewIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("TPP Token base enroll", integrationTestEnv.TokenIntegrationIssueCertificate)
	t.Run("TPP Token base enroll with custom fields", integrationTestEnv.TokenIntegrationIssueCertificateWithCustomFields)
	t.Run("TPP Token base enroll and verify ttl", integrationTestEnv.TokenIntegrationIssueCertificateAndValidateTTL)
	t.Run("TPP Token base enroll with ttl on request", integrationTestEnv.TokenIntegrationIssueCertificateWithTTLOnIssueData)
	t.Run("TPP Token base enroll with password", integrationTestEnv.TokenIntegrationIssueCertificateWithPassword)
	t.Run("TPP Token base enroll PKCS12 formatted certificate", integrationTestEnv.TokenIntegrationIssueCertificateAsPkcs12)
	t.Run("TPP Token restricted enroll", integrationTestEnv.TokenIntegrationIssueCertificateRestricted)
	t.Run("TPP Token sign certificate", integrationTestEnv.TokenIntegrationSignCertificate)
	t.Run("TPP Token sign certificate with custom fields", integrationTestEnv.TokenIntegrationSignCertificateWithCustomFields)
	t.Run("TPP Token sign certificate and ttl attribute", integrationTestEnv.TokenIntegrationSignWithTTLCertificate)
	t.Run("TPP Token revoke certificate by cn", integrationTestEnv.TokenIntegrationRevokeCertificateCN)
	t.Run("TPP Token revoke certificate by serial", integrationTestEnv.TokenIntegrationRevokeCertificateSerial)

}

func TestTPPzoneOverride(t *testing.T) {
	t.Parallel()
	integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := &testData{minCertTimeLeft: regDuration}
		integrationTestEnv.SetupParallelismEnv(t, data, venafiConfigToken, nil)
		count := 20
		var certSerials = map[string]string{}
		t.Run("executing", func(t *testing.T) {
			for i := 1; i <= count; i++ {
				index := i
				t.Run(fmt.Sprintf("executing cert number: %d", index), func(t *testing.T) {
					t.Parallel()
					serialNumber := integrationTestEnv.IssueCertificateAndSaveSerialParallelism(t, *data, venafiConfigToken)
					mu.Lock()
					certSerials[serialNumber] = serialNumber
					mu.Unlock()
				})
			}
		})
		// If the amount of distinct serials is different than the amount of certificates names, means we got
		if len(certSerials) != 1 {
			t.Fatal("The distinct amount of certificate serials is different that the distinct certificates we requested")
		}
	})

	t.Run("execute 50 certificates with some of them having different CN", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := &testData{minCertTimeLeft: regDuration}
		integrationTestEnv.SetupParallelismEnv(t, data, venafiConfigToken, nil)
		count := 10
		countCertNames := 5
		var certSerials = map[string]string{}
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
						serialNumber := integrationTestEnv.IssueCertificateAndSaveSerialParallelism(t, *dataCertReq, venafiConfigToken)
						mu.Lock()
						certSerials[serialNumber] = serialNumber
						mu.Unlock()
					})
				}
			}
		})
		// If the amount of distinct serials is different than the amount of certificates names, means we got
		if len(certSerials) != countCertNames {
			t.Fatal("The distinct amount of certificate serials is different that the distinct certificates we requested")
		}
	})
}

// Testing TPP with preventing re-issuance using local storage with local generated CSR
func TestTPPpreventLocalWithLocalGenCSR(t *testing.T) {
	t.Parallel()
	// regular duration for testing
	regDuration := time.Duration(168) * time.Hour // one week
	// CASE: should be the SAME - same CN and SAN
	t.Run("TPP Token enroll same certificate and prevent-reissue locally", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceLocalCNwithNoCNandThreeSANDNS(t, data, venafiConfigToken)
	})
}

func TestTPPpreventLocalWithServiceGenCSR(t *testing.T) {
	t.Parallel()
	// regular duration for testing
	regDuration := time.Duration(168) * time.Hour // one week
	// Service generated CSR
	// CASE: should be the SAME - same CN and SAN
	t.Run("Service Generated CSR - TPP Token enroll same certificate and prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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

func TestTPPpreventReissuanceLocalGenCSR(t *testing.T) {
	t.Parallel()
	// regular duration for testing
	regDuration := time.Duration(24) * time.Hour
	// CASE: should be the SAME - same CN and SAN
	t.Run("TPP Token enroll same certificate and prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{
			minCertTimeLeft: regDuration,
		}
		integrationTestEnv.PreventReissuanceCNwithNoCNandThreeSANDNS(t, data, venafiConfigToken)
	})
}

func TestTPPpreventReissuanceServiceGenCSR(t *testing.T) {
	t.Parallel()
	// regular duration for testing
	regDuration := time.Duration(24) * time.Hour
	// Service generated CSR
	// CASE: should be the SAME - same CN and SAN
	t.Run("Service Generated CSR - TPP Token enroll same certificate and prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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

func TestTPPnegativeTest(t *testing.T) {
	t.Parallel()
	t.Run("test error with wrong credentials", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		t.Run("TPP Token base negative enroll", integrationTestEnv.TPPnegativeIssueCertificate)
	})
}
