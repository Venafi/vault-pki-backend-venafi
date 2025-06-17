//go:build vaas
// +build vaas

package pki

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// **Important**
// All VAAS tests should start with "TestVAAS" as defined in the Makefile
// otherwise they will be ignored

// Testing Venafi As A Service
func TestVAASintegration(t *testing.T) {
	t.Parallel()
	integrationTestEnv, err := NewIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Cloud base enroll", integrationTestEnv.CloudIntegrationIssueCertificate)
	t.Run("Cloud base enroll and verify ttl", integrationTestEnv.CloudIntegrationIssueCertificateAndVerifyTTL)
	t.Run("Cloud restricted enroll", integrationTestEnv.CloudIntegrationIssueCertificateRestricted)
	t.Run("Cloud issue certificate with password", integrationTestEnv.CloudIntegrationIssueCertificateWithPassword)
	t.Run("Cloud sign certificate", integrationTestEnv.CloudIntegrationSignCertificate)

}

func TestVAASparallelism(t *testing.T) {
	mu := sync.Mutex{}
	regDuration := time.Duration(24) * time.Hour
	t.Run("execute 20 certificates with same CN", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := &testData{minCertTimeLeft: regDuration}
		integrationTestEnv.SetupParallelismEnv(t, data, venafiConfigCloud, nil)
		count := 20
		var certSerials = map[string]string{}
		t.Run("executing", func(t *testing.T) {
			for i := 1; i <= count; i++ {
				index := i
				t.Run(fmt.Sprintf("executing cert number: %d", index), func(t *testing.T) {
					t.Parallel()
					serialNumber := integrationTestEnv.IssueCertificateAndSaveSerialParallelism(t, *data, venafiConfigCloud)
					mu.Lock()
					//certSerials = append(certSerials, serialNumber)
					certSerials[serialNumber] = serialNumber
					mu.Unlock()
				})
			}
		})
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
		integrationTestEnv.SetupParallelismEnv(t, data, venafiConfigCloud, nil)
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
						serialNumber := integrationTestEnv.IssueCertificateAndSaveSerialParallelism(t, *dataCertReq, venafiConfigCloud)
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

func TestVAASpreventLocalReissuance(t *testing.T) {
	t.Parallel()
	// regular duration for testing
	regDuration := time.Duration(24) * time.Hour
	// CASE: should be the SAME - same CN and SAN
	t.Run("VaaS enroll same certificate and prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: regDuration}
		integrationTestEnv.PreventReissuanceLocal(t, data, venafiConfigCloud)
	})
	// CASE: should be different - same CN but 1 additional SAN
	t.Run("VaaS second enroll certificate with extra SAN DNS and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: regDuration}
		integrationTestEnv.PreventReissuanceLocalCNwithExtraSANDNS(t, data, venafiConfigCloud)
	})
	// CASE: should be different - same CN and missing 1 SAN of 3
	t.Run("VaaS second enroll certificate and removing one SAN DNS from list and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: regDuration}
		integrationTestEnv.PreventReissuanceLocalCNandRemovingSANDNS(t, data, venafiConfigCloud)
	})
	// CASE: should be the SAME - same CN and no SANs
	t.Run("VaaS certificate with CN only and no SAN DNS second enroll should be prevented", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: regDuration}
		integrationTestEnv.PreventReissuanceLocalCNandNoSANSDNS(t, data, venafiConfigCloud)
	})
	t.Run("VaaS second enroll same certificate with TTL that is not sufficient for set valid time and should not prevent-reissue",
		func(t *testing.T) {
			integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: time.Duration(2159) * time.Hour}
		integrationTestEnv.PreventReissuanceLocalTTLvalid(t, data, venafiConfigCloud)
	})
	// CASE: should be the SAME - same CN and same 3 SANs
	t.Run("VaaS second enroll certificate with three SAN DNS and should prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: regDuration}
		integrationTestEnv.PreventReissuanceLocalCNwithThreeSANDNS(t, data, venafiConfigCloud)
	})
	// CASE: should be different - different CN and same 3 SANs
	t.Run("VaaS second enroll certificate with three SAN DNS but different CN and should not prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: regDuration}
		integrationTestEnv.PreventReissuanceLocalCNwithDifferentCNandThreeSANDNS(t, data, venafiConfigCloud)
	})
	// CASE: should be the SAME - no CN and same 3 SANs
	t.Run("VaaS second enroll certificate with three SAN DNS but no CN and should prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		data := testData{minCertTimeLeft: regDuration}
		integrationTestEnv.PreventReissuanceLocalCNwithNoCNandThreeSANDNS(t, data, venafiConfigCloud)
	})
	// Service generated CSR
	// CASE: should be the SAME - same CN and SAN
	t.Run("Service Generated CSR - VaaS enroll same certificate and prevent-reissue", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
			integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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
		integrationTestEnv, err := NewIntegrationTestEnv()
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

// Skipping following tests until we identify issue with VCP/CyberArk MIS service
//func TestVAASpreventReissuance(t *testing.T) {
//	t.Parallel()
//	// regular duration for testing
//	regDuration := time.Duration(24) * time.Hour
//	// CASE: should be the SAME - same CN and SAN
//	t.Run("VaaS enroll same certificate and prevent-reissue", func(t *testing.T) {
//		integrationTestEnv, err := NewIntegrationTestEnv()
//		if err != nil {
//			t.Fatal(err)
//		}
//		data := testData{
//			minCertTimeLeft: regDuration,
//		}
//		integrationTestEnv.PreventReissuance(t, data, venafiConfigCloud)
//	})
//	// CASE: should be different - same CN but 1 additional SAN
//	t.Run("VaaS second enroll certificate with extra SAN DNS and should not prevent-reissue", func(t *testing.T) {
//		integrationTestEnv, err := NewIntegrationTestEnv()
//		if err != nil {
//			t.Fatal(err)
//		}
//		data := testData{
//			minCertTimeLeft: regDuration,
//		}
//		integrationTestEnv.PreventReissuanceCNwithExtraSANDNS(t, data, venafiConfigCloud)
//	})
//	// CASE: should be different - same CN and missing 1 SAN of 3
//	t.Run("VaaS second enroll certificate and removing one SAN DNS from list and should not prevent-reissue", func(t *testing.T) {
//		integrationTestEnv, err := NewIntegrationTestEnv()
//		if err != nil {
//			t.Fatal(err)
//		}
//		data := testData{
//			minCertTimeLeft: regDuration,
//		}
//		integrationTestEnv.PreventReissuanceCNandRemovingSANDNS(t, data, venafiConfigCloud)
//	})
//	// CASE: should be the SAME - same CN and no SANs
//	t.Run("VaaS certificate with CN only and no SAN DNS second enroll should be prevented", func(t *testing.T) {
//		integrationTestEnv, err := NewIntegrationTestEnv()
//		if err != nil {
//			t.Fatal(err)
//		}
//		data := testData{
//			minCertTimeLeft: regDuration,
//		}
//		integrationTestEnv.PreventReissuanceCNnoSANSDNS(t, data, venafiConfigCloud)
//	})
//	t.Run("VaaS second enroll same certificate with TTL that is not sufficient for set valid time and should not prevent-reissue",
//		func(t *testing.T) {
//			integrationTestEnv, err := NewIntegrationTestEnv()
//			if err != nil {
//				t.Fatal(err)
//			}
//			data := testData{
//				// for VaaS use case we need to set and extra 24 hours since value is truncated (2184hrs = 91 days)
//				minCertTimeLeft: time.Duration(2184) * time.Hour,
//			}
//			integrationTestEnv.PreventReissuanceTTLnotValid(t, data, venafiConfigCloud)
//		})
//	// CASE: should be the SAME - same CN and SAN and just barely sufficiently valid
//	t.Run("VaaS second enroll same certificate wit TTL with barely sufficient valid time and should prevent-reissue", func(t *testing.T) {
//		integrationTestEnv, err := NewIntegrationTestEnv()
//		if err != nil {
//			t.Fatal(err)
//		}
//		data := testData{
//			minCertTimeLeft: time.Duration(2159) * time.Hour,
//		}
//		integrationTestEnv.PreventReissuanceTTLvalid(t, data, venafiConfigCloud)
//	})
//	// CASE: should be the SAME - same CN and same 3 SANs
//	t.Run("VaaS second enroll certificate with three SAN DNS and should prevent-reissue", func(t *testing.T) {
//		integrationTestEnv, err := NewIntegrationTestEnv()
//		if err != nil {
//			t.Fatal(err)
//		}
//		data := testData{
//			minCertTimeLeft: regDuration,
//		}
//		integrationTestEnv.PreventReissuanceCNwithThreeSANDNS(t, data, venafiConfigCloud)
//	})
//	// CASE: should be different - different CN and same 3 SANs
//	t.Run("VaaS second enroll certificate with three SAN DNS but different CN and should not prevent-reissue", func(t *testing.T) {
//		integrationTestEnv, err := NewIntegrationTestEnv()
//		if err != nil {
//			t.Fatal(err)
//		}
//		data := testData{
//			minCertTimeLeft: regDuration,
//		}
//		integrationTestEnv.PreventReissuanceCNwithDifferentCNandThreeSANDNS(t, data, venafiConfigCloud)
//	})
//	// CASE: should be the SAME - no CN and same 3 SANs
//	t.Run("VaaS second enroll certificate with three SAN DNS but no CN and should prevent-reissue", func(t *testing.T) {
//		integrationTestEnv, err := NewIntegrationTestEnv()
//		if err != nil {
//			t.Fatal(err)
//		}
//		data := testData{
//			minCertTimeLeft: regDuration,
//		}
//		integrationTestEnv.PreventReissuanceCNwithNoCNandThreeSANDNS(t, data, venafiConfigCloud)
//	})
//	// Service generated CSR
//	// CASE: should be the SAME - same CN and SAN
//	t.Run("Service Generated CSR - VaaS enroll same certificate and prevent-reissue", func(t *testing.T) {
//		integrationTestEnv, err := NewIntegrationTestEnv()
//		if err != nil {
//			t.Fatal(err)
//		}
//		data := testData{
//			serviceGeneratedCert: true,
//			minCertTimeLeft:      regDuration,
//		}
//		integrationTestEnv.PreventReissuance(t, data, venafiConfigCloud)
//	})
//	// CASE: should be different - same CN but 1 additional SAN
//	t.Run("Service Generated CSR - VaaS second enroll certificate with extra SAN DNS and should not prevent-reissue",
//		func(t *testing.T) {
//			integrationTestEnv, err := NewIntegrationTestEnv()
//			if err != nil {
//				t.Fatal(err)
//			}
//			data := testData{
//				serviceGeneratedCert: true,
//				minCertTimeLeft:      regDuration,
//			}
//			integrationTestEnv.PreventReissuanceCNwithExtraSANDNS(t, data, venafiConfigCloud)
//		})
//	// CASE: should be different - same CN and missing 1 SAN of 3
//	t.Run("Service Generated CSR - VaaS second enroll certificate and removing one SAN DNS from list and should not prevent-reissue",
//		func(t *testing.T) {
//			integrationTestEnv, err := NewIntegrationTestEnv()
//			if err != nil {
//				t.Fatal(err)
//			}
//			data := testData{
//				serviceGeneratedCert: true,
//				minCertTimeLeft:      regDuration,
//			}
//			integrationTestEnv.PreventReissuanceCNandRemovingSANDNS(t, data, venafiConfigCloud)
//		})
//	// CASE: should be the SAME - same CN and no SANs
//	t.Run("Service Generated CSR - VaaS certificate with CN only and no SAN DNS second enroll should be prevented",
//		func(t *testing.T) {
//			integrationTestEnv, err := NewIntegrationTestEnv()
//			if err != nil {
//				t.Fatal(err)
//			}
//			data := testData{
//				serviceGeneratedCert: true,
//				minCertTimeLeft:      regDuration,
//			}
//			integrationTestEnv.PreventReissuanceCNnoSANSDNS(t, data, venafiConfigCloud)
//		})
//	t.Run("Service Generated CSR - VaaS second enroll same certificate with TTL that is not sufficient for set valid time and should not prevent-reissue",
//		func(t *testing.T) {
//			integrationTestEnv, err := NewIntegrationTestEnv()
//			if err != nil {
//				t.Fatal(err)
//			}
//			data := testData{
//				serviceGeneratedCert: true,
//				// for VaaS use case we need to set and extra 24 hours since value is truncated (2184hrs = 91 days)
//				minCertTimeLeft: time.Duration(2184) * time.Hour,
//			}
//			integrationTestEnv.PreventReissuanceTTLnotValid(t, data, venafiConfigCloud)
//		})
//	// CASE: should be the SAME - same CN and SAN and just barely sufficiently valid
//	t.Run("Service Generated CSR - VaaS second enroll same certificate wit TTL with barely sufficient valid time and should prevent-reissue",
//		func(t *testing.T) {
//			integrationTestEnv, err := NewIntegrationTestEnv()
//			if err != nil {
//				t.Fatal(err)
//			}
//			data := testData{
//				serviceGeneratedCert: true,
//				minCertTimeLeft:      time.Duration(2159) * time.Hour,
//			}
//			integrationTestEnv.PreventReissuanceTTLvalid(t, data, venafiConfigCloud)
//		})
//	// CASE: should be the SAME - same CN and same 3 SANs
//	t.Run("Service Generated CSR - VaaS second enroll certificate with three SAN DNS and should prevent-reissue",
//		func(t *testing.T) {
//			integrationTestEnv, err := NewIntegrationTestEnv()
//			if err != nil {
//				t.Fatal(err)
//			}
//			data := testData{
//				serviceGeneratedCert: true,
//				minCertTimeLeft:      regDuration,
//			}
//			integrationTestEnv.PreventReissuanceCNwithThreeSANDNS(t, data, venafiConfigCloud)
//		})
//	// CASE: should be different - different CN and same 3 SANs
//	t.Run("Service Generated CSR - VaaS second enroll certificate with three SAN DNS but different CN and should not prevent-reissue",
//		func(t *testing.T) {
//			integrationTestEnv, err := NewIntegrationTestEnv()
//			if err != nil {
//				t.Fatal(err)
//			}
//			data := testData{
//				serviceGeneratedCert: true,
//				minCertTimeLeft:      regDuration,
//			}
//			integrationTestEnv.PreventReissuanceCNwithDifferentCNandThreeSANDNS(t, data, venafiConfigCloud)
//		})
//	// CASE: should be the SAME - no CN and same 3 SANs
//	t.Skip("Currently we skip this scenario as VaaS currently doesn't support it (probable bug)")
//	t.Run("Service Generated CSR - VaaS second enroll certificate with three SAN DNS but no CN and should prevent-reissue",
//		func(t *testing.T) {
//			integrationTestEnv, err := NewIntegrationTestEnv()
//			if err != nil {
//				t.Fatal(err)
//			}
//			data := testData{
//				serviceGeneratedCert: true,
//				minCertTimeLeft:      regDuration,
//			}
//			integrationTestEnv.PreventReissuanceCNwithNoCNandThreeSANDNS(t, data, venafiConfigCloud)
//		})
//}

func TestVAASnegativeTest(t *testing.T) {
	t.Parallel()
	t.Run("test error with wrong credentials", func(t *testing.T) {
		integrationTestEnv, err := NewIntegrationTestEnv()
		if err != nil {
			t.Fatal(err)
		}
		t.Run("VAAS base negative enroll", integrationTestEnv.VAASnegativeIssueCertificate)
	})
}
