package pki

import (
	"testing"
)

func TestIntegration(t *testing.T) {

	integrationTestEnv, err := newIntegrationTestEnv(t)
	if err != nil {
		t.Fatal(err)
	}


	t.Run("fake base enroll", integrationTestEnv.FakeIssueCertificate)
	t.Run("TPP base enroll", integrationTestEnv.TPPIssueCertificate)
	t.Run("TPP restricted enroll", integrationTestEnv.TPPIssueCertificateRestricted)
	t.Run("TPP sign certificate", integrationTestEnv.TPPSignCertificate)
	t.Run("Cloud base enroll", integrationTestEnv.CloudIssueCertificate)
	t.Run("Cloud restricted enroll", integrationTestEnv.CloudIssueCertificateRestricted)
	t.Run("Cloud sign certificate", integrationTestEnv.CloudSignCertificate)

}

