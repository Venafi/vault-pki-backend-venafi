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
	t.Run("fake base enroll with password", integrationTestEnv.FakeIssueCertificateWithPassword)
	t.Run("fake sign certificate", integrationTestEnv.FakeSignCertificate)

	t.Run("TPP base enroll", integrationTestEnv.TPPIssueCertificate)
	t.Run("TPP base enroll with password", integrationTestEnv.TPPIssueCertificateWithPassword)
	t.Run("TPP restricted enroll", integrationTestEnv.TPPIssueCertificateRestricted)
	t.Run("TPP sign certificate", integrationTestEnv.TPPSignCertificate)

	t.Run("Cloud base enroll", integrationTestEnv.CloudIssueCertificate)
	t.Run("Cloud restricted enroll", integrationTestEnv.CloudIssueCertificateRestricted)
	t.Run("Cloud issue certificate with password", integrationTestEnv.CloudIssueCertificateWithPassword)
	t.Run("Cloud sign certificate", integrationTestEnv.CloudSignCertificate)

}

//TODO: add tests for cert read and list