package pki

import (
	"testing"
)

func TestEndpoints(t *testing.T) {
	integrationTestEnv, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("fake create role", integrationTestEnv.FakeCreateRole)
	t.Run("fake list roles", integrationTestEnv.FakeListRole)
	t.Run("fake issue", integrationTestEnv.FakeIssueCertificate)
	t.Run("fake sign", integrationTestEnv.FakeSignCertificate)
	t.Run("fake list", integrationTestEnv.FakeListCertificate)
	t.Run("fake read by cn", integrationTestEnv.FakeReadCertificateByCN)
	t.Run("fake read by serial", integrationTestEnv.FakeReadCertificateBySerial)
}

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

func TestCloudIntegration(t *testing.T) {

	integrationTestEnv, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Cloud base enroll", integrationTestEnv.CloudIntegrationIssueCertificate)
	t.Run("Cloud restricted enroll", integrationTestEnv.CloudIntegrationIssueCertificateRestricted)
	t.Run("Cloud issue certificate with password", integrationTestEnv.CloudIntegrationIssueCertificateWithPassword)
	t.Run("Cloud sign certificate", integrationTestEnv.CloudIntegrationSignCertificate)
}

//TODO: add tests for cert read and list
