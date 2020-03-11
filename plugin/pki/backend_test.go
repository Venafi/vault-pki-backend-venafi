package pki

import (
	"testing"
)

func TestRolesConfigurations(t *testing.T) {
	integrationTestEnv, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("create wrong role", integrationTestEnv.CreateMixedRole)
	t.Run("delete role", integrationTestEnv.DeleteRole)
	t.Run("tpp create role", integrationTestEnv.TPPCreateRole)
	t.Run("tpp read role", integrationTestEnv.TPPReadRole)
	t.Run("delete role", integrationTestEnv.DeleteRole)
	t.Run("cloud create role", integrationTestEnv.CloudCreateRole)
	t.Run("cloud read role", integrationTestEnv.CloudReadRole)
}

//Testing all endpoints with fake vcert CA
func TestEndpoints(t *testing.T) {
	integrationTestEnv, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("fake create role", integrationTestEnv.FakeCreateRole)
	t.Run("fake list roles", integrationTestEnv.FakeListRole)
	t.Run("fake read roles", integrationTestEnv.FakeReadRole)
	t.Run("fake issue", integrationTestEnv.FakeIssueCertificate)
	t.Run("fake list certificates", integrationTestEnv.FakeListCertificate)
	t.Run("fake read certificate by serial", integrationTestEnv.FakeReadCertificateBySerial)
	t.Run("fake sign", integrationTestEnv.FakeSignCertificate)
	t.Run("fake revoke certificate", integrationTestEnv.FakeRevokeCertificate)

}

//testing store_by no_store and deprecated store_by_cn and store_by_serial options
func TestStoreByOptions(t *testing.T) {
	integrationTestEnv, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	//test store_by_serial deprecated option
	t.Run("fake create role deprecated store_by_serial", integrationTestEnv.FakeCreateRoleDeprecatedStoreBySerial)
	t.Run("fake issue", integrationTestEnv.FakeIssueCertificate)
	t.Run("fake read certificate by serial", integrationTestEnv.FakeReadCertificateBySerial)
	t.Run("delete role", integrationTestEnv.DeleteRole)

	//test store_by_cn deprecated option
	t.Run("fake create role deprecated store_by_cn", integrationTestEnv.FakeCreateRoleDeprecatedStoreByCN)
	t.Run("fake issue", integrationTestEnv.FakeIssueCertificate)
	t.Run("fake read certificate by cn", integrationTestEnv.FakeReadCertificateByCN)
	t.Run("delete role", integrationTestEnv.DeleteRole)

	//
	t.Run("fake create role deprecated store_by_cn", integrationTestEnv.FakeCreateRoleStoreBySerial)
	t.Run("fake issue", integrationTestEnv.FakeIssueCertificate)
	t.Run("fake read certificate by serial", integrationTestEnv.FakeReadCertificateBySerial)
	t.Run("delete role", integrationTestEnv.DeleteRole)

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
	t.Run("Cloud restricted enroll", integrationTestEnv.CloudIntegrationIssueCertificateRestricted)
	t.Run("Cloud issue certificate with password", integrationTestEnv.CloudIntegrationIssueCertificateWithPassword)
	t.Run("Cloud sign certificate", integrationTestEnv.CloudIntegrationSignCertificate)
}
