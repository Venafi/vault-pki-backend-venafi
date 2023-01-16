package pki

import (
	"context"
	"github.com/Venafi/vault-pki-backend-venafi/plugin/util"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
)

func TestFakeRolesConfigurations(t *testing.T) {
	integrationTestEnv, err := NewIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("create role with no venafi secret", integrationTestEnv.CreateRoleEmptyVenafi)

}

func TestFakeVenafiSecretsConfigurations(t *testing.T) {
	integrationTestEnv, err := NewIntegrationTestEnv()
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

	t.Run("create venafi secret TPP Token", integrationTestEnv.CreateVenafiTokenWithRefresh)
	t.Run("read venafi secret TPP Token", integrationTestEnv.ReadVenafiToken)
	t.Run("delete venafi secret", integrationTestEnv.DeleteVenafi)

	t.Run("create venafi secret TPP Token", integrationTestEnv.FailCreateVenafiTokenWithOnlyOneRefresh)
	t.Run("delete venafi secret", integrationTestEnv.DeleteVenafi)

	t.Run("create venafi secret TPP Token", integrationTestEnv.FailCreateVenafiTokenWithOnlySecondRefreshSet)
	t.Run("delete venafi secret", integrationTestEnv.DeleteVenafi)
}

//Testing all endpoints with fake vcert CA
func TestFakeEndpoints(t *testing.T) {
	integrationTestEnv, err := NewIntegrationTestEnv()
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
	integrationTestEnv, err := NewIntegrationTestEnv()
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

func NewIntegrationTestEnv() (*testEnv, error) {
	ctx := context.Background()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	var err error
	b := Backend(config)
	err = b.Setup(context.Background(), config)
	if err != nil {
		return nil, err
	}

	return &testEnv{
		Backend:          b,
		Context:          ctx,
		Storage:          config.StorageView,
		TestRandString:   util.RandRunes(9),
		RoleName:         util.RandRunes(9) + "-role",
		VenafiSecretName: util.RandRunes(9) + "-venafi",
	}, nil
}
