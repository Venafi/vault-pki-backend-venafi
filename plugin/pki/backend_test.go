package pki

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"
	"os"
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

func TestPKI_CloudEnrollWithPassword(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.provider = "cloud"

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
		Logger: hclog.NewNullLogger(),
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	var err error
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("pki/roles/example", map[string]interface{}{
		"generate_lease": true,
		"cloud_url":      os.Getenv("CLOUDURL"),
		"zone":           os.Getenv("CLOUDZONE"),
		"apikey":         os.Getenv("CLOUDAPIKEY"),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Logical().Write("pki/issue/example", map[string]interface{}{
		"common_name":  data.cn,
		"key_password": "password",
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Data["certificate"] == "" {
		t.Fatalf("expected a cert to be generated")
	}

	data.cert = resp.Data["certificate"].(string)
	encryptedKey := resp.Data["private_key"].(string)
	b, _ := pem.Decode([]byte(encryptedKey))
	b.Bytes, err = x509.DecryptPEMBlock(b, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	data.private_key = string(pem.EncodeToMemory(b))
	checkStandartCert(t, data)
}
