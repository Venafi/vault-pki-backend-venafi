package pki

import (
	"github.com/Venafi/vcert/v4"
	"testing"
)

func TestOriginInRequest(t *testing.T) {
	integrationTestEnv, err := newIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	signCSR := false
	var data requestData
	var role roleEntry

	data.commonName = "tpp.example.com"
	role.KeyType = "rsa"
	role.ChainOption = "first"

	// The purpose of this test is to verify the customField Utility, regardless of connector Type
	cfg := &vcert.Config{}
	client, err := vcert.NewClient(cfg)

	certReq, err := formRequest(data, &role, &client, signCSR, integrationTestEnv.Backend.Logger())
	if certReq.CustomFields[0].Value != utilityName {
		t.Fatalf("Expected %s in request custom fields origin", utilityName)
	}
}
