package pki

import (
	"testing"
)

func TestOriginInRequest(t *testing.T)  {
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

	err, certReq := formRequest(data, &role, signCSR, integrationTestEnv.Backend.Logger())
	if certReq.CustomFields[0].Value != utilityName {
		t.Fatalf("Expected %s in request custom fields origin", utilityName)
	}
}
