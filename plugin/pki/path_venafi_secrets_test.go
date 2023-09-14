package pki

import (
	"testing"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/util"
)

func TestVenafiSecretValidate(t *testing.T) {
	entry := &venafiSecretEntry{}

	err := validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextInvalidMode {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextInvalidMode, err)
	}

	entry = &venafiSecretEntry{
		AccessToken: "foo123bar==",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextURLEmpty {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextURLEmpty, err)
	}

	entry = &venafiSecretEntry{
		URL:         "https://ha-tpp12.sqlha.com:5008/vedsdk",
		AccessToken: "foo123bar==",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextZoneEmpty {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextZoneEmpty, err)
	}

	entry = &venafiSecretEntry{
		URL:         "https://qa-tpp.exmple.com/vedsdk",
		Zone:        "devops\\vcert",
		Apikey:      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TppUser:     "admin",
		TppPassword: "xxxx",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextMixedTPPAndCloud {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextMixedTPPAndCloud, err)
	}

	entry = &venafiSecretEntry{
		URL:         "https://qa-tpp.exmple.com/vedsdk",
		Zone:        "devops\\vcert",
		AccessToken: "foo123bar==",
		TppUser:     "admin",
		TppPassword: "xxxx",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextMixedTPPAndToken {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextMixedTPPAndToken, err)
	}

	entry = &venafiSecretEntry{
		URL:         "https://qa-tpp.exmple.com/vedsdk",
		Zone:        "devops\\vcert",
		AccessToken: "foo123bar==",
		Apikey:      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextMixedTokenAndCloud {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextMixedTokenAndCloud, err)
	}
}
