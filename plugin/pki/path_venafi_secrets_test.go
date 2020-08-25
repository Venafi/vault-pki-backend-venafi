package pki

import "testing"

func TestVenafiSecretValidate(t *testing.T) {
	entry := &venafiSecretEntry{}

	err := validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextInvalidMode {
		t.Fatalf("Expecting error %s but got %s", errorTextInvalidMode, err)
	}

	entry = &venafiSecretEntry{
		AccessToken: "foo123bar==",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextURLEmpty {
		t.Fatalf("Expecting error %s but got %s", errorTextURLEmpty, err)
	}

	entry = &venafiSecretEntry{
		URL:         "https://ha-tpp12.sqlha.com:5008/vedsdk",
		AccessToken: "foo123bar==",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextZoneEmpty {
		t.Fatalf("Expecting error %s but got %s", errorTextZoneEmpty, err)
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
	if err.Error() != errorTextMixedTPPAndCloud {
		t.Fatalf("Expecting error %s but got %s", errorTextMixedTPPAndCloud, err)
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
	if err.Error() != errorTextMixedTPPAndToken {
		t.Fatalf("Expecting error %s but got %s", errorTextMixedTPPAndToken, err)
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
	if err.Error() != errorTextMixedTokenAndCloud {
		t.Fatalf("Expecting error %s but got %s", errorTextMixedTokenAndCloud, err)
	}
}
