package pki

import (
	"testing"
)

func TestRoleValidate(t *testing.T) {

	entry := &roleEntry{
		TPPURL: "https://ha-tpp12.sqlha.com:5008/vedsdk",
	}

	err, entry := validateEntry(entry)
	if err.Error() != errorTextInvalidMode {
		t.Fatalf("Expecting error %s but got %s", errorTextInvalidMode, err)
	}

	entry = &roleEntry{
		TPPURL: "https://ha-tpp12.sqlha.com:5008/vedsdk",
		TPPUser: "admin",
		TPPPassword: "xxxx",
		TTL: 120,
		MaxTTL: 100,
	}

	err, entry = validateEntry(entry)
	if err.Error() != errorTextValueMustBeLess {
		t.Fatalf("Expecting error %s but got %s", errorTextValueMustBeLess, err)
	}
}
