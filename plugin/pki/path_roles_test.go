package pki

import (
	"fmt"
	"testing"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/util"
)

func TestRoleValidate(t *testing.T) {

	entry := &roleEntry{}

	err := validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextVenafiSecretEmpty {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextInvalidMode, err)
	}

	entry = &roleEntry{
		VenafiSecret: "testSecret",
		TTL:          120,
		MaxTTL:       100,
	}

	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextValueMustBeLess {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextValueMustBeLess, err)
	}

	entry = &roleEntry{
		VenafiSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreByCN:    true,
		StoreBy:      "cn",
	}
	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextStoreByAndStoreByCNOrSerialConflict {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextStoreByAndStoreByCNOrSerialConflict, err)
	}

	entry = &roleEntry{
		VenafiSecret:  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreBySerial: true,
		StoreBy:       "cn",
	}
	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextStoreByAndStoreByCNOrSerialConflict {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextStoreByAndStoreByCNOrSerialConflict, err)
	}

	entry = &roleEntry{
		VenafiSecret:  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreBySerial: true,
		StoreByCN:     true,
		StoreBy:       "cn",
	}
	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextStoreByAndStoreByCNOrSerialConflict {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextStoreByAndStoreByCNOrSerialConflict, err)
	}

	entry = &roleEntry{
		VenafiSecret:  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreBySerial: true,
		StoreByCN:     true,
		NoStore:       true,
	}
	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextNoStoreAndStoreByCNOrSerialConflict {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextNoStoreAndStoreByCNOrSerialConflict, err)
	}

	entry = &roleEntry{
		VenafiSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreBy:      "serial",
		NoStore:      true,
	}
	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextNoStoreAndStoreByConflict {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextNoStoreAndStoreByConflict, err)
	}

	entry = &roleEntry{
		VenafiSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreBy:      "sebial",
	}
	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	expectingError := fmt.Sprintf(util.ErrTextStoreByWrongOption, util.StoreBySerialString, util.StoreByCNString, util.StoreByHASHstring, "sebial")
	if err.Error() != expectingError {
		t.Fatalf("Expecting error %s but got %s", expectingError, err)
	}

	entry = &roleEntry{
		VenafiSecret:  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreBySerial: true,
		StoreByCN:     true,
	}
	err = validateEntry(entry)
	if err != nil {
		t.Fatal(err)
	}

	if entry.StoreBy != util.StoreBySerialString {
		t.Fatalf("Expecting store_by parameter will be set to %s", util.StoreBySerialString)
	}

	entry = &roleEntry{
		VenafiSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreByCN:    true,
	}
	err = validateEntry(entry)
	if err != nil {
		t.Fatal(err)
	}

	if entry.StoreBy != util.StoreByCNString {
		t.Fatalf("Expecting store_by parameter will be set to %s", util.StoreByCNString)
	}
}
