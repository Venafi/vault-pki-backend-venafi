package pki

import (
	"fmt"
	"testing"
)

func TestRoleValidate(t *testing.T) {

	entry := &roleEntry{}

	err := validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextVenafiSecretEmpty {
		t.Fatalf("Expecting error %s but got %s", errorTextInvalidMode, err)
	}

	entry = &roleEntry{
		VenafiSecret: "testSecret",
	}

	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextZoneEmpty {
		t.Fatalf("Expecting error %s but got %s", errorTextZoneEmpty, err)
	}

	entry = &roleEntry{
		VenafiSecret: "testSecret",
		Zone:         "devops\\vcert",
		TTL:          120,
		MaxTTL:       100,
	}

	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextValueMustBeLess {
		t.Fatalf("Expecting error %s but got %s", errorTextValueMustBeLess, err)
	}

	entry = &roleEntry{
		VenafiSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Zone:         "devops\\vcert",
		StoreByCN:    true,
		StoreBy:      "cn",
	}
	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextStoreByAndStoreByCNOrSerialConflict {
		t.Fatalf("Expecting error %s but got %s", errorTextStoreByAndStoreByCNOrSerialConflict, err)
	}

	entry = &roleEntry{
		VenafiSecret:  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Zone:          "devops\\vcert",
		StoreBySerial: true,
		StoreBy:       "cn",
	}
	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextStoreByAndStoreByCNOrSerialConflict {
		t.Fatalf("Expecting error %s but got %s", errorTextStoreByAndStoreByCNOrSerialConflict, err)
	}

	entry = &roleEntry{
		VenafiSecret:  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Zone:          "devops\\vcert",
		StoreBySerial: true,
		StoreByCN:     true,
		StoreBy:       "cn",
	}
	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextStoreByAndStoreByCNOrSerialConflict {
		t.Fatalf("Expecting error %s but got %s", errorTextStoreByAndStoreByCNOrSerialConflict, err)
	}

	entry = &roleEntry{
		VenafiSecret:  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Zone:          "devops\\vcert",
		StoreBySerial: true,
		StoreByCN:     true,
		NoStore:       true,
	}
	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextNoStoreAndStoreByCNOrSerialConflict {
		t.Fatalf("Expecting error %s but got %s", errorTextNoStoreAndStoreByCNOrSerialConflict, err)
	}

	entry = &roleEntry{
		VenafiSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Zone:         "devops\\vcert",
		StoreBy:      "serial",
		NoStore:      true,
	}
	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextNoStoreAndStoreByConflict {
		t.Fatalf("Expecting error %s but got %s", errorTextNoStoreAndStoreByConflict, err)
	}

	entry = &roleEntry{
		VenafiSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Zone:         "devops\\vcert",
		StoreBy:      "sebial",
	}
	err = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	expectingError := fmt.Sprintf(errTextStoreByWrongOption, storeBySerialString, storeByCNString, "sebial")
	if err.Error() != expectingError {
		t.Fatalf("Expecting error %s but got %s", expectingError, err)
	}

	entry = &roleEntry{
		VenafiSecret:  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Zone:          "devops\\vcert",
		StoreBySerial: true,
		StoreByCN:     true,
	}
	err = validateEntry(entry)
	if err != nil {
		t.Fatal(err)
	}

	if entry.StoreBy != storeBySerialString {
		t.Fatalf("Expecting store_by parameter will be set to %s", storeBySerialString)
	}

	entry = &roleEntry{
		VenafiSecret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Zone:         "devops\\vcert",
		StoreByCN:    true,
	}
	err = validateEntry(entry)
	if err != nil {
		t.Fatal(err)
	}

	if entry.StoreBy != storeByCNString {
		t.Fatalf("Expecting store_by parameter will be set to %s", storeByCNString)
	}
}
