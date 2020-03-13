package pki

import (
	"fmt"
	"testing"
)

func TestRoleValidate(t *testing.T) {

	entry := &roleEntry{
		TPPURL: "https://ha-tpp12.sqlha.com:5008/vedsdk",
	}

	err, entry := validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextInvalidMode {
		t.Fatalf("Expecting error %s but got %s", errorTextInvalidMode, err)
	}

	entry = &roleEntry{
		TPPURL:      "https://qa-tpp.exmple.com/vedsdk",
		TPPUser:     "admin",
		TPPPassword: "xxxx",
		TTL:         120,
		MaxTTL:      100,
	}

	err, entry = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextValueMustBeLess {
		t.Fatalf("Expecting error %s but got %s", errorTextValueMustBeLess, err)
	}

	entry = &roleEntry{
		TPPURL:      "https://qa-tpp.exmple.com/vedsdk",
		Apikey:      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TPPUser:     "admin",
		TPPPassword: "xxxx",
	}

	err, entry = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextTPPandCloudMixedCredentials {
		t.Fatalf("Expecting error %s but got %s", errorTextTPPandCloudMixedCredentials, err)
	}

	entry = &roleEntry{
		Apikey:    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreByCN: true,
		StoreBy:   "cn",
	}
	err, entry = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextStoreByAndStoreByCNOrSerialConflict {
		t.Fatalf("Expecting error %s but got %s", errorTextStoreByAndStoreByCNOrSerialConflict, err)
	}

	entry = &roleEntry{
		Apikey:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreBySerial: true,
		StoreBy:       "cn",
	}
	err, entry = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextStoreByAndStoreByCNOrSerialConflict {
		t.Fatalf("Expecting error %s but got %s", errorTextStoreByAndStoreByCNOrSerialConflict, err)
	}

	entry = &roleEntry{
		Apikey:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreBySerial: true,
		StoreByCN:     true,
		StoreBy:       "cn",
	}
	err, entry = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextStoreByAndStoreByCNOrSerialConflict {
		t.Fatalf("Expecting error %s but got %s", errorTextStoreByAndStoreByCNOrSerialConflict, err)
	}

	entry = &roleEntry{
		Apikey:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreBySerial: true,
		StoreByCN:     true,
		NoStore:       true,
	}
	err, entry = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextNoStoreAndStoreByCNOrSerialConflict {
		t.Fatalf("Expecting error %s but got %s", errorTextNoStoreAndStoreByCNOrSerialConflict, err)
	}

	entry = &roleEntry{
		Apikey:  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreBy: "serial",
		NoStore: true,
	}
	err, entry = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextNoStoreAndStoreByConflict {
		t.Fatalf("Expecting error %s but got %s", errorTextNoStoreAndStoreByConflict, err)
	}

	entry = &roleEntry{
		Apikey:  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreBy: "sebial",
	}
	err, entry = validateEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	expectingError := fmt.Sprintf(errTextStoreByWrongOption, storeBySerialString, storeByCNString, "sebial")
	if err.Error() != expectingError {
		t.Fatalf("Expecting error %s but got %s", expectingError, err)
	}

	entry = &roleEntry{
		Apikey:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreBySerial: true,
		StoreByCN:     true,

	}
	err, entry = validateEntry(entry)
	if err != nil {
		t.Fatal(err)
	}

	if entry.StoreBy != storeBySerialString {
		t.Fatalf("Expecting store_by parameter will be set to %s", storeBySerialString)
	}

	entry = &roleEntry{
		Apikey:        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		StoreByCN:     true,

	}
	err, entry = validateEntry(entry)
	if err != nil {
		t.Fatal(err)
	}

	if entry.StoreBy != storeByCNString {
		t.Fatalf("Expecting store_by parameter will be set to %s", storeBySerialString)
	}
}
