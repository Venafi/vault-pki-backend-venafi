package pki

import (
	"testing"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/util"
)

func TestSHA1SUM(t *testing.T) {
	// Known SHA1SUM value of "hello"
	// echo -n "hello" | sha1sum
	SHA1SUMstringValue := "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"

	s := "hello"
	SHA1SUMvalue := util.Sha1sum(s)
	if SHA1SUMstringValue != SHA1SUMvalue {
		t.Fatalf("sha1sum function is not outputting expected value")
	}
}
