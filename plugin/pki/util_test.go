package pki

import (
	"testing"
)

func TestSHA1SUM(t *testing.T) {
	// Known SHA1SUM value of "hello"
	// echo -n "hello" | sha1sum
	SHA1SUMstringValue := "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"

	s := "hello"
	SHA1SUMvalue := sha1sum(s)
	if SHA1SUMstringValue != SHA1SUMvalue {
		t.Fatalf("sha1sum function is not outputting expected value")
	}
}
