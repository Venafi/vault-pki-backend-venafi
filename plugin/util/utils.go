package util

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	mathrand "math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/youmark/pkcs8"
)

func SliceContains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

func GetHexFormatted(buf []byte, sep string) (string, error) {
	var ret bytes.Buffer
	for _, cur := range buf {
		if ret.Len() > 0 {
			if _, err := fmt.Fprint(&ret, sep); err != nil {
				return "", err
			}
		}
		if _, err := fmt.Fprintf(&ret, "%02x", cur); err != nil {
			return "", err
		}
	}
	return ret.String(), nil
}

// AddSeparatorToHexFormattedString gets a hexadecimal string and adds colon (:) every two characters
// it returns a string with a colon every two chracters and any error during the convertion process
// input: 6800b707811f0befb37f922b9e12f68eab8093
// output: 68:00:b7:07:81:1f:0b:ef:b3:7f:92:2b:9e:12:f6:8e:ab:80:93
func AddSeparatorToHexFormattedString(s string, sep string) (string, error) {
	var ret bytes.Buffer
	for n, v := range s {
		if n > 0 && n%2 == 0 {
			if _, err := fmt.Fprint(&ret, sep); err != nil {
				return "", err
			}
		}
		if _, err := fmt.Fprintf(&ret, "%c", v); err != nil {
			return "", err
		}
	}
	return ret.String(), nil
}

func NormalizeSerial(serial string) string {
	return strings.Replace(strings.ToLower(serial), ":", "-", -1)
}

func SameIpSlice(x, y []net.IP) bool {
	if len(x) != len(y) {
		return false
	}
	x1 := make([]string, len(x))
	y1 := make([]string, len(y))
	for i := range x {
		x1[i] = x[i].String()
		y1[i] = y[i].String()
	}
	sort.Strings(x1)
	sort.Strings(y1)
	for i := range x1 {
		if x1[i] != y1[i] {
			return false
		}
	}
	return true
}

func SameStringSlice(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	x1 := make([]string, len(x))
	y1 := make([]string, len(y))
	copy(x1, x)
	copy(y1, y)
	sort.Strings(x1)
	sort.Strings(y1)
	for i := range x1 {
		if x1[i] != y1[i] {
			return false
		}
	}
	return true
}

func GetStatusCode(msg string) int64 {

	var statusCode int64
	splittedMsg := strings.Split(msg, ":")

	for i := 0; i < len(splittedMsg); i++ {

		current := splittedMsg[i]
		current = strings.TrimSpace(current)

		if current == "Invalid status" {

			status := splittedMsg[i+1]
			status = strings.TrimSpace(status)
			splittedStatus := strings.Split(status, " ")
			statusCode, _ = strconv.ParseInt(splittedStatus[0], 10, 64)
			break

		}
	}

	return statusCode
}

func CopyMap(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{})
	for k, v := range m {
		vm, ok := v.(map[string]interface{})
		if ok {
			cp[k] = CopyMap(vm)
		} else {
			cp[k] = v
		}
	}

	return cp
}

func RandRunes(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, n)
	for i := range b {
		/* #nosec */
		b[i] = letterRunes[mathrand.Intn(len(letterRunes))]
	}
	return string(b)
}

func GetPrivateKey(keyBytes []byte, passphrase string) ([]byte, error) {
	// this section makes some small changes to code from notary/tuf/utils/x509.go
	pemBlock, _ := pem.Decode(keyBytes)
	if pemBlock == nil {
		return nil, errors.New("no valid private key found")
	}

	var err error
	if util.X509IsEncryptedPEMBlock(pemBlock) {
		keyBytes, err = util.X509DecryptPEMBlock(pemBlock, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("private key is encrypted, but could not decrypt it: %s", err.Error())
		}
		keyBytes = pem.EncodeToMemory(&pem.Block{Type: pemBlock.Type, Bytes: keyBytes})
	}

	return keyBytes, nil
}

func EncryptPrivateKey(privateKey string, password string) (string, error) {
	var encryptedPrivateKeyPem string
	var err error
	encryptedPrivateKeyPem, err = EncryptPkcs1PrivateKey(privateKey, password)
	if err != nil {
		// We try PKCS8
		encryptedPrivateKeyPem, err = encryptPkcs8PrivateKey(privateKey, password)
		if err != nil {
			return "", err
		}
	}
	return encryptedPrivateKeyPem, nil
}

func DecryptPkcs8PrivateKey(privateKey string, password string) (string, error) {

	block, _ := pem.Decode([]byte(privateKey))
	key, _, err := pkcs8.ParsePrivateKey(block.Bytes, []byte(password))

	if err != nil {
		return "", err
	}

	pemType := "PRIVATE KEY"

	privateKeyBytes, err := pkcs8.MarshalPrivateKey(key, nil, nil)

	if err != nil {
		return "", err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: privateKeyBytes})

	return string(pemBytes), nil
}

func EncryptPkcs1PrivateKey(privateKey string, password string) (string, error) {

	block, _ := pem.Decode([]byte(privateKey))

	keyType := util.GetPrivateKeyType(privateKey, password)
	var encrypted *pem.Block
	var err error
	if keyType == "RSA PRIVATE KEY" {
		encrypted, err = util.X509EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", block.Bytes, []byte(password), util.PEMCipherAES256)
		if err != nil {
			return "", nil
		}
	} else if keyType == "EC PRIVATE KEY" {
		encrypted, err = util.X509EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", block.Bytes, []byte(password), util.PEMCipherAES256)
		if err != nil {
			return "", nil
		}
	} else {
		return "", errors.New("unable to encrypt key in PKCS1 format")
	}
	return string(pem.EncodeToMemory(encrypted)), nil
}

func encryptPkcs8PrivateKey(privateKey string, password string) (string, error) {
	block, _ := pem.Decode([]byte(privateKey))
	key, _, err := pkcs8.ParsePrivateKey(block.Bytes, []byte(""))
	if err != nil {
		return "", err
	}
	privateKeyBytes1, err := pkcs8.MarshalPrivateKey(key, []byte(password), nil)
	if err != nil {
		return "", err
	}

	keyType := "ENCRYPTED PRIVATE KEY"

	// Generate a pem block with the private key
	keyPemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  keyType,
		Bytes: privateKeyBytes1,
	})
	encryptedPrivateKeyPem := string(keyPemBytes)
	return encryptedPrivateKeyPem, nil
}

// ShortDurationString will trim
func ShortDurationString(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func Sha1sum(s string) string {
	//nolint
	hash := sha1.New()
	buffer := []byte(s)
	hash.Write(buffer)
	return hex.EncodeToString(hash.Sum(nil))
}

// we may want to enhance this function when we update to Go 1.18, since generics are only supported starting from that version
func RemoveDuplicateStr(strSlice *[]string) {
	allKeys := make(map[string]bool)
	var list []string
	for _, item := range *strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	*strSlice = list
}

func StringSlicesEqual(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func AreDNSNamesCorrect(actualAltNames []string, expectedCNNames []string, expectedAltNames []string) bool {

	//There is no cn names. Check expectedAltNames only. Is it possible?
	if len(expectedCNNames) == 0 {
		if len(actualAltNames) != len(expectedAltNames) {
			return false

		} else if !SameStringSlice(actualAltNames, expectedAltNames) {
			return false
		}
	} else {

		if len(actualAltNames) < len(expectedAltNames) {
			return false
		}

		for i := range expectedAltNames {
			expectedName := expectedAltNames[i]
			found := false

			for j := range actualAltNames {

				if actualAltNames[j] == expectedName {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}

		//Checking expectedCNNames
		allNames := append(expectedAltNames, expectedCNNames...)
		for i := range actualAltNames {
			name := actualAltNames[i]
			found := false

			for j := range allNames {

				if allNames[j] == name {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}

	}

	return true
}
