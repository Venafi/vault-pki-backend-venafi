package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	//nolint // ignoring since we don't expect to use complex hashing
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/pki/vpkierror"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/util"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/youmark/pkcs8"
)

const (
	role_ttl_test_property = int(120)
	ttl_test_property      = int(48)
	HTTP_UNAUTHORIZED      = 401
	LEGACY_PEM             = "der"
)

func sliceContains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

func getHexFormatted(buf []byte, sep string) (string, error) {
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

// addSeparatorToHexFormattedString gets a hexadecimal string and adds colon (:) every two characters
// it returns a string with a colon every two chracters and any error during the convertion process
// input: 6800b707811f0befb37f922b9e12f68eab8093
// output: 68:00:b7:07:81:1f:0b:ef:b3:7f:92:2b:9e:12:f6:8e:ab:80:93
func addSeparatorToHexFormattedString(s string, sep string) (string, error) {
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

func normalizeSerial(serial string) string {
	return strings.Replace(strings.ToLower(serial), ":", "-", -1)
}

type RunContext struct {
	TPPurl              string
	TPPuser             string
	TPPPassword         string
	TPPZone             string
	CloudUrl            string
	CloudAPIkey         string
	CloudZone           string
	TokenUrl            string
	AccessToken         string
	TPPTestingEnabled   bool
	CloudTestingEnabled bool
	FakeTestingEnabled  bool
	TokenTestingEnabled bool
	TPPIssuerCN         string
	CloudIssuerCN       string
	FakeIssuerCN        string
}

func GetContext() *RunContext {

	c := RunContext{}

	c.TPPurl = os.Getenv("TPP_URL")
	c.TPPuser = os.Getenv("TPP_USER")
	c.TPPPassword = os.Getenv("TPP_PASSWORD")
	c.TPPZone = os.Getenv("TPP_ZONE")

	c.CloudUrl = os.Getenv("CLOUD_URL")
	c.CloudAPIkey = os.Getenv("CLOUD_APIKEY")
	c.CloudZone = os.Getenv("CLOUD_ZONE")

	c.TokenUrl = os.Getenv("TPP_TOKEN_URL")
	c.AccessToken = os.Getenv("ACCESS_TOKEN")

	c.TPPTestingEnabled, _ = strconv.ParseBool(os.Getenv("VENAFI_TPP_TESTING"))
	c.CloudTestingEnabled, _ = strconv.ParseBool(os.Getenv("VENAFI_CLOUD_TESTING"))
	c.FakeTestingEnabled, _ = strconv.ParseBool(os.Getenv("VENAFI_FAKE_TESTING"))
	c.TokenTestingEnabled, _ = strconv.ParseBool(os.Getenv("VENAFI_TPP_TOKEN_TESTING"))

	c.TPPIssuerCN = os.Getenv("TPP_ISSUER_CN")
	c.CloudIssuerCN = os.Getenv("CLOUD_ISSUER_CN")
	c.FakeIssuerCN = os.Getenv("FAKE_ISSUER_CN")

	return &c
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

func areDNSNamesCorrect(actualAltNames []string, expectedCNNames []string, expectedAltNames []string) bool {

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

func getTppConnector(cfg *vcert.Config) (*tpp.Connector, error) {

	var connectionTrustBundle *x509.CertPool
	if cfg.ConnectionTrust != "" {
		connectionTrustBundle = x509.NewCertPool()
		if !connectionTrustBundle.AppendCertsFromPEM([]byte(cfg.ConnectionTrust)) {
			return nil, fmt.Errorf("failed to parse PEM trust bundle")
		}
	}
	tppConnector, err := tpp.NewConnector(cfg.BaseUrl, "", cfg.LogVerbose, connectionTrustBundle)
	if err != nil {
		return nil, fmt.Errorf("could not create TPP connector: %s", err)
	}

	return tppConnector, nil
}

func isTokenRefreshNeeded(b *backend, ctx context.Context, storage logical.Storage, secretName string) (bool, string, error) {
	secretEntry, err := b.getVenafiSecret(ctx, storage, secretName)
	if err != nil {
		return false, "", err
	}

	return secretEntry.NextRefresh.Before(time.Now()), secretEntry.RefreshToken2, nil
}

func updateAccessToken(b *backend, ctx context.Context, req *logical.Request, cfg *vcert.Config, role *roleEntry) error {
	b.mux.Lock()
	defer b.mux.Unlock()

	refreshNeeded, refreshToken, err := isTokenRefreshNeeded(b, ctx, req.Storage, role.VenafiSecret)
	if err != nil {
		return err
	}
	if !refreshNeeded {
		return nil // we're done, another thread beat us to it
	}

	tppConnector, _ := getTppConnector(cfg)

	var httpClient *http.Client
	httpClient, err = getHTTPClient(cfg.ConnectionTrust)
	if err != nil {
		return err
	}

	tppConnector.SetHTTPClient(httpClient)

	b.Logger().Debug("Refreshing token")
	var resp tpp.OauthRefreshAccessTokenResponse
	resp, err = tppConnector.RefreshAccessToken(&endpoint.Authentication{
		RefreshToken: refreshToken,
		ClientId:     "hashicorp-vault-by-venafi",
		Scope:        "certificate:manage,revoke",
	})
	if resp.Access_token != "" && resp.Refresh_token != "" {
		err = storeAccessData(b, ctx, req, role.Name, resp)
	}
	return err
}

func storeAccessData(b *backend, ctx context.Context, req *logical.Request, roleName string, resp tpp.OauthRefreshAccessTokenResponse) error {
	entry, err := b.getRole(ctx, req.Storage, roleName)

	if err != nil {
		return err
	}

	if entry.VenafiSecret == "" {
		return fmt.Errorf("Role " + roleName + " does not have any Venafi secret associated")
	}

	venafiEntry, err := b.getVenafiSecret(ctx, req.Storage, entry.VenafiSecret)
	if err != nil {
		return err
	}

	venafiEntry.RefreshToken2 = venafiEntry.RefreshToken
	venafiEntry.AccessToken = resp.Access_token
	venafiEntry.RefreshToken = resp.Refresh_token
	venafiEntry.NextRefresh = time.Now().Add(venafiEntry.RefreshInterval)

	// Store it
	jsonEntry, err := logical.StorageEntryJSON(CredentialsRootPath+entry.VenafiSecret, venafiEntry)
	if err != nil {
		return err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return err
	}
	return nil
}

func getHTTPClient(trustBundlePem string) (*http.Client, error) {

	var netTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	tlsConfig := http.DefaultTransport.(*http.Transport).TLSClientConfig

	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}

	/* #nosec */
	if trustBundlePem != "" {
		trustBundle, err := parseTrustBundlePEM(trustBundlePem)
		if err != nil {
			return nil, err
		}

		tlsConfig.RootCAs = trustBundle
	}

	tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient
	netTransport.TLSClientConfig = tlsConfig

	client := &http.Client{
		Timeout:   time.Second * 30,
		Transport: netTransport,
	}
	return client, nil
}

func parseTrustBundlePEM(trustBundlePem string) (*x509.CertPool, error) {
	var connectionTrustBundle *x509.CertPool

	if trustBundlePem != "" {
		connectionTrustBundle = x509.NewCertPool()
		if !connectionTrustBundle.AppendCertsFromPEM([]byte(trustBundlePem)) {
			return nil, fmt.Errorf("failed to parse PEM trust bundle")
		}
	} else {
		return nil, fmt.Errorf("trust bundle PEM data is empty")
	}

	return connectionTrustBundle, nil
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{})
	for k, v := range m {
		vm, ok := v.(map[string]interface{})
		if ok {
			cp[k] = copyMap(vm)
		} else {
			cp[k] = v
		}
	}

	return cp
}

func getStatusCode(msg string) int64 {

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

func createConfigFromFieldData(data *venafiSecretEntry) (*vcert.Config, error) {

	cfg := &vcert.Config{}

	cfg.BaseUrl = data.URL
	cfg.Zone = data.Zone
	cfg.LogVerbose = true

	trustBundlePath := data.TrustBundleFile

	if trustBundlePath != "" {

		var trustBundlePEM string
		trustBundle, err := ioutil.ReadFile(trustBundlePath)

		if err != nil {
			return cfg, err
		}

		trustBundlePEM = string(trustBundle)
		cfg.ConnectionTrust = trustBundlePEM
	}

	cfg.ConnectorType = endpoint.ConnectorTypeTPP

	cfg.Credentials = &endpoint.Authentication{

		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
	}

	return cfg, nil
}

func getAccessData(cfg *vcert.Config) (tpp.OauthRefreshAccessTokenResponse, error) {

	var tokenInfoResponse tpp.OauthRefreshAccessTokenResponse
	tppConnector, _ := getTppConnector(cfg)
	httpClient, err := getHTTPClient(cfg.ConnectionTrust)

	if err != nil {
		return tokenInfoResponse, err
	}

	tppConnector.SetHTTPClient(httpClient)

	tokenInfoResponse, err = tppConnector.RefreshAccessToken(&endpoint.Authentication{
		RefreshToken: cfg.Credentials.RefreshToken,
		ClientId:     "hashicorp-vault-by-venafi",
		Scope:        "certificate:manage,revoke",
	})

	return tokenInfoResponse, err

}

func randRunes(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, n)
	for i := range b {
		/* #nosec */
		b[i] = letterRunes[mathrand.Intn(len(letterRunes))]
	}
	return string(b)
}

func getPrivateKey(keyBytes []byte, passphrase string) ([]byte, error) {
	// this section makes some small changes to code from notary/tuf/utils/x509.go
	pemBlock, _ := pem.Decode(keyBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("no valid private key found")
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

func encryptPrivateKey(privateKey string, password string) (string, error) {
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
		return "", fmt.Errorf("unable to encrypt key in PKCS1 format")
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

func loadCertificateFromStorage(b *backend, ctx context.Context, req *logical.Request, certUID string, keyPassword string) (cert *VenafiCert, err error) {
	path := "certs/" + certUID

	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read Venafi certificate: %s", err)
	}
	if entry == nil {
		return nil, vpkierror.CertEntryNotFound{EntryPath: path}
	}

	b.Logger().Info(fmt.Sprintf("Getting venafi certificate from storage with ID: %v", certUID))

	if err := entry.DecodeJSON(&cert); err != nil {
		return nil, fmt.Errorf("error reading venafi configuration: %s", err.Error())
	}
	b.Logger().Debug("certificate is:" + cert.Certificate)
	b.Logger().Debug("chain is:" + cert.CertificateChain)

	if keyPassword != "" {
		encryptedPrivateKeyPem, err := encryptPrivateKey(cert.PrivateKey, keyPassword)
		if err != nil {
			return nil, fmt.Errorf("error opening private key: %s", err.Error())
		}
		cert.PrivateKey = encryptedPrivateKeyPem
	}
	return cert, nil
}

// shortDurationString will trim
func shortDurationString(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func sha1sum(s string) string {
	//nolint
	hash := sha1.New()
	buffer := []byte(s)
	hash.Write(buffer)
	return hex.EncodeToString(hash.Sum(nil))
}

// we may want to enhance this function when we update to Go 1.18, since generics are only supported starting from that version
func removeDuplicateStr(strSlice *[]string) {
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

func stringSlicesEqual(a []string, b []string) bool {
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
