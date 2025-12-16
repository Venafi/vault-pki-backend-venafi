package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi/tpp"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/pki/vpkierror"
	"github.com/Venafi/vault-pki-backend-venafi/plugin/util"
)

const (
	HTTP_UNAUTHORIZED = 401
	LEGACY_PEM        = "der"
)

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
	ClientId            string
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
	c.ClientId = os.Getenv("TPP_CLIENT_ID")

	c.TPPTestingEnabled, _ = strconv.ParseBool(os.Getenv("VENAFI_TPP_TESTING"))
	c.CloudTestingEnabled, _ = strconv.ParseBool(os.Getenv("VENAFI_CLOUD_TESTING"))
	c.FakeTestingEnabled, _ = strconv.ParseBool(os.Getenv("VENAFI_FAKE_TESTING"))
	c.TokenTestingEnabled, _ = strconv.ParseBool(os.Getenv("VENAFI_TPP_TOKEN_TESTING"))

	c.TPPIssuerCN = os.Getenv("TPP_ISSUER_CN")
	c.CloudIssuerCN = os.Getenv("CLOUD_ISSUER_CN")
	c.FakeIssuerCN = os.Getenv("FAKE_ISSUER_CN")

	return &c
}

func getTppConnector(cfg *vcert.Config) (*tpp.Connector, error) {

	var connectionTrustBundle *x509.CertPool
	if cfg.ConnectionTrust != "" {
		connectionTrustBundle = x509.NewCertPool()
		if !connectionTrustBundle.AppendCertsFromPEM([]byte(cfg.ConnectionTrust)) {
			return nil, errors.New("failed to parse PEM trust bundle")
		}
	}
	tppConnector, err := tpp.NewConnector(cfg.BaseUrl, "", cfg.LogVerbose, connectionTrustBundle)
	if err != nil {
		return nil, fmt.Errorf("could not create Certificate Manager, Self-Hosted connector: %s", err)
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

	b.Logger().Info("Verifying again if token still needs refresh")
	refreshNeeded, refreshToken, err := isTokenRefreshNeeded(b, ctx, req.Storage, role.VenafiSecret)
	if err != nil {
		return err
	}
	if !refreshNeeded {
		b.Logger().Info("Refresh is not needed. Another process updated the tokens already")
		return nil // we're done, another thread beat us to it
	}

	tppConnector, _ := getTppConnector(cfg)

	var httpClient *http.Client
	httpClient, err = getHTTPClient(cfg.ConnectionTrust)
	if err != nil {
		return err
	}

	tppConnector.SetHTTPClient(httpClient)

	b.Logger().Info("Refreshing access_token")
	var resp tpp.OauthRefreshAccessTokenResponse
	resp, err = tppConnector.RefreshAccessToken(&endpoint.Authentication{
		RefreshToken: refreshToken,
		ClientId:     cfg.Credentials.ClientId,
		Scope:        "certificate:manage,revoke",
	})
	if resp.Access_token != "" && resp.Refresh_token != "" {
		b.Logger().Info("Storing new token")
		err = storeAccessData(b, ctx, req, role, resp)
	}
	return err
}

func storeAccessData(b *backend, ctx context.Context, req *logical.Request, role *roleEntry, resp tpp.OauthRefreshAccessTokenResponse) error {

	if role.VenafiSecret == "" {
		return fmt.Errorf("Role %s does not have any CyberArk secret associated", role.Name)
	}

	venafiEntry, err := b.getVenafiSecret(ctx, req.Storage, role.VenafiSecret)
	if err != nil {
		return err
	}

	b.Logger().Info("swapping tokens")
	venafiEntry.RefreshToken2 = venafiEntry.RefreshToken
	b.Logger().Info("setting new access_token")
	venafiEntry.AccessToken = resp.Access_token
	b.Logger().Info("setting new refresh_token")
	venafiEntry.RefreshToken = resp.Refresh_token
	venafiEntry.NextRefresh = time.Now().Add(venafiEntry.RefreshInterval)
	b.Logger().Info(fmt.Sprintf("Setting new time refresh: %s", venafiEntry.NextRefresh.String()))
	// Store it
	b.Logger().Info("preparing tokens for storage")
	jsonEntry, err := logical.StorageEntryJSON(util.CredentialsRootPath+role.VenafiSecret, venafiEntry)

	if err != nil {
		b.Logger().Error("Error on creating new tokens into CyberArk secret:", err.Error())
		return err
	}
	b.Logger().Info("storing new tokens")
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		b.Logger().Error("Error on storing new tokens into CyberArk secret:", err.Error())
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
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
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
			return nil, errors.New("failed to parse PEM trust bundle")
		}
	} else {
		return nil, errors.New("trust bundle PEM data is empty")
	}

	return connectionTrustBundle, nil
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
		ClientId:     data.ClientId,
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
		ClientId:     cfg.Credentials.ClientId,
		Scope:        "certificate:manage,revoke",
	})

	return tokenInfoResponse, err

}

func loadCertificateFromStorage(b *backend, ctx context.Context, req *logical.Request, certUID string, keyPassword string) (cert *VenafiCert, err error) {
	path := "certs/" + certUID

	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CyberArk certificate: %s", err)
	}
	if entry == nil {
		return nil, vpkierror.CertEntryNotFound{EntryPath: path}
	}

	b.Logger().Info(fmt.Sprintf("Getting CyberArk certificate from storage with ID: %v", certUID))

	if err := entry.DecodeJSON(&cert); err != nil {
		return nil, fmt.Errorf("error reading CyberArk configuration: %s", err.Error())
	}
	b.Logger().Debug("certificate is:" + cert.Certificate)
	b.Logger().Debug("chain is:" + cert.CertificateChain)

	if keyPassword != "" {
		encryptedPrivateKeyPem, err := util.EncryptPrivateKey(cert.PrivateKey, keyPassword)
		if err != nil {
			return nil, fmt.Errorf("error opening private key: %s", err.Error())
		}
		cert.PrivateKey = encryptedPrivateKeyPem
	}
	return cert, nil
}
