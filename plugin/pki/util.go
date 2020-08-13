package pki

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/Venafi/vcert/pkg/venafi/tpp"
	"github.com/hashicorp/vault/logical"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
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
	TPPTestingEnabled   bool
	CloudTestingEnabled bool
	FakeTestingEnabled  bool
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
	c.TPPTestingEnabled, _ = strconv.ParseBool(os.Getenv("VENAFI_TPP_TESTING"))
	c.CloudTestingEnabled, _ = strconv.ParseBool(os.Getenv("VENAFI_CLOUD_TESTING"))
	c.FakeTestingEnabled, _ = strconv.ParseBool(os.Getenv("VENAFI_FAKE_TESTING"))
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

func getTppConnector(cfg *vcert.Config) (*tpp.Connector, error) {

	var connectionTrustBundle *x509.CertPool
	if cfg.ConnectionTrust != "" {
		connectionTrustBundle = x509.NewCertPool()
		if !connectionTrustBundle.AppendCertsFromPEM([]byte(cfg.ConnectionTrust)) {
			return nil, fmt.Errorf("Failed to parse PEM trust bundle")
		}
	}
	tppConnector, err := tpp.NewConnector(cfg.BaseUrl, "", cfg.LogVerbose, connectionTrustBundle)
	if err != nil {
		return nil, fmt.Errorf("could not create TPP connector: %s", err)
	}

	return tppConnector, nil
}

func updateAccessToken(cfg *vcert.Config, b *backend, ctx context.Context, req *logical.Request, roleName string) error {
	tppConnector, _ := getTppConnector(cfg)

	resp, err := tppConnector.RefreshAccessToken(&endpoint.Authentication{
		RefreshToken: cfg.Credentials.RefreshToken,
		ClientId:     "hashicorp-vault-by-venafi",
		Scope:        "certificate:revoke",
	})
	if resp.Access_token != "" && resp.Refresh_token != "" {

		err := storeAccessData(b, ctx, req, roleName, resp)
		if err != nil {
			return err
		}

	} else {
		return err
	}
	return nil
}

func storeAccessData(b *backend, ctx context.Context, req *logical.Request, roleName string, resp tpp.OauthRefreshAccessTokenResponse) error {
	entry, err := b.getRole(ctx, req.Storage, roleName)

	if err != nil {
		return err
	}

	if entry.VenafiSecret == "" {
		return fmt.Errorf("Role " + roleName + " does not have any Venafi secret associated")
	}

	venafiEntry, err := b.getCredentials(ctx, req.Storage, entry.VenafiSecret)
	if err != nil {
		return err
	}

	venafiEntry.AccessToken = resp.Access_token
	venafiEntry.RefreshToken = resp.Refresh_token

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
