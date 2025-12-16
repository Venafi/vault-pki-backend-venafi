package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/verror"
)

func (b *backend) ClientVenafi(ctx context.Context, req *logical.Request, role *roleEntry) (

	endpoint.Connector, *vcert.Config, error) {

	cfg, err := b.getConfig(ctx, req, role, false)
	if err != nil {
		return nil, nil, err
	}

	client, err := vcert.NewClient(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get CyberArk issuer client: %w", err)
	}

	return client, cfg, nil

}

func (b *backend) getConfig(ctx context.Context, req *logical.Request, role *roleEntry, includeRefreshToken bool) (*vcert.Config, error) {
	var cfg *vcert.Config

	venafiSecret, err := b.getVenafiSecret(ctx, req.Storage, role.VenafiSecret)
	if err != nil {
		return nil, err
	}
	if venafiSecret == nil {
		return nil, fmt.Errorf("unknown CyberArk secret %v", role.VenafiSecret)
	}

	var trustBundlePEM string
	if venafiSecret.TrustBundleFile != "" {
		b.Logger().Debug(fmt.Sprintf("Reading trust bundle from file: " + venafiSecret.TrustBundleFile))

		trustBundle, err := os.ReadFile(venafiSecret.TrustBundleFile)
		if err != nil {
			return cfg, err
		}
		trustBundlePEM = string(trustBundle)
	}

	// If the role has a Zone declared, it takes priority over the Zone in the CyberArk secret
	var zone string
	if role.Zone != "" {
		b.Logger().Debug(fmt.Sprintf("Using role zone: [%s]. Overrides CyberArk Secret zone: [%s]", role.Zone, venafiSecret.Zone))
		zone = role.Zone
	} else {
		b.Logger().Debug(fmt.Sprintf("Using CyberArk secret zone: [%s]. Role zone not found. ", venafiSecret.Zone))
		zone = venafiSecret.Zone
	}

	var netTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   role.ServerTimeout,
			KeepAlive: role.ServerTimeout,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	cfg = &vcert.Config{}
	cfg.BaseUrl = venafiSecret.URL
	cfg.Zone = zone
	cfg.LogVerbose = true
	if trustBundlePEM != "" {
		cfg.ConnectionTrust = trustBundlePEM
	}

	if venafiSecret.Fakemode {
		b.Logger().Debug("Using fakemode to issue certificate")
		cfg = &vcert.Config{
			ConnectorType: endpoint.ConnectorTypeFake,
			LogVerbose:    true,
		}

	} else if venafiSecret.URL != "" && venafiSecret.TppUser != "" && venafiSecret.TppPassword != "" {
		b.Logger().Debug(fmt.Sprintf("Using Certificate Manager, Self-Hosted with URL %s to issue certificate", venafiSecret.URL))
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		cfg.Credentials = &endpoint.Authentication{
			User:     venafiSecret.TppUser,
			Password: venafiSecret.TppPassword,
		}

	} else if venafiSecret.URL != "" && venafiSecret.AccessToken != "" {
		b.Logger().Debug(fmt.Sprintf("Using CyberArk Platform with URL %s to issue certificate", venafiSecret.URL))
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		var refreshToken string
		if includeRefreshToken {
			refreshToken = venafiSecret.RefreshToken
		}
		cfg.Credentials = &endpoint.Authentication{
			AccessToken:  venafiSecret.AccessToken,
			RefreshToken: refreshToken,
			ClientId:     venafiSecret.ClientId,
		}

	} else if venafiSecret.Apikey != "" {
		b.Logger().Debug("Using Certificate Manager, SaaS to issue certificate")
		cfg.ConnectorType = endpoint.ConnectorTypeCloud
		cfg.Credentials = &endpoint.Authentication{
			APIKey: venafiSecret.Apikey,
		}

	} else {
		return nil, errors.New("failed to build config for CyberArk issuer")
	}

	if role.ServerTimeout > 0 {
		cfg.Client = &http.Client{
			Timeout:   role.ServerTimeout,
			Transport: netTransport,
		}
	}

	var connectionTrustBundle *x509.CertPool

	if cfg.ConnectionTrust != "" {
		log.Println("Using trust bundle in custom http client")
		connectionTrustBundle = x509.NewCertPool()
		if !connectionTrustBundle.AppendCertsFromPEM([]byte(cfg.ConnectionTrust)) {
			return nil, fmt.Errorf("%w: failed to parse PEM trust bundle", verror.UserDataError)
		}
		netTransport.TLSClientConfig = &tls.Config{
			RootCAs:    connectionTrustBundle,
			MinVersion: tls.VersionTLS12,
		}
		cfg.Client.Transport = netTransport
	}

	return cfg, nil
}
