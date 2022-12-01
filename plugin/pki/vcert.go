package pki

import (
	"context"
	"fmt"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/logical"
	"io/ioutil"
)

func (b *backend) ClientVenafi(ctx context.Context, req *logical.Request, role *roleEntry) (
	endpoint.Connector, *vcert.Config, error) {

	cfg, err := b.getConfig(ctx, req, role, false)
	if err != nil {
		return nil, nil, err
	}

	client, err := vcert.NewClient(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get Venafi issuer client: %s", err)
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
		return nil, fmt.Errorf("unknown venafi secret %v", role.VenafiSecret)
	}

	var trustBundlePEM string
	if venafiSecret.TrustBundleFile != "" {
		b.Logger().Debug(fmt.Sprintf("Reading trust bundle from file: " + venafiSecret.TrustBundleFile))
		trustBundle, err := ioutil.ReadFile(venafiSecret.TrustBundleFile)
		if err != nil {
			return cfg, err
		}
		trustBundlePEM = string(trustBundle)
	}

	// If the role has a Zone declared, it takes priority over the Zone in the Venafi secret
	var zone string
	if role.Zone != "" {
		b.Logger().Debug(fmt.Sprintf("Using role zone: [%s]. Overrides venafi Secret zone: [%s]", role.Zone, venafiSecret.Zone))
		zone = role.Zone
	} else {
		b.Logger().Debug(fmt.Sprintf("Using venafi secret zone: [%s]. Role zone not found. ", venafiSecret.Zone))
		zone = venafiSecret.Zone
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
		b.Logger().Debug(fmt.Sprintf("Using Venafi Platform with URL %s to issue certificate", venafiSecret.URL))
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		cfg.Credentials = &endpoint.Authentication{
			User:     venafiSecret.TppUser,
			Password: venafiSecret.TppPassword,
		}

	} else if venafiSecret.URL != "" && venafiSecret.AccessToken != "" {
		b.Logger().Debug(fmt.Sprintf("Using Venafi Platform with URL %s to issue certificate", venafiSecret.URL))
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		var refreshToken string
		if includeRefreshToken {
			refreshToken = venafiSecret.RefreshToken
		}
		cfg.Credentials = &endpoint.Authentication{
			AccessToken:  venafiSecret.AccessToken,
			RefreshToken: refreshToken,
		}

	} else if venafiSecret.Apikey != "" {
		b.Logger().Debug("Using Venafi Cloud to issue certificate")
		cfg.ConnectorType = endpoint.ConnectorTypeCloud
		cfg.Credentials = &endpoint.Authentication{
			APIKey: venafiSecret.Apikey,
		}

	} else {
		return nil, fmt.Errorf("failed to build config for Venafi issuer")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get Venafi issuer client: %s", err)
	}

	return cfg, nil
}
