package pki

import (
	"context"
	"fmt"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"io/ioutil"
	"time"
)

func (b *backend) ClientVenafi(ctx context.Context, s logical.Storage, data *framework.FieldData, req *logical.Request, roleName string) (
	endpoint.Connector, time.Duration, error) {
	b.Logger().Debug(fmt.Sprintf("Using role: %s", roleName))
	if roleName == "" {
		return nil, 0, fmt.Errorf("missing role name")
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, 0, err
	}
	if role == nil {
		return nil, 0, fmt.Errorf("unknown role %v", role)
	}

	cfg, err := b.getConfig(ctx, req, roleName, false)
	if err != nil {
		return nil, 0, err
	}

	client, err := vcert.NewClient(cfg)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get Venafi issuer client: %s", err)
	}

	return client, role.ServerTimeout, nil

}

func (b *backend) getConfig(ctx context.Context, req *logical.Request, roleName string, includeRefreshToken bool) (*vcert.Config, error) {
	var cfg *vcert.Config
	b.Logger().Debug(fmt.Sprintf("Using role: %s", roleName))
	if roleName == "" {
		return nil, fmt.Errorf("missing role name")
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("unknown role %v", role)
	}

	venafiSecret, err := b.getVenafiSecret(ctx, req.Storage, role.VenafiSecret)
	if err != nil {
		return nil, err
	}
	if venafiSecret == nil {
		return nil, fmt.Errorf("unknown venafi secret %v", role.VenafiSecret)
	}

	var trustBundlePEM string
	if venafiSecret.TrustBundleFile != "" {
		b.Logger().Debug("Reading trust bundle from file %s\n", venafiSecret.TrustBundleFile)
		trustBundle, err := ioutil.ReadFile(venafiSecret.TrustBundleFile)
		if err != nil {
			return cfg, err
		}
		trustBundlePEM = string(trustBundle)
	}

	cfg = &vcert.Config{}
	cfg.BaseUrl = venafiSecret.URL
	cfg.Zone = venafiSecret.Zone
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
		b.Logger().Debug("Using Venafi Platform with URL %s to issue certificate\n", venafiSecret.URL)
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		cfg.Credentials = &endpoint.Authentication{
			User:     venafiSecret.TppUser,
			Password: venafiSecret.TppPassword,
		}

	} else if venafiSecret.URL != "" && venafiSecret.AccessToken != "" {
		b.Logger().Debug("Using Venafi Platform with URL %s to issue certificate\n", venafiSecret.URL)
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
