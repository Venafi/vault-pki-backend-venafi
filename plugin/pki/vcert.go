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
		return nil, 0, fmt.Errorf("Missing role name")
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, 0, err
	}
	if role == nil {
		return nil, 0, fmt.Errorf("Unknown role %v", role)
	}

	var cfg *vcert.Config
	var trustBundlePEM string
	if role.TrustBundleFile != "" {
		b.Logger().Debug("Reading trust bundle from file %s\n", role.TrustBundleFile)
		trustBundle, err := ioutil.ReadFile(role.TrustBundleFile)
		if err != nil {
			return nil, 0, err
		}
		trustBundlePEM = string(trustBundle)
	}

	if role.Fakemode {
		b.Logger().Debug("Using dev mode to issue certificate")
		cfg = &vcert.Config{
			ConnectorType: endpoint.ConnectorTypeFake,
			LogVerbose:    true,
		}

	} else if role.TPPURL != "" && role.TPPUser != "" && role.TPPPassword != "" {
		b.Logger().Debug("Using Venafi Platform with URL %s to issue certificate\n", role.TPPURL)
		if trustBundlePEM != "" {
			cfg = &vcert.Config{
				ConnectorType:   endpoint.ConnectorTypeTPP,
				BaseUrl:         role.TPPURL,
				ConnectionTrust: trustBundlePEM,
				Credentials: &endpoint.Authentication{
					User:     role.TPPUser,
					Password: role.TPPPassword,
				},
				Zone:       role.Zone,
				LogVerbose: true,
			}
		} else {
			cfg = &vcert.Config{
				ConnectorType: endpoint.ConnectorTypeTPP,
				BaseUrl:       role.TPPURL,
				Credentials: &endpoint.Authentication{
					User:     role.TPPUser,
					Password: role.TPPPassword,
				},
				Zone:       role.Zone,
				LogVerbose: true,
			}
		}

	} else if role.Apikey != "" {
		b.Logger().Debug("Using Venafi Cloud to issue certificate")
		if trustBundlePEM != "" {
			cfg = &vcert.Config{
				ConnectorType: endpoint.ConnectorTypeCloud,
				BaseUrl:       role.CloudURL,
				ConnectionTrust: trustBundlePEM,
				Credentials: &endpoint.Authentication{
					APIKey: role.Apikey,
				},
				Zone:       role.Zone,
				LogVerbose: true,
			}
		} else {
			cfg = &vcert.Config{
				ConnectorType: endpoint.ConnectorTypeCloud,
				BaseUrl:       role.CloudURL,
				Credentials: &endpoint.Authentication{
					APIKey: role.Apikey,
				},
				Zone:       role.Zone,
				LogVerbose: true,
			}
		}
	} else {
		return nil, 0, fmt.Errorf("failed to build config for Venafi issuer")
	}

	client, err := vcert.NewClient(cfg)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get Venafi issuer client: %s", err)
	}

	return client, role.ServerTimeout, nil

}
