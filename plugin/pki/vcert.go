package pki

import (
	"context"
	"fmt"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"log"
)

func (b *backend) ClientVenafi(ctx context.Context, s logical.Storage, data *framework.FieldData, req *logical.Request, roleName string) (
	endpoint.Connector, error) {
	log.Printf("Using role: %s", roleName)
	if roleName == "" {
		return nil, fmt.Errorf("Missing role name")
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("Unknown role %v", role)
	}

	var cfg *vcert.Config
	if role.Fakemode {
		log.Println("Using fakemode to issue certificate")
		cfg = &vcert.Config{
			ConnectorType: endpoint.ConnectorTypeFake,
			LogVerbose:    true,
		}
	} else if role.TPPURL != "" && role.TPPUser != "" && role.TPPPassword != "" {
		log.Printf("Using Platform with url %s to issue certificate\n",role.TPPURL)
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

	} else if role.Apikey != "" {
		log.Println("Using Cloud to issue certificate")
		cfg = &vcert.Config{
			ConnectorType: endpoint.ConnectorTypeCloud,
			BaseUrl:       role.CloudURL,
			Credentials: &endpoint.Authentication{
				APIKey: role.Apikey,
			},
			Zone:       role.Zone,
			LogVerbose: true,
		}
	} else {
		return nil, fmt.Errorf("failed to build config for Venafi issuer")
	}

	client, err := vcert.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get Venafi issuer client: %s", err)
	}

	log.Printf("Venafi vcert client. type = %T, p = %p, v = %v\n", client, &client, client)
	return client, nil

}
