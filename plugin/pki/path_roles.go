package pki

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/vault/helper/consts"
	"github.com/hashicorp/vault/helper/parseutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},

		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func pathRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"tpp_url": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `URL of Venafi Platfrom. Example: https://tpp.venafi.example/vedsdk`,
			},

			"cloud_url": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `URL for Venafi Cloud. Set it only if you want to use non production Cloud`,
			},

			"zone": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `Name of Venafi Platfrom or Cloud policy. 
Example for Platform: testpolicy\\vault
Example for Venafi Cloud: Default`,
			},

			"tpp_user": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `web API user for Venafi Platfrom Example: admin`,
			},
			"tpp_password": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `Password for web API user Example: password`,
			},
			"trust_bundle_file": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `Use to specify a PEM formatted file with certificates to be used as trust anchors when communicating with the remote server.
Example:
  trust_bundle_file = "/full/path/to/chain.pem""`,
			},
			"apikey": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: `API key for Venafi Cloud. Example: 142231b7-cvb0-412e-886b-6aeght0bc93d`,
			},
			"fakemode": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Description: `Set it to true to use face CA instead of Cloud or Platform to issue certificates. Useful for testing.`,
			},

			"store_by_cn": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Description: `Set it to true to store certificates by CN in certs/ path`,
			},

			"store_by_serial": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Description: `Set it to true to store certificates by unique serial number in certs/ path`,
			},

			"store_pkey": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Description: `Set it to true to store certificates privates key in certificate fields`,
			},
			"key_type": &framework.FieldSchema{
				Type:    framework.TypeString,
				Default: "rsa",
				Description: `The type of key to use; defaults to RSA.
					Valid values are:
					"rsa": RSA key type
					"ec":  ECDSA which implements P-256
					"ecdsa_224": ECDSA which implements P-224
					"ecdsa_256": ECDSA which implements P-256
					"ecdsa_384": ECDSA which implements P-384
	                "ecdsa_521": ECDSA which implements P-521
`,
			},
			"key_bits": &framework.FieldSchema{
				Type:    framework.TypeInt,
				Default: 2048,
				Description: `The number of bits to use. You will almost
certainly want to change this if you adjust
the key_type. Default: 2048`,
			},
			"ttl": &framework.FieldSchema{
				Type: framework.TypeDurationSecond,
				Description: `The lease duration if no specific lease duration is
requested. The lease duration controls the expiration
of certificates issued by this backend. Defaults to
the value of max_ttl.`,
			},

			"max_ttl": &framework.FieldSchema{
				Type:        framework.TypeDurationSecond,
				Description: "The maximum allowed lease duration",
			},

			"generate_lease": &framework.FieldSchema{
				Type: framework.TypeBool,
				Description: `
If set, certificates issued/signed against this role will have Vault leases
attached to them. Defaults to "false".`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathRoleRead,
			logical.UpdateOperation: b.pathRoleCreate,
			logical.DeleteOperation: b.pathRoleDelete,
		},

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}
}

func (b *backend) getRole(ctx context.Context, s logical.Storage, n string) (*roleEntry, error) {
	entry, err := s.Get(ctx, "role/"+n)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result roleEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	// Migrate existing saved entries and save back if changed
	modified := false
	if len(result.DeprecatedTTL) == 0 && len(result.Lease) != 0 {
		result.DeprecatedTTL = result.Lease
		result.Lease = ""
		modified = true
	}
	if result.TTL == 0 && len(result.DeprecatedTTL) != 0 {
		parsed, err := parseutil.ParseDurationSecond(result.DeprecatedTTL)
		if err != nil {
			return nil, err
		}
		result.TTL = parsed
		result.DeprecatedTTL = ""
		modified = true
	}
	if len(result.DeprecatedMaxTTL) == 0 && len(result.LeaseMax) != 0 {
		result.DeprecatedMaxTTL = result.LeaseMax
		result.LeaseMax = ""
		modified = true
	}
	if result.MaxTTL == 0 && len(result.DeprecatedMaxTTL) != 0 {
		parsed, err := parseutil.ParseDurationSecond(result.DeprecatedMaxTTL)
		if err != nil {
			return nil, err
		}
		result.MaxTTL = parsed
		result.DeprecatedMaxTTL = ""
		modified = true
	}

	if modified && (b.System().LocalMount() || !b.System().ReplicationState().HasState(consts.ReplicationPerformanceSecondary)) {
		jsonEntry, err := logical.StorageEntryJSON("role/"+n, &result)
		if err != nil {
			return nil, err
		}
		if err := s.Put(ctx, jsonEntry); err != nil {
			// Only perform upgrades on replication primary
			if !strings.Contains(err.Error(), logical.ErrReadOnly.Error()) {
				return nil, err
			}
		}
	}

	return &result, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "role/"+data.Get("name").(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: role.ToResponseData(),
	}
	return resp, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathRoleCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	name := data.Get("name").(string)

	entry := &roleEntry{
		TPPURL:          data.Get("tpp_url").(string),
		CloudURL:        data.Get("cloud_url").(string),
		Zone:            data.Get("zone").(string),
		TPPPassword:     data.Get("tpp_password").(string),
		Apikey:          data.Get("apikey").(string),
		TPPUser:         data.Get("tpp_user").(string),
		TrustBundleFile: data.Get("trust_bundle_file").(string),
		Fakemode:        data.Get("fakemode").(bool),
		StoreByCN:       data.Get("store_by_cn").(bool),
		StoreBySerial:   data.Get("store_by_serial").(bool),
		StorePrivateKey: data.Get("store_pkey").(bool),
		KeyType:         data.Get("key_type").(string),
		KeyBits:         data.Get("key_bits").(int),
		MaxTTL:          time.Duration(data.Get("max_ttl").(int)) * time.Second,
		TTL:             time.Duration(data.Get("ttl").(int)) * time.Second,
		GenerateLease:   data.Get("generate_lease").(bool),
	}

	if entry.MaxTTL > 0 && entry.TTL > entry.MaxTTL {
		return logical.ErrorResponse(
			`"ttl" value must be less than "max_ttl" value`,
		), nil
	}

	// Store it
	jsonEntry, err := logical.StorageEntryJSON("role/"+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

type roleEntry struct {

	//Venafi values
	TPPURL           string        `json:"tpp_url"`
	CloudURL         string        `json:"cloud_url"`
	Zone             string        `json:"zone"`
	TPPPassword      string        `json:"tpp_password"`
	Apikey           string        `json:"apikey"`
	TPPUser          string        `json:"tpp_user"`
	TrustBundleFile  string        `json:"trust_bundle_file"`
	Fakemode         bool          `json:"fakemode"`
	StoreByCN        bool          `json:"store_by_cn"`
	StoreBySerial    bool          `json:"store_by_serial"`
	StorePrivateKey  bool          `json:"store_pkey"`
	KeyType          string        `json:"key_type" mapstructure:"key_type"`
	KeyBits          int           `json:"key_bits" mapstructure:"key_bits"`
	LeaseMax         string        `json:"lease_max"`
	Lease            string        `json:"lease"`
	TTL              time.Duration `json:"ttl_duration" mapstructure:"ttl_duration"`
	MaxTTL           time.Duration `json:"max_ttl_duration" mapstructure:"max_ttl_duration"`
	GenerateLease    bool          `json:"generate_lease,omitempty"`
	DeprecatedMaxTTL string        `json:"max_ttl" mapstructure:"max_ttl"`
	DeprecatedTTL    string        `json:"ttl" mapstructure:"ttl"`
}

func (r *roleEntry) ToResponseData() map[string]interface{} {
	responseData := map[string]interface{}{
		//Venafi
		"tpp_url":   r.TPPURL,
		"cloud_url": r.CloudURL,
		"zone":      r.Zone,
		//We shouldn't show credentials
		//"tpp_password":      r.TPPPassword,
		//"apikey":            r.Apikey,
		"tpp_user":          r.TPPUser,
		"trust_bundle_file": r.TrustBundleFile,
		"fakemode":          r.Fakemode,
		"store_by_cn":       r.StoreByCN,
		"store_by_serial":   r.StoreBySerial,
		"store_pkey":        r.StorePrivateKey,
		"ttl":               int64(r.TTL.Seconds()),
		"max_ttl":           int64(r.MaxTTL.Seconds()),
		"generate_lease":    r.GenerateLease,
	}
	return responseData
}

const pathListRolesHelpSyn = `List the existing roles in this backend`

const pathListRolesHelpDesc = `Roles will be listed by the role name.`

const pathRoleHelpSyn = `Manage the roles that can be created with this backend.`

const pathRoleHelpDesc = `This path lets you manage the roles that can be created with this backend.`
