package pki

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/util"
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
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
				Required:    true,
			},
			"zone": {
				Type: framework.TypeString,
				Description: `Name of Venafi Platform policy or Venafi Cloud project zone.
This field overrides the zone field declared in the Venafi secret.
Example for Platform: testpolicy\\vault
Example for Venafi Cloud: e33f3e40-4e7e-11ea-8da3-b3c196ebeb0b`,
				Required: false,
			},
			"store_by_cn": {
				Type:        framework.TypeBool,
				Description: `Set it to true to store certificates by CN in certs/ path`,
				Deprecated:  true,
			},

			"store_by_serial": {
				Type:        framework.TypeBool,
				Description: `Set it to true to store certificates by unique serial number in certs/ path`,
				Deprecated:  true,
			},

			"store_by": {
				Type:        framework.TypeString,
				Description: `The attribute by which certificates are stored in the backend.  "serial" (default), "cn" and "hash" are the only valid values.`,
			},

			"no_store": {
				Type:        framework.TypeBool,
				Description: `If set, certificates issued/signed against this role will not be stored in the storage backend.`,
			},

			"service_generated_cert": {
				Type:        framework.TypeBool,
				Description: `Have Trust Protection Platform or Venafi as a Service generate keys and CSRs`,
				Default:     false,
			},
			"store_pkey": {
				Type:        framework.TypeBool,
				Description: `Set it to true to store certificates privates key in certificate fields`,
			},
			"chain_option": {
				Type:        framework.TypeString,
				Description: `Specify ordering certificates in chain. Root can be "first" or "last"`,
				Default:     "last",
			},
			"key_type": {
				Type:    framework.TypeString,
				Default: "rsa",
				Description: `The type of key to use; defaults to RSA. "rsa"
				and "ec" (ECDSA) are the only valid values.`,
			},
			"key_bits": {
				Type:    framework.TypeInt,
				Default: 2048,
				Description: `The number of bits to use. You will almost
certainly want to change this if you adjust
the key_type. Default: 2048`,
			},
			"key_curve": {
				Type:        framework.TypeString,
				Default:     "P256",
				Description: `Key curve for EC key type. Valid values are: "P256","P384","P521"`,
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: `The certificate validity if no specific certificate validity is requested.`,
			},
			"issuer_hint": {
				Type:        framework.TypeString,
				Description: `Indicate the target issuer to enable ttl with Venafi Platform; "DigiCert", "Entrust", and "Microsoft" are supported values.`,
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "The maximum allowed certificate validity",
			},

			"generate_lease": {
				Type: framework.TypeBool,
				Description: `
If set, certificates issued/signed against this role will have Vault leases
attached to them. Defaults to "false".`,
			},
			"server_timeout": {
				Type:        framework.TypeDurationSecond,
				Description: "Timeout of waiting certificate (seconds)",
				Default:     180,
			},
			"venafi_secret": {
				Type:        framework.TypeString,
				Description: `The name of the credentials object to be used for authentication`,
				Required:    true,
			},
			"update_if_exist": {
				Type: framework.TypeBool,
				Description: `When true, settings of an existing role will be retained unless they are specified in the update.
                              By default unspecified settings are returned to their default values`,
			},
			"min_cert_time_left": {
				Type:        framework.TypeDurationSecond,
				Description: `When set, is used to determinate if certificate issuance is needed comparing certificate validity against desired remaining validity`,
				Default:     time.Duration(30*24) * time.Hour,
			},
			"ignore_local_storage": {
				Type:        framework.TypeBool,
				Description: `When true, bypasses prevent re-issue logic to issue new certificate'`,
				Default:     false,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRoleRead,
				Summary:  "Read the properties of a role and displays it to the user.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleCreate,
				Summary:  "Create a role if not exist and updates it if exists",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathRoleDelete,
				Summary:  "Delete a role",
			},
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

func (b *backend) pathRoleUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*roleEntry, error) {
	name := data.Get("name").(string)
	entry, err := b.getRole(ctx, req.Storage, name)

	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("role %s does not exist", name)
	}

	_, isSet := data.GetOk("chain_option")
	chainOption := data.Get("chain_option").(string)
	if isSet && (entry.ChainOption != chainOption) {
		entry.ChainOption = chainOption
	}

	_, isSet = data.GetOk("store_by_cn")
	storeByCn := data.Get("store_by_cn").(bool)
	if isSet && storeByCn {
		entry.StoreBy = "cn"
	}

	_, isSet = data.GetOk("store_by_serial")
	storeBySerial := data.Get("store_by_serial").(bool)
	if isSet && storeBySerial {
		entry.StoreBy = "serial"
	}

	_, isSet = data.GetOk("store_by")
	storeBy := data.Get("store_by").(string)
	if isSet && (entry.StoreBy != storeBy) {
		entry.StoreBy = storeBy
	}

	_, isSet = data.GetOk("no_store")
	noStore := data.Get("no_store").(bool)
	if isSet && (entry.NoStore != noStore) {
		entry.NoStore = noStore
	}

	_, isSet = data.GetOk("service_generated_cert")
	serviceGeneratedCert := data.Get("service_generated_cert").(bool)
	if isSet && (entry.ServiceGenerated != serviceGeneratedCert) {
		entry.ServiceGenerated = serviceGeneratedCert
	}

	_, isSet = data.GetOk("store_pkey")
	storePkey := data.Get("store_pkey").(bool)
	if isSet && (entry.StorePrivateKey != storePkey) {
		entry.StorePrivateKey = storePkey
	}

	_, isSet = data.GetOk("key_type")
	keyType := data.Get("key_type").(string)
	if isSet && (entry.KeyType != keyType) {
		entry.KeyType = keyType
	}

	_, isSet = data.GetOk("key_bits")
	keyBits := data.Get("key_bits").(int)
	if isSet && (entry.KeyBits != keyBits) {
		entry.KeyBits = keyBits
	}

	_, isSet = data.GetOk("key_curve")
	keyCurve := data.Get("key_curve").(string)
	if isSet && (entry.KeyCurve != keyCurve) {
		entry.KeyCurve = keyCurve
	}

	_, isSet = data.GetOk("max_ttl")
	maxTtl := time.Duration(data.Get("max_ttl").(int)) * time.Second
	if isSet && (entry.MaxTTL != maxTtl) {
		entry.MaxTTL = maxTtl
	}

	_, isSet = data.GetOk("ttl")
	ttl := time.Duration(data.Get("ttl").(int)) * time.Second
	if isSet && (entry.TTL != ttl) {
		entry.TTL = ttl
	}

	_, isSet = data.GetOk("generate_lease")
	generateLease := data.Get("generate_lease").(bool)
	if isSet && (entry.GenerateLease != generateLease) {
		entry.GenerateLease = generateLease
	}

	_, isSet = data.GetOk("server_timeout")
	serverTimeout := time.Duration(data.Get("server_timeout").(int)) * time.Second
	if isSet && (entry.ServerTimeout != serverTimeout) {
		entry.ServerTimeout = serverTimeout
	}

	_, isSet = data.GetOk("venafi_secret")
	venafiSecret := data.Get("venafi_secret").(string)
	if isSet && (entry.VenafiSecret != venafiSecret) {
		entry.VenafiSecret = venafiSecret
	}

	_, isSet = data.GetOk("zone")
	zone := data.Get("zone").(string)
	if isSet && (entry.Zone != zone) {
		entry.Zone = zone
	}

	_, isSet = data.GetOk("min_cert_time_left")
	minCertTimeLeft := time.Duration(data.Get("min_cert_time_left").(int)) * time.Second
	if isSet && (entry.MinCertTimeLeft != minCertTimeLeft) {
		entry.MinCertTimeLeft = minCertTimeLeft
	}

	_, isSet = data.GetOk("ignore_local_storage")
	ignoreLocalStorage := data.Get("ignore_local_storage").(bool)
	if isSet && (entry.IgnoreLocalStorage != ignoreLocalStorage) {
		entry.IgnoreLocalStorage = ignoreLocalStorage
	}

	err = validateEntry(entry)
	if err != nil {
		return nil, err
	}

	return entry, nil
}

func (b *backend) pathRoleCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error

	name := data.Get("name").(string)
	updateEntry := data.Get("update_if_exist").(bool)

	var entry *roleEntry

	if updateEntry {
		entry, err = b.pathRoleUpdate(ctx, req, data)
		if err != nil {
			return nil, err
		}

	} else {
		entry = &roleEntry{
			ChainOption:        data.Get("chain_option").(string),
			StoreByCN:          data.Get("store_by_cn").(bool),
			StoreBySerial:      data.Get("store_by_serial").(bool),
			StoreBy:            data.Get("store_by").(string),
			NoStore:            data.Get("no_store").(bool),
			ServiceGenerated:   data.Get("service_generated_cert").(bool),
			StorePrivateKey:    data.Get("store_pkey").(bool),
			KeyType:            data.Get("key_type").(string),
			KeyBits:            data.Get("key_bits").(int),
			KeyCurve:           data.Get("key_curve").(string),
			MaxTTL:             time.Duration(data.Get("max_ttl").(int)) * time.Second,
			TTL:                time.Duration(data.Get("ttl").(int)) * time.Second,
			IssuerHint:         data.Get("issuer_hint").(string),
			GenerateLease:      data.Get("generate_lease").(bool),
			ServerTimeout:      time.Duration(data.Get("server_timeout").(int)) * time.Second,
			VenafiSecret:       data.Get("venafi_secret").(string),
			Zone:               data.Get("zone").(string),
			MinCertTimeLeft:    time.Duration(data.Get("min_cert_time_left").(int)) * time.Second,
			IgnoreLocalStorage: data.Get("ignore_local_storage").(bool),
		}
	}

	err = validateEntry(entry)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	// Store it
	jsonEntry, err := logical.StorageEntryJSON("role/"+name, entry)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, jsonEntry); err != nil {
		return nil, err
	}

	var logResp *logical.Response

	respData := map[string]interface{}{}

	warnings := getCredentialsWarnings(b, ctx, req.Storage, entry.VenafiSecret)

	if cap(warnings) > 0 {
		logResp = &logical.Response{

			Data:     respData,
			Redirect: "",
			Warnings: warnings,
		}
		return logResp, nil
	}

	return nil, nil
}

func validateEntry(entry *roleEntry) (err error) {

	credName := entry.VenafiSecret
	if credName == "" {
		return fmt.Errorf(util.ErrorTextVenafiSecretEmpty)
	}

	if entry.MaxTTL > 0 && entry.TTL > entry.MaxTTL {
		return fmt.Errorf(
			util.ErrorTextValueMustBeLess,
		)
	}

	if (entry.StoreByCN || entry.StoreBySerial) && entry.StoreBy != "" {
		return fmt.Errorf(util.ErrorTextStoreByAndStoreByCNOrSerialConflict)
	}
	if (entry.StoreByCN || entry.StoreBySerial) && entry.NoStore {
		return fmt.Errorf(util.ErrorTextNoStoreAndStoreByCNOrSerialConflict)
	}
	if entry.StoreBy != "" && entry.NoStore {
		return fmt.Errorf(util.ErrorTextNoStoreAndStoreByConflict)
	}
	if entry.StoreBy != "" {
		if (entry.StoreBy != util.StoreBySerialString) && (entry.StoreBy != util.StoreByCNString) && (entry.StoreBy != util.StoreByHASHstring) {
			return fmt.Errorf(
				fmt.Sprintf(util.ErrTextStoreByWrongOption, util.StoreBySerialString, util.StoreByCNString, util.StoreByHASHstring, entry.StoreBy),
			)
		}
	}

	//StoreBySerial and StoreByCN options are deprecated
	//if one of them is set we will set store_by option
	//if both are set then we set store_by to serial
	if entry.StoreBySerial {
		entry.StoreBy = util.StoreBySerialString
	} else if entry.StoreByCN {
		entry.StoreBy = util.StoreByCNString
	}

	return nil
}

func getCredentialsWarnings(b *backend, ctx context.Context, s logical.Storage, credentialsName string) []string {
	if credentialsName == "" {
		return []string{}
	}

	cred, err := b.getVenafiSecret(ctx, s, credentialsName)
	if err != nil || cred == nil {
		return []string{}
	}

	warnings := getWarnings(cred, credentialsName)

	return warnings
}

type roleEntry struct {

	//Venafi values
	Name               string
	ChainOption        string        `json:"chain_option"`
	StoreByCN          bool          `json:"store_by_cn"`
	StoreBySerial      bool          `json:"store_by_serial"`
	StoreBy            string        `json:"store_by"`
	NoStore            bool          `json:"no_store"`
	ServiceGenerated   bool          `json:"service_generated_cert"`
	StorePrivateKey    bool          `json:"store_pkey"`
	KeyType            string        `json:"key_type"`
	KeyBits            int           `json:"key_bits"`
	KeyCurve           string        `json:"key_curve"`
	LeaseMax           string        `json:"lease_max"`
	Lease              string        `json:"lease"`
	TTL                time.Duration `json:"ttl_duration"`
	MaxTTL             time.Duration `json:"max_ttl_duration"`
	IssuerHint         string        `json:"issuer_hint"`
	GenerateLease      bool          `json:"generate_lease,omitempty"`
	DeprecatedMaxTTL   string        `json:"max_ttl"`
	DeprecatedTTL      string        `json:"ttl"`
	ServerTimeout      time.Duration `json:"server_timeout"`
	VenafiSecret       string        `json:"venafi_secret"`
	Zone               string        `json:"zone"`
	MinCertTimeLeft    time.Duration `json:"min_cert_time_left"`
	IgnoreLocalStorage bool          `json:"ignore_local_storage"`
}

func (r *roleEntry) ToResponseData() map[string]interface{} {
	responseData := map[string]interface{}{
		"venafi_secret":          r.VenafiSecret,
		"role_zone":              r.Zone,
		"store_by":               r.StoreBy,
		"no_store":               r.NoStore,
		"service_generated_cert": r.ServiceGenerated,
		"store_pkey":             r.StorePrivateKey,
		"ttl":                    int64(r.TTL.Seconds()),
		"issuer_hint":            r.IssuerHint,
		"max_ttl":                int64(r.MaxTTL.Seconds()),
		"generate_lease":         r.GenerateLease,
		"chain_option":           r.ChainOption,
		"min_cert_time_left":     util.ShortDurationString(r.MinCertTimeLeft),
		"server_timeout":         util.ShortDurationString(r.ServerTimeout),
		"ignore_local_storage":   r.IgnoreLocalStorage,
	}
	return responseData
}

const (
	pathListRolesHelpSyn  = `List the existing roles in this backend`
	pathListRolesHelpDesc = `Roles will be listed by the role name.`
	pathRoleHelpSyn       = `Manage the roles that can be created with this backend.`
	pathRoleHelpDesc      = `This path lets you manage the roles that can be created with this backend.`
)
