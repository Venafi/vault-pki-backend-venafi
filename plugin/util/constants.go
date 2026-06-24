package util

import "fmt"

const (
	CredentialsRootPath                          = `venafi/`
	tokenMode                                    = `Certificate Manager, Self-Hosted Token (access_token, refresh_token)` // #nosec G101
	tppMode                                      = `Certificate Manager, Self-Hosted Credentials (tpp_user, tpp_password)`
	cloudMode                                    = `Cloud API Key (apikey)`
	ngtsMode                                     = `Strata Cloud Manager (NGTS) service account (ngts_client_id, ngts_client_secret) or pre-issued ngts_access_token` // #nosec G101
	StoreByCNString                              = "cn"
	StoreByHASHstring                            = "hash"
	StoreBySerialString                          = "serial"
	ErrorTextValueMustBeLess                     = `"ttl" value must be less than "max_ttl" value`
	ErrorTextStoreByAndStoreByCNOrSerialConflict = `can't specify both story_by and store_by_cn or store_by_serial options '`
	ErrorTextNoStoreAndStoreByCNOrSerialConflict = `can't specify both no_store and store_by_cn or store_by_serial options '`
	ErrorTextNoStoreAndStoreByConflict           = `can't specify both no_store and store_by options '`
	ErrTextStoreByWrongOption                    = "option store_by can be %s, %s or %s, not %s"
	ErrorTextVenafiSecretEmpty                   = `"venafi_secret" argument is required`
	ErrorTextURLEmpty                            = `"url" argument is required`
	ErrorTextZoneEmpty                           = `"zone" argument is required`
	ErrorTextInvalidMode                         = "invalid mode: fakemode or apikey or Certificate Manager, Self-Hosted credentials or Certificate Manager, Self-Hosted access token or NGTS service account required"
	ErrorTextNeed2RefreshTokens                  = "secrets engine requires 2 refresh tokens for no impact token refresh"
	errorMultiModeMessage                        = `can't specify both: %s and %s modes in the same CyberArk secret`

	// NGTS (Strata Cloud Manager) — service-account auth is a credential sink; see
	// the NGTS implementation plan in docs/vault-pki-backend-venafi/.
	NgtsTrustedTokenHostSuffix = ".paloaltonetworks.com" // token URL must be within the trusted Palo Alto domain
	NgtsScopePattern           = `^tsg_id:[0-9]{10}$`    // anchored (stricter than the Go SDK's unanchored check)

	ErrorTextNgtsCredsIncomplete       = "NGTS requires either ngts_client_id, ngts_client_secret, ngts_token_url and ngts_scope, or a pre-issued ngts_access_token"
	ErrorTextNgtsTokenURLEmpty         = "ngts_token_url is required for NGTS service-account authentication"                                       // #nosec G101
	ErrorTextNgtsScopeInvalid          = "ngts_scope must be in the form tsg_id:<10-digit TSG ID>"                                                  // #nosec G101
	ErrorTextNgtsTokenURLInvalid       = "ngts_token_url is not a valid URL: %s"                                                                    // #nosec G101
	ErrorTextNgtsTokenURLUntrustedHost = "ngts_token_url host %q is not within the trusted domain %q; refusing to send service-account credentials" // #nosec G101
	WarningNgtsTokenURLHTTPUpgraded    = "ngts_token_url used http://; upgraded to https:// to protect service-account credentials"                 // #nosec G101
)

const (
	Role_ttl_test_property = int(120)
	Ttl_test_property      = int(48)
)

var (
	ErrorTextMixedTPPAndToken   = fmt.Sprintf(errorMultiModeMessage, tppMode, tokenMode)
	ErrorTextMixedTPPAndCloud   = fmt.Sprintf(errorMultiModeMessage, tppMode, cloudMode)
	ErrorTextMixedTokenAndCloud = fmt.Sprintf(errorMultiModeMessage, tokenMode, cloudMode)
	ErrorTextMixedNgtsAndTPP    = fmt.Sprintf(errorMultiModeMessage, ngtsMode, tppMode)
	ErrorTextMixedNgtsAndToken  = fmt.Sprintf(errorMultiModeMessage, ngtsMode, tokenMode)
	ErrorTextMixedNgtsAndCloud  = fmt.Sprintf(errorMultiModeMessage, ngtsMode, cloudMode)
)
