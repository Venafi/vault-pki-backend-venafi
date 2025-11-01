package util

import "fmt"

const (
	CredentialsRootPath                          = `venafi/`
	tokenMode                                    = `Certificate Manager, Self-Hosted Token (access_token, refresh_token)` // #nosec G101
	tppMode                                      = `Certificate Manager, Self-Hosted Credentials (tpp_user, tpp_password)`
	cloudMode                                    = `Cloud API Key (apikey)`
	StoreByCNString                              = "cn"
	StoreByHASHstring                            = "hash"
	StoreBySerialString                          = "serial"
	ErrorTextValueMustBeLess                     = `"ttl" value must be less than "max_ttl" value`
	ErrorTextStoreByAndStoreByCNOrSerialConflict = `Can't specify both story_by and store_by_cn or store_by_serial options '`
	ErrorTextNoStoreAndStoreByCNOrSerialConflict = `Can't specify both no_store and store_by_cn or store_by_serial options '`
	ErrorTextNoStoreAndStoreByConflict           = `Can't specify both no_store and store_by options '`
	ErrTextStoreByWrongOption                    = "Option store_by can be %s, %s or %s, not %s"
	ErrorTextVenafiSecretEmpty                   = `"venafi_secret" argument is required`
	ErrorTextURLEmpty                            = `"url" argument is required`
	ErrorTextZoneEmpty                           = `"zone" argument is required`
	ErrorTextInvalidMode                         = "invalid mode: fakemode or apikey or Certificate Manager, Self-Hosted credentials or Certificate Manager, Self-Hosted access token required"
	ErrorTextNeed2RefreshTokens                  = "secrets engine requires 2 refresh tokens for no impact token refresh"
	errorMultiModeMessage                        = `can't specify both: %s and %s modes in the same CyberArk secret`
)

const (
	Role_ttl_test_property = int(120)
	Ttl_test_property      = int(48)
)

var (
	ErrorTextMixedTPPAndToken   = fmt.Sprintf(errorMultiModeMessage, tppMode, tokenMode)
	ErrorTextMixedTPPAndCloud   = fmt.Sprintf(errorMultiModeMessage, tppMode, cloudMode)
	ErrorTextMixedTokenAndCloud = fmt.Sprintf(errorMultiModeMessage, tokenMode, cloudMode)
)
