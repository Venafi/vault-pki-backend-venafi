package util

import (
	"fmt"
	"strings"
)

const (
	CredentialsRootPath                          = `venafi/`
	tokenMode                                    = `TPP Token (access_token, refresh_token)` // #nosec G101
	tppMode                                      = `TPP Credentials (tpp_user, tpp_password)`
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
	ErrorTextInvalidMode                         = "invalid mode: fakemode or apikey or tpp credentials or tpp access token required"
	ErrorTextNeed2RefreshTokens                  = "secrets engine requires 2 refresh tokens for no impact token refresh"
	errorMultiModeMessage                        = `can't specify both: %s and %s modes in the same venafi secret`
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

type CertificateFormat int

const (
	CertPEM CertificateFormat = iota
	CertPKCS12
	CertFormatDefault = CertPEM
	certStrPEM        = "pem"
	certStrPKCS12     = "p12"
)

func (f *CertificateFormat) String() string {
	switch *f {
	case CertPEM:
		return certStrPEM
	case CertPKCS12:
		return certStrPKCS12
	default:
		return ""
	}
}

// Set EllipticCurve value via a string
func (f *CertificateFormat) Set(value string) {
	switch strings.ToLower(value) {
	case certStrPEM:
		*f = CertPEM
	case certStrPKCS12:
		*f = CertPKCS12
	default:
		*f = CertFormatDefault
	}
}
