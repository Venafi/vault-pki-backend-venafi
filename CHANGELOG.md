## v0.7.1 (August 28, 2020)

Added support for token authentication with Trust Protection Platform (API Application ID "hashicorp-vault-by-venafi").

Deprecated legacy username/password for Trust Protection Platform.

Discontinued the apikey, tpp_user, tpp_password, tpp_url, cloud_url, trust_bundle_file, and zone role settings.

## v0.6.4 (July 23, 2020)

Prevent certificates from being enrolled by Performance Standby (regression) and Performance Secondary (new issue).

Extend trust bundle option to Venafi Cloud.

Source Application Tagging for Venafi Cloud.

## v0.6.2 (March 16, 2020)

Revert to no error on attempt to revoke (unsupported) to restore ability to disable backend. 

Introduce no_store and store_by parameters to replace store_by_cn and store_by_serial (now deprecated).

Source Application Tagging for Trust Protection Platform.

## v0.5.3 (December 18, 2019)

Resolve issue involving the handling of IP SANs.

## v0.5.2 (November 20, 2019)

Prevent issuing certificate twice with Vault Enterprise Performance Standbys.

## v0.5.1 (July 13, 2019)

Update to latest VCert-Go library.

## v0.4.2 (May 21, 2019)

Added support for signing externally generated CSRs.

## v0.4.1 (April 17, 2019)

Fixed issue related to Windows. https://github.com/hashicorp/go-plugin/pull/111

## v0.4.0 (March 6, 2019)

Update CSR generation to populate Subject OU, O, ST, L, and C from Venafi policy.

## v0.3.1 (February 7, 2019)

Initial Release.
