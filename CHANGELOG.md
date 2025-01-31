# v0.14.0 (February 17, 2025)
* Adds support for Darwin ARM based systems
* Fixes issues for found CVE's

# v0.13.0 (February 29, 2023)
* Enables adding a custom timeout for requests by fixing bug below
* Fixes bug for current `server_timeout` role attribute

# v0.12.1 (January 19, 2023)
* Added `ignore_local_storage` and `min_cert_time_left` new attributes at `issue` path, which
bypasses `prevent-reissue-local` feature, if enabled, and requests the certificate, and handles
certificate time left considered to be valid, respectively
* Fixes bug that wouldn't let to create `venafi` secret in a Vault cluster environment where refresh tokens were provided
* Added more logs for refresh token process
* Starting from release, binaries are signed

# v0.12.0 (December 27, 2022)
* Added ability to ignore search-certificate in local storage. Fixes behaviour for prevent-reissue features to have certificate default validity.
* Introduced `proactive refresh` feature, which now relies on handling refreshing the `access_token` by passing two refresh tokens in the `venafi` secret (`refresh_token` and `refresh_token_2`)
* Solved scenario when many requests are sent in parallel
* Added flag `ignore_local` in role parameters to always ignore local storage when issuing a certificate

# v0.11.0 (November 25, 2022)
Added ability to store certificates by hash string

Improved the prevention of an issuance of the certificate if it exists Vault storage, adding a new feature that bases searching using a hash string

# v0.10.6 (September 12, 2022)
Adds bug fix for Prevent-reissue feature to work on VaaS

# v0.10.5 (August 30, 2022)
Added feature in order to prevent an issuance of the certificate if it is already inside Vault storage 

# v.0.10.4 (May 27, 2022)
Fixed a thread locking bug

# v0.10.3 (May 12, 2022)
Fixed a bug about storing private keys behavior and validation of certificate mismatch

# v0.10.2 (March 24, 2022)
Fixed issue with revocation while disabling secrets engine

# v0.10.1 (March 10, 2022)
Fix for a bug with the use of a synchronized block in pathVenafiCertObtain function.

# v0.10.0 (Feb 8, 2022)
Support for CSR Service generated and Revoke action and changed the default format of private keys.

# v0.9.1 (May 25, 2021)
Updated to the latest VCert client version (v4.14.2) to address a timing issue that caused certificates requested from Venafi as a Service to fail sporadically.

# v0.9.0 (February 11, 2021)

Updated Venafi Cloud integration to use OutagePREDICT instead of DevOpsACCELERATE.

## v0.8.3 (December 31, 2020)

Resolved issue that unintentionally required trust_bundle_file to be specified for Venafi API services secured by certificates issued by non-publicly trusted CAs https://github.com/Venafi/vault-pki-backend-venafi/issues/79.

Added text file containing SHA256 hash to release assets (zip archives).

Discontinued darwin 386 (32-bit macOS) releases since support was dropped in Go 1.15 and Vault 1.6.0

## v0.8.2 (December 3, 2020)

Updated credential requirements for Trust Protection Platform to support initialization with only a `refresh_token`.

Added `ca_chain`, `issuing_ca`, and `expiration` values to the output of `/issue` and `/sign` operations.

## v0.8.1 (October 30, 2020)

Added `zone` role parameter to allow for multiple zones to be used and avoid issues with Trust Protection Platform token refresh.

## v0.8.0 (October 21, 2020)

Added support for requesting specific validity periods using the Vault native `ttl` and `max_ttl` parameters.

Added support for Trust Protection Platform Custom Fields.

## v0.7.1 (August 28, 2020)

Added support for token authentication with Trust Protection Platform (API Application ID "hashicorp-vault-by-venafi").

Deprecated legacy username/password for Trust Protection Platform.

Discontinued the `apikey`, `tpp_user`, `tpp_password`, `tpp_url`, `cloud_url`, `trust_bundle_file`, and `zone` role settings.

## v0.6.4 (July 23, 2020)

Updated to prevent certificates from being enrolled by Performance Standby (regression) and Performance Secondary (new issue).

Extended trust bundle option to Venafi Cloud.

Added Source Application Tagging for Venafi Cloud.

## v0.6.2 (March 16, 2020)

Reverted to no error on attempt to revoke (unsupported) to restore ability to disable backend. 

Introduced `no_store` and `store_by` parameters to replace `store_by_cn` and `store_by_serial` (now deprecated).

Added Source Application Tagging for Trust Protection Platform.

## v0.5.3 (December 18, 2019)

Resolved issue involving the handling of IP SANs.

## v0.5.2 (November 20, 2019)

Updated to prevent issuing certificate twice with Vault Enterprise Performance Standbys.

## v0.5.1 (July 13, 2019)

Updated to latest VCert-Go library.

## v0.4.2 (May 21, 2019)

Added support for signing externally generated CSRs.

## v0.4.1 (April 17, 2019)

Fixed issue related to Windows. https://github.com/hashicorp/go-plugin/pull/111

## v0.4.0 (March 6, 2019)

Updated CSR generation to populate Subject OU, O, ST, L, and C from Venafi policy.

## v0.3.1 (February 7, 2019)

Initial Release.
