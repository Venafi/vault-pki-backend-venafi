[![Venafi](https://raw.githubusercontent.com/Venafi/.github/master/images/Venafi_logo.png)](https://www.venafi.com/)
[![MPL 2.0 License](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](https://opensource.org/licenses/MPL-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & VaaS](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20VaaS-f9a90c)  
_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](../../issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](../../pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# Venafi PKI Secrets Engine for HashiCorp Vault

This solution enables [HashiCorp Vault](https://www.vaultproject.io/) users to have certificate requests fulfilled by
the [Venafi Trust Protection Platform](https://www.venafi.com/platform/trust-protection-platform) or
[Venafi as a Service](https://www.venafi.com/venaficloud) ensuring compliance with corporate security policy and
providing visibility into certificate issuance enterprise wide.

### Venafi Trust Protection Platform Requirements

Your certificate authority (CA) must be able to issue a certificate in
under one minute. Microsoft Active Directory Certificate Services (ADCS) is a
popular choice. Other CA choices may have slightly different
requirements.

Within Trust Protection Platform, configure these settings. For more
information see the _Venafi Administration Guide_.

- A user account that has an authentication token for the "Venafi Secrets
  Engine for HashiCorp Vault" (ID "hashicorp-vault-by-venafi") API Application
  as of 20.1 (or scope "certificate:manage" for 19.2 through 19.4) or has been
  granted WebSDK Access (deprecated)
- A Policy folder where the user has the following permissions: View, Read,
  Write, Create.
- Enterprise compliant policies applied to the folder including:

  - Subject DN values for Organizational Unit (OU), Organization (O),
    City/Locality (L), State/Province (ST) and Country (C).
  - CA Template that Trust Protection Platform will use to enroll general
    certificate requests.
  - Management Type not locked or locked to 'Enrollment'.
  - Certificate Signing Request (CSR) Generation unlocked or not locked to
    'Service Generated CSR'.
  - Generate Key/CSR on Application not locked or locked to 'No'.
  - (Recommended) Disable Automatic Renewal set to 'Yes'.
  - (Recommended) Key Bit Strength set to 2048 or higher.
  - (Recommended) Domain Whitelisting policy appropriately assigned.

  **NOTE**: If you are using Microsoft ACDS, the CRL distribution point and
  Authority Information Access (AIA) URIs must start with an HTTP URI
  (non-default configuration). If an LDAP URI appears first in the X509v3
  extensions, some applications will fail, such as NGINX ingress controllers.
  These applications aren't able to retrieve CRL and OCSP information.

#### Trust between Vault and Trust Protection Platform

The Trust Protection Platform REST API (WebSDK) must be secured with a
certificate. Generally, the certificate is issued by a CA that is not publicly
trusted so establishing trust is a critical part of your setup.

Two methods can be used to establish trust. Both require the trust anchor
(root CA certificate) of the WebSDK certificate. If you have administrative
access, you can import the root certificate into the trust store for your
operating system. If you don't have administrative access, or prefer not to
make changes to your system configuration, save the root certificate to a file
in PEM format (e.g. /opt/venafi/bundle.pem) and reference it using the
`trust_bundle_file` parameter whenever you create or update a PKI role in your
Vault.

### Venafi as a Service Requirements

If you are using Venafi as a Service, verify the following:

- The Venafi as a Service REST API at [https://api.venafi.cloud](https://api.venafi.cloud/swagger-ui.html)
is accessible from the systems where Vault will be running.
- You have successfully registered for a Venafi as a Service account, have been granted at least the
"Resource Owner" role, and know your API key.
- A CA Account and Issuing Template exist and have been configured with:
    - Recommended Settings values for:
        - Organizational Unit (OU)
        - Organization (O)
        - City/Locality (L)
        - State/Province (ST)
        - Country (C)
    - Issuing Rules that:
        - (Recommended) Limits Common Name and Subject Alternative Name to domains that are allowed by your organization
        - (Recommended) Restricts the Key Length to 2048 or higher
        - (Recommended) Does not allow Private Key Reuse
- An Application exists where you are among the owners, and you know the Application name.
- An Issuing Template is assigned to the Application, and you know its API Alias.

## Setup

Before certificates can be issued, you must complete these steps to configure the
Venafi secrets engine:

1. Create the [directory](https://www.vaultproject.io/docs/internals/plugins#plugin-directory)
   where your Vault server will look for plugins (e.g. /etc/vault/vault_plugins).
   The directory must not be a symbolic link. On macOS, for example, /etc is a
   link to /private/etc. To avoid errors, choose an alternative directory such
   as /private/etc/vault/vault_plugins.

1. Download the latest `vault-pki-backend-venafi` [release package](../../releases/latest)
   for your operating system. Unzip the binary to the plugin directory. Note
   that the URL for the zip file, referenced below, changes as new versions of the
   plugin are released.

   ```text
   $ wget https://github.com/Venafi/vault-pki-backend-venafi/releases/download/v0.0.1/venafi-pki-backend_v0.0.1+1_linux.zip
   $ unzip venafi-pki-backend_v0.0.1+1_linux.zip
   $ mv venafi-pki-backend /etc/vault/vault_plugins
   ```

   :pushpin: **NOTE**: Release binaries are built and tested using the latest generally
   available version of Vault at the time.  Backward compatibility with older versions of Vault
   is typical but not confirmed by testing.

1. Update the Vault [server configuration](https://www.vaultproject.io/docs/configuration/)
   to specify the plugin directory:

   ```text
   plugin_directory = "/etc/vault/vault_plugins"
   ```

   :pushpin: **NOTE**: If plugin directory is a symbolic link, Vault responds
   with an error[:bookmark:](https://groups.google.com/forum/#!topic/vault-tool/IVYLA3aH72M).
   If you're configuring on a MacBook, /etc is default symlinked to /private/etc. To
   prevent the error from occurring, change the `plugin_directory` to a non-symlinked
   directory. For example "/private/etc/vault/vault_plugins". If you make this change,
   keep it in mind as you go through the remaining steps.

1. Start your Vault using the [server command](https://www.vaultproject.io/docs/commands/server).

1. Get the SHA-256 checksum of the `venafi-pki-backend` plugin binary:

   ```text
   $ SHA256=$(sha256sum /etc/vault/vault_plugins/venafi-pki-backend| cut -d' ' -f1)
   ```

1. Register the `venafi-pki-backend` plugin in the Vault
   [system catalog](https://www.vaultproject.io/docs/internals/plugins#plugin-catalog):

   ```text
   $ vault write sys/plugins/catalog/secret/venafi-pki-backend \
       sha_256="${SHA256}" command="venafi-pki-backend"
   Success! Data written to: sys/plugins/catalog/secret/venafi-pki-backend
   ```

    :pushpin: **NOTE**: If you get an error that says "can not execute files
    outside of configured plugin directory", it's probably because you didn't set the
    plugin directory correctly with a non-symlinked directory as mentioned earlier. Also,
    make sure this change is reflected when calling for the SHA-256 checksum.

1. Enable the Venafi secrets engine:

   ```text
   $ vault secrets enable -path=venafi-pki -plugin-name=venafi-pki-backend plugin
   Success! Enabled the pki-backend-venafi secrets engine at: venafi-pki/
   ```

1. Configure a Venafi secret that maps a name in Vault to connection and authentication
   settings for enrolling certificate using Venafi. The zone is a policy folder for Trust
   Protection Platform or an Application name and Issuing Template API Alias (e.g.
   "Business App\Enterprise CIT") for Venafi as a Service. Obtain the `access_token` and
   `refresh_token` for Trust Protection Platform using the 
   [VCert CLI](https://github.com/Venafi/vcert/blob/master/README-CLI-PLATFORM.md#obtaining-an-authorization-token)
   (`getcred` action with `--client-id "hashicorp-vault-by-venafi"` and
   `--scope "certificate:manage"`) or the Platform's Authorize REST API method. To see
   other available options for the Venafi secret after it is created, use
   `vault path-help venafi-pki/venafi/:name`.

   **Trust Protection Platform**:

   ```
   $ vault write venafi-pki/venafi/tpp \
       url="https://tpp.venafi.example" \
       access_token="tn1PwE1QTZorXmvnTowSyA==" \
       refresh_token="MGxV7DzNnclQi9CkJMCXCg==" \
       zone="DevOps\\HashiCorp Vault" \
       trust_bundle_file="/opt/venafi/bundle.pem"
   Success! Data written to: venafi-pki/venafi/tpp
   ```

   :warning: **CAUTION**: Do not create more than one Venafi secret for the same
   pair of tokens. Supplying a `refresh_token` allows the secrets engine to
   automatically obtain new tokens and operate without interruption whenever the
   `access_token` expires. This behavior is important to understand because it 
   may require you to provide a new `access_token` and `refresh_token` if you need
   to modify the Venafi secret in the future (i.e. depending upon whether the
   original set of tokens has been refreshed by the secrets engine plugin). Having
   more than one Venafi secret for the same set of tokens would result in all but 
   one Venafi secret being rendered inoperable when the token is refreshed.

   **Venafi as a Service**:

   ```
   $ vault write venafi-pki/venafi/vaas \
       apikey="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
       zone="Business App\\Enterprise CIT"
   Success! Data written to: venafi-pki/roles/vaas
   ```

1. Lastly, configure a [role](https://www.vaultproject.io/api-docs/secret/pki#create-update-role)
   that maps a name in Vault to a Venafi secret for enrollment. To see other available
   options for the role after it is created, use `vault path-help venafi-pki/roles/:name`.

   **Trust Protection Platform**:

   ```text
   $ vault write venafi-pki/roles/tpp \
       venafi_secret=tpp \
       generate_lease=true store_by=serial store_pkey=true
   Success! Data written to: venafi-pki/roles/tpp
   ```

   **Venafi as a Service**:

   ```text
   $ vault write venafi-pki/roles/vaas \
       venafi_secret=vaas \
       generate_lease=true store_by=serial store_pkey=true
   Success! Data written to: venafi-pki/roles/vaas
   ```

   :pushpin: **NOTE**: The `ttl` and `max_ttl` role parameters can be used specify the
   default and maximum allowed validity for certificate requests if the Venafi CA template
   supports flexible validity periods.  If the CA is DigiCert, Entrust, or Microsoft with
   Trust Protection Platform, the `issuer_hint` parameter is also required for `ttl`
   functionality (e.g. `issuer_hint="m"` for Microsoft).  When issue or sign operations
   include the `ttl` parameter it overrides the role default `ttl` and will be constrained
   by the role `max_ttl`.
   
   :pushpin: **NOTE**: The `zone` role parameter allows multiple zones to be used with a
   single Venafi secret.  If `zone` is not specified by the role, the `zone` specified by
   the Venafi secret applies.

## Usage

After the Venafi secrets engine is configured and a user/machine has a Vault
token with the proper permission, it can enroll certificates using Venafi.

1. Generate a certificate by writing to the `/issue` endpoint with the name of
   the role (add the `key_password` parameter to get a password encrypted
   private key in the output):

   **Trust Protection Platform**:

   ```text
   $ vault write venafi-pki/issue/tpp common_name="common-name.example.com" \
       alt_names="dns-san-1.example.com,dns-san-2.example.com"

   Key                  Value
   ---                  -----
   lease_id             venafi-pki/issue/tpp/oLih42SCFzyjntxGc00vqmWH
   lease_duration       719h49m55s
   lease_renewable      false
   certificate          -----BEGIN CERTIFICATE-----
   certificate_chain    -----BEGIN CERTIFICATE-----
   common_name          common-name.example.com
   private_key          -----BEGIN RSA PRIVATE KEY-----
   serial_number        1d:bc:a8:3c:00:00:00:05:5c:e8
   ```

   **Venafi as a Service**:

   ```text
   $ vault write venafi-pki/issue/vaas common_name="common-name.example.com" \
       alt_names="dns-san-1.example.com,dns-san-2.example.com"

   Key                  Value
   ---                  -----
   lease_id             venafi-pki/issue/vaas/1WCNvXKiwboWfRRfjzlPAwEi
   lease_duration       167h59m58s
   lease_renewable      false
   certificate          -----BEGIN CERTIFICATE-----
   certificate_chain    -----BEGIN CERTIFICATE-----
   common_name          common-name.example.com
   private_key          -----BEGIN RSA PRIVATE KEY-----
   serial_number        17:47:8b:13:90:b8:3d:87:b0:dc:b6:9e:00:2b:87:02:c9:d3:1e:8a
   ```

1. Or sign a CSR from a file by writing to the `/sign` endpoint with the name of
   the role:

   **Trust Protection Platform**:

   ```text
   $ vault write venafi-pki/sign/tpp csr=@example.req

   Key                  Value
   ---                  -----
   lease_id             venafi-pki/sign/tpp/tQq3QNY45e4sJMqTTI9DXEGK
   lease_duration       719h49m57s
   lease_renewable      false
   certificate          -----BEGIN CERTIFICATE-----
   certificate_chain    -----BEGIN CERTIFICATE-----
   common_name          common-name.example.com
   serial_number        1d:c4:07:9a:00:00:00:05:5c:ea
   ```

   **Venafi as a Service**:

   ```text
   $ vault write venafi-pki/sign/vaas csr=@example.req

   Key                  Value
   ---                  -----
   lease_id             venafi-pki/sign/vaas/fF44FdMAjuCdC29w3Ff81hes
   lease_duration       167h59m58s
   lease_renewable      false
   certificate          -----BEGIN CERTIFICATE-----
   certificate_chain    -----BEGIN CERTIFICATE-----
   common_name          common-name.example.com
   serial_number        76:55:e2:14:de:c8:3f:e1:64:4a:fa:37:d4:6e:f5:ef:5e:4c:16:5b
   ```

Custom Fields can be set when requesting certificates from Trust Protection
Platform using the `custom_fields` parameter (e.g.
`custom_fields="field1_name=valueX,field2_name=valueY,field2_name=valueZ"`).

## API

Venafi Machine Identity Secrets Engine uses the same
[Vault API](https://www.vaultproject.io/api/secret/pki)
as the built-in PKI secrets engine. Some methods, such as those for
managing certificate authorities, do not apply.

## Upgrading

To upgrade to a new version of this plugin, review the
[release notes](../../releases) to understand the impact and then follow the 
[standard procedure](https://www.vaultproject.io/docs/upgrading/plugins).
The following command will trigger a plugin reload globally:

```text
$ vault write sys/plugins/reload/backend plugin=venafi-pki-backend scope=global

Key          Value
---          -----
reload_id    d8180af4-01e0-d4d8-10ce-0daf69fbb6ed
```

:warning: **IMPORTANT:** Every member of a Vault cluster must be running
with the same version of the plugin to avoid inconsistent, unexpected, and
possibly erroneous results.

## Prevent Re-issue

In order to prevent an issuance of a new certificate if current certificate exists in Vault's storage, we added a capability
to return that certificate instead. To issue this feature you must set:

- `min_cert_time_left` (_optional_): Golang's duration format string (e.g. 24h, 23h5m20s, 10000s, etc.). Default is 30 days.
- `store_by="serial"` (_required_)
- `store_pkey=true` (_required_)
- `ignore_local_storage=false`  (_required_)

If certificate was successfully loaded from Vault storage, you will encounter `Loading certificate from storage` message
in logs when `[DEBUG]` mode is set:

```
2022-08-30T13:41:49.007-0500 [DEBUG] secrets.venafi-pki-backend.venafi-pki-backend_5df77702.venafi-pki-backend.venafi-pki-backend: Loading certificate from storage: timestamp=2022-08-30T13:41:49.006-0500
2022-08-30T13:41:49.008-0500 [DEBUG] secrets.venafi-pki-backend.venafi-pki-backend_5df77702.venafi-pki-backend.venafi-pki-backend: Getting venafi certificate: timestamp=2022-08-30T13:41:49.008-0500
2022-08-30T13:41:49.010-0500 [DEBUG] secrets.venafi-pki-backend.venafi-pki-backend_5df77702.venafi-pki-backend.venafi-pki-backend: certificate is:-----BEGIN CERTIFICATE-----
MIIHvjCCBaagAwIBAgITbQCpUfV8kBfjsOaP8QAAAKlR9TANBgkqhkiG9w0BAQsF
ADBbMRMwEQYKCZImiZPyLGQBGRYDY29tMRYwFAYKCZImiZPyLGQBGRYGdmVuYWZp
MRUwEwYKCZImiZPyLGQBGRYFdmVucWExFTATBgNVBAMTDFFBIFZlbmFmaSBDQTAe
Fw0yMjA4MzAxODMxNDNaFw0yNDA4MjkxODMxNDNaMIHAMQswCQYDVQQGEwJVUzEN
MAsGA1UECBMEVXRhaDEXMBUGA1UEBxMOU2FsdCBMYWtlIENpdHkxFDASBgNVBAoT
C1ZlbmFmaSBJbmMuMRQwEgYDVQQLEwtFbmdpbmVlcmluZzEbMBkGA1UECxMSUHJv
ZHVjdCBNYW5hZ2VtZW50MRowGAYDVQQLExFRdWFsaXR5IEFzc3VyYW5jZTEkMCIG
A1UEAxMbbm9wcml2YXRla2V5LnZlbmFmaS5leGFtcGxlMIIBIjANBgkqhkiG9w0B
```

## Prevent Re-issue Local

### Introducing store by hash

We enabled capability to store certificates by hash.
The hash is generated by:

`Common Name + SAN DNS + Zone`

It's required to set any of (at least one): `Common Name` or `SAN DNS`.

### Using Prevent Re-issue Local

In order to prevent an issuance of a new certificate if current certificate exists in Vault's storage, we added a capability
to return that certificate instead. To issue this feature you must set:

- `min_cert_time_left` (_optional_): Golang's duration format string (e.g. 24h, 23h5m20s, 10000s, etc.). Default is 30 days.
- `store_by="hash"` (_required_)
- `store_pkey=true` (_required_)
- `ignore_local_storage=false` (_required_)

`If certificate was successfully loaded from Vault storage, you will encounter `Loading certificate from storage` message
in logs when `[DEBUG]` mode is set:

```
2022-08-30T13:41:49.007-0500 [DEBUG] secrets.venafi-pki-backend.venafi-pki-backend_5df77702.venafi-pki-backend.venafi-pki-backend: Loading certificate from storage: timestamp=2022-08-30T13:41:49.006-0500
2022-08-30T13:41:49.008-0500 [DEBUG] secrets.venafi-pki-backend.venafi-pki-backend_5df77702.venafi-pki-backend.venafi-pki-backend: Getting venafi certificate: timestamp=2022-08-30T13:41:49.008-0500
2022-08-30T13:41:49.010-0500 [DEBUG] secrets.venafi-pki-backend.venafi-pki-backend_5df77702.venafi-pki-backend.venafi-pki-backend: certificate is:-----BEGIN CERTIFICATE-----
MIIHvjCCBaagAwIBAgITbQCpUfV8kBfjsOaP8QAAAKlR9TANBgkqhkiG9w0BAQsF
ADBbMRMwEQYKCZImiZPyLGQBGRYDY29tMRYwFAYKCZImiZPyLGQBGRYGdmVuYWZp
MRUwEwYKCZImiZPyLGQBGRYFdmVucWExFTATBgNVBAMTDFFBIFZlbmFmaSBDQTAe
Fw0yMjA4MzAxODMxNDNaFw0yNDA4MjkxODMxNDNaMIHAMQswCQYDVQQGEwJVUzEN
MAsGA1UECBMEVXRhaDEXMBUGA1UEBxMOU2FsdCBMYWtlIENpdHkxFDASBgNVBAoT
C1ZlbmFmaSBJbmMuMRQwEgYDVQQLEwtFbmdpbmVlcmluZzEbMBkGA1UECxMSUHJv
ZHVjdCBNYW5hZ2VtZW50MRowGAYDVQQLExFRdWFsaXR5IEFzc3VyYW5jZTEkMCIG
A1UEAxMbbm9wcml2YXRla2V5LnZlbmFmaS5leGFtcGxlMIIBIjANBgkqhkiG9w0B
```

## Ignore Local Storage

If certificates are stored locally in vault by `serial` or `hash`, normal behavior would be to always look into certificate locally before issuing a new certificate.
If `ignore_local_storage` flag is set to `true`, it would bypass the logic to check certificate locally (to prevent re-issue) and always issue a new certificate.
Default value is always `false`.

## License

Copyright &copy; Venafi, Inc. All rights reserved.

This solution is licensed under the Mozilla Public License, Version 2.0. See `LICENSE` for the full license text.

Please direct questions/comments to opensource@venafi.com.
