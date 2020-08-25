![Venafi](Venafi_logo.png)
[![MPL 2.0 License](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](https://opensource.org/licenses/MPL-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 17.3+ & Cloud](https://img.shields.io/badge/Compatibility-TPP%2017.3+%20%26%20Cloud-f9a90c)  
_This open source project is community-supported. To report a problem or share an idea, use the
**[Issues](../../issues)** tab; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use the **[Pull requests](../../pulls)** tab to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions._

# Venafi PKI Secrets Engine for HashiCorp Vault

This solution enables [HashiCorp Vault](https://www.vaultproject.io/) users to have certificate requests fulfilled by the [Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or [Venafi Cloud](https://www.venafi.com/platform/cloud/devops) ensuring compliance with corporate security policy and providing visibility into certificate issuance enterprise wide.

### Venafi Trust Protection Platform Requirements

Your certificate authority (CA) must be able to issue a certificate in
under one minute. Microsoft Active Directory Certificate Services (ADCS) is a
popular choice. Other CA choices may have slightly different
requirements.

Within Trust Protection Platform, configure these settings. For more
information see the _Venafi Administration Guide_.

- A user account that has been granted REST API (WebSDK) access.
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

### Venafi Cloud Requirements

If you are using Venafi Cloud, be sure to set up an issuing template, project,
and any other dependencies that appear in the Venafi Cloud documentation.

- Set up an issuing template to link Venafi Cloud to your CA. To learn more,
  search for "Issuing Templates" in the
  [Venafi Cloud Help system](https://docs.venafi.cloud/help/Default.htm).
- Create a project and zone that identifies the template and other information.
  To learn more, search for "Projects" in the
  [Venafi Cloud Help system](https://docs.venafi.cloud/help/Default.htm).

## Setup

Before certificates can be issued, you must complete these steps to configure the
Venafi secrets engine:

1. Create the [directory](https://www.vaultproject.io/docs/internals/plugins#plugin-directory)
   where your Vault server will look for plugins (e.g. /etc/vault/vault_plugins).
   The directory must not be a symbolic link. On macOS, for example, /etc is a
   link to /private/etc. To avoid errors, choose an alternative directory such
   as /private/etc/vault/vault_plugins.

1. Download the latest `vault-pki-backend-venafi`
   [release package](https://github.com/Venafi/vault-pki-backend-venafi/releases/latest)
   for your operating system. Unzip the binary to the plugin directory. Note
   that the URL for the zip file, referenced below, changes as new versions of the
   plugin are released.

   ```text
   $ wget https://github.com/Venafi/vault-pki-backend-venafi/releases/download/v0.0.1/venafi-pki-backend_v0.0.1+1_linux.zip
   $ unzip venafi-pki-backend_v0.0.1+1_linux.zip
   $ mv venafi-pki-backend /etc/vault/vault_plugins
   ```

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

1. Get the SHA-256 checksum of the `vault-pki-backend-venafi` plugin binary:

   ```text
   $ SHA256=$(sha256sum /etc/vault/vault_plugins/venafi-pki-backend| cut -d' ' -f1)
   ```

1. Register the `vault-pki-backend-venafi` plugin in the Vault
   [system catalog](https://www.vaultproject.io/docs/internals/plugins#plugin-catalog):

   ```text
   $ vault write sys/plugins/catalog/secret/venafi-pki-backend \
       sha_256="${SHA256}" command="venafi-pki-backend"
   Success! Data written to: sys/plugins/catalog/secret/pki-backend-venafi
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
   Protection Platform or a DevOps project zone for Venafi Cloud. Obtain the `access_token`
   and `refresh_token` for Trust Protection Platform using the the VCert CLI `getcred`
   action or the Platform's Authorize REST API method. To see other available options for
   the role after it is created, use `vault path-help venafi-pki/venafi/:name`.

   **Trust Protection Platform**:

   ```
   $ vault write venafi-pki/venafi/tpp \
       url="https://tpp.venafi.example" \
       access_token="tn1PwE1QTZorXmvnTowSyA=="
       refresh_token="MGxV7DzNnclQi9CkJMCXCg==" \
       zone="DevOps\\HashiCorp Vault" \
       trust_bundle_file="/opt/venafi/bundle.pem"
   Success! Data written to: venafi-pki/venafi/tpp
   ```

   **Venafi Cloud**:

   ```
   $ vault write venafi-pki/venafi/cloud \
       apikey="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
       zone="zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
   Success! Data written to: venafi-pki/roles/cloud
   ```

1. Lastly, configure a [role](https://www.vaultproject.io/api-docs/secret/pki#create-update-role)
   that maps a name in Vault to a Venafi secret for enrollment. To see other available
   options for the role after it is created, use `vault path-help venafi-pki/roles/:name`.

   **Trust Protection Platform**:

   ```text
   $ vault write venafi-pki/roles/tpp \
       venafi_secret=tpp \
       generate_lease=true store_by=serial store_pkey=true \
       allowed_domains=example.com \
       allow_subdomains=true
   Success! Data written to: venafi-pki/roles/tpp
   ```

   **Venafi Cloud**:

   ```text
   $ vault write venafi-pki/roles/cloud \
       venafi_secret=cloud \
       generate_lease=true store_by=serial store_pkey=true \
       allowed_domains=example.com \
       allow_subdomains=true
   Success! Data written to: venafi-pki/roles/cloud
   ```

## Usage

After the Venafi secrets engine is configured and a user/machine has a Vault
token with the proper permission, it can enroll certificates using Venafi.

1. Generate a certificate by writing to the `/issue` endpoint with the name of
   the role:

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

   **Venafi Cloud**:

   ```text
   $ vault write venafi-pki/issue/cloud common_name="common-name.example.com" \
       alt_names="dns-san-1.example.com,dns-san-2.example.com"

   Key                  Value
   ---                  -----
   lease_id             venafi-pki/issue/cloud/1WCNvXKiwboWfRRfjzlPAwEi
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

   **Venafi Cloud**:

   ```text
   $ vault write venafi-pki/sign/cloud csr=@example.req

   Key                  Value
   ---                  -----
   lease_id             venafi-pki/sign/cloud/fF44FdMAjuCdC29w3Ff81hes
   lease_duration       167h59m58s
   lease_renewable      false
   certificate          -----BEGIN CERTIFICATE-----
   certificate_chain    -----BEGIN CERTIFICATE-----
   common_name          common-name.example.com
   serial_number        76:55:e2:14:de:c8:3f:e1:64:4a:fa:37:d4:6e:f5:ef:5e:4c:16:5b
   ```

## API

Venafi Machine Identity Secrets Engine uses the same
[Vault API](https://www.vaultproject.io/api/secret/pki)
as the built-in PKI secrets engine. Some methods, such as those for
managing certificate authorities, do not apply.

## Upgrading

To upgrade to a new version of this plugin, follow the 
[standard procedure](https://www.vaultproject.io/docs/upgrading/plugins).
There is no CLI for reloading plugins but you can use cURL to invoke it
from the command line like this (after you've deployed and successfully
registered the new version of the plugin):

```text
curl --request PUT \
     --header "X-Vault-Token: s.32K0lvvzWqFssLOCPtKN4AQo" \
     --data '{ "plugin": "venafi-pki-backend" }' \
     https://vault.example.com:8200/v1/sys/plugins/reload/backend
```

:warning: **IMPORTANT:** Every member of a Vault cluster must be running
with the same version of the plugin to avoid inconsistent, unexpected, and
possibly erroneous results.
