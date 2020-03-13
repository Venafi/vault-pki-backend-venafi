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

## Dependencies

* HashiCorp Vault: https://www.vaultproject.io/downloads.html
* HashiCorp Consul Template: https://github.com/hashicorp/consul-template#installation
* Docker Compose: https://docs.docker.com/compose/install/

## Requirements for Use with Trust Protection Platform

The following content assumes certificates will be enrolled by a Microsoft Active Directory Certificate Services (ADCS) Certificate Authority. Other CAs will also work with this solution but may have slightly different requirements.

* The Microsoft CA template, appropriate for issuing Vault certificates, must be assigned by policy. It should have the "Automatically include CN as DNS SAN" option enabled.

* The WebSDK user that Vault will be using to authenticate with the Venafi Platform has been granted view, read, write, and create permission to the  policy folder.

* The CRL distribution point and Authority Information Access (AIA) URIs configured for certificates issued by the Microsoft ADCS must start with an HTTP URI (non-default configuration). If an LDAP URI appears first in the X509v3 extensions, NGINX ingress controllers will fail because they aren't able to retrieve CRL and OCSP information. Example:

    ```text
    X509v3 extensions:
    X509v3 Subject Alternative Name: DNS:test-cert-manager1.venqa.venafi.com
    X509v3 Subject Key Identifier: 61:5B:4D:40:F2:CF:87:D5:75:5E:58:55:EF:E8:9E:02:9D:E1:81:8E
    X509v3 Authority Key Identifier: keyid:3C:AC:9C:A6:0D:A1:30:D4:56:A7:3D:78:BC:23:1B:EC:B4:7B:4D:75
    X509v3 CRL Distribution Points: Full Name:
    URI:http://qavenafica.venqa.venafi.com/CertEnroll/QA%20Venafi%20CA.crl
    URI:ldap:///CN=QA%20Venafi%20CA,CN=qavenafica,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=venqa,DC=venafi,DC=com?certificateRevocationList?base?objectClass=cRLDistributionPoint
    Authority Information Access:
    CA Issuers - URI:http://qavenafica.venqa.venafi.com/CertEnroll/qavenafica.venqa.venafi.com_QA%20Venafi%20CA.crt
    CA Issuers - URI:ldap:///CN=QA%20Venafi%20CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=venqa,DC=venafi,DC=com?cACertificate?base?objectClass=certificationAuthority
    ```

### Trust Requirements Between Vault and Trust Protection Platform

It is not common for the Venafi Platform's REST API (WebSDK) to be secured using a certificate issued by a publicly trusted CA. Therefore, establishing trust for that server certificate is a critical part of your configuration.  Ideally, you can get  the root CA certificate in the issuing chain in PEM format. Copy that file to your Vault server (e.g. /opt/venafi/bundle.pem).  You then reference that file using the 'trust_bundle_file' parameter whenever you create a new PKI role in your Vault.

## Quick Start, Step by Step

1. Familiarize yourself with the [HashiCorp Vault Plugin System](https://www.vaultproject.io/docs/internals/plugins.html).

1. Download the current `vault-pki-backend-venafi` release package for your operating system. Unzip the plugin to the `/etc/vault/vault_plugins` directory (or another directory):

    ```text
    wget https://github.com/Venafi/vault-pki-backend-venafi/releases/latest/download/venafi-pki-backend_0.5.2+586_linux.zip
    unzip venafi-pki-backend_0.5.2+586_linux.zip
    mv venafi-pki-backend /etc/vault/vault_plugins
    ```

    **NOTE**: The zip file name, referenced above, will change as new versions are released.  Check [here](https://github.com/Venafi/vault-pki-backend-venafi/releases/latest) for the current file name to use with the commands.

1. In the startup configuration file, configure the plugin directory for your Vault:

    ```text
    echo 'plugin_directory = "/etc/vault/vault_plugins"' > vault-config.hcl
    ```

    **NOTE**: If plugin directory is a symlink, Vault responds with an error[:bookmark:](https://groups.google.com/forum/#!topic/vault-tool/IVYLA3aH72M). If you're configuring on a MacBook, /etc is default symlinked to /private/etc. To prevent the error from occurring, change the `plugin_directory` to a non-symlinked directory. For example "/private/etc/vault/vault_plugins". If you make this change, keep it in mind as you go through the remaining steps.

1. Start your Vault. If you don't have a working configuration you can start it in dev mode:

    ```text
    vault server -log-level=debug -dev -config=vault-config.hcl
    ```

1. Export the `VAULT_ADDR environment` variable so that the Vault client will interact with the local Vault:

    ```text
    export VAULT_ADDR=http://127.0.0.1:8200
    ```

1. Get the SHA-256 checksum of the `vault-pki-backend-venafi` plugin binary:

    ```text
    SHA256=$(shasum -a 256 /etc/vault/vault_plugins/venafi-pki-backend| cut -d' ' -f1)
    ```

1. Add the `vault-pki-backend-venafi` plugin to the Vault system catalog:

    ```text
    vault write sys/plugins/catalog/secret/venafi-pki-backend sha_256="${SHA256}" command="venafi-pki-backend"
    ```

    **NOTE**: If you get an error that says "can not execute files outside of configured plugin directory", it's probably because you didn't set the plugin directory correctly with a non-symlinked directory. Go back to step 3 and reread the note. Also, make sure this change is reflected when calling for the SHA-256 checksum.

1. Enable the secrets backend for the `venafi-pki-backend` plugin:

    ```text
    vault secrets enable -path=venafi-pki -plugin-name=venafi-pki-backend plugin
    ```

1. Get help for all role options:_
    ```
    vault path-help venafi-pki/roles/role
    ```

1. Create a [PKI role](https://www.vaultproject.io/docs/secrets/pki/index.html) for the `venafi-pki` backend.

    **Venafi Cloud**:

    ```text
    vault write venafi-pki/roles/cloud-backend \
    apikey="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
    zone="zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz" \
    generate_lease=true store_pkey=true ttl=1h max_ttl=1h \
    allowed_domains=example.com \
    allow_subdomains=true
    ```

    **NOTE**: In special situations, where you need a non-production Venafi Cloud instance, you need to add the URL for that environment using the `cloud_url` parameter.  When not specified, `cloud_url` defaults to _api.venafi.cloud_.

    **Venafi Platform**:

    ```text
    vault write venafi-pki/roles/tpp-backend \
    tpp_url="https://tpp.venafi.example:443/vedsdk" \
    tpp_user="local:admin" \
    tpp_password="password" \
    zone="DevOps\\Vault Backend" \
    trust_bundle_file="/opt/venafi/bundle.pem" \
    generate_lease=true store_pkey=true ttl=1h max_ttl=1h \
    allowed_domains=example.com \
    allow_subdomains=true
    ```

    **NOTE**: To view role options, use `vault path-help vault-pki-backend-venafi/roles/<ROLE_NAME>`.

1. Enroll a certificate:

    **Venafi Cloud**:

    ```text
    vault write venafi-pki/issue/cloud-backend common_name="test.example.com" alt_names="test-1.example.com,test-2.example.com"
    ```

    **Venafi Platform**:

    ```text
    vault write venafi-pki/issue/tpp-backend common_name="test.example.com" alt_names="test-1.example.com,test-2.example.com"
    ```

1. Generate and sign the CSR:  

    ```text
    cat <<EOF> csr.conf
    [req]
    default_bits = 4096
    prompt = no
    default_md = sha256
    req_extensions = req_ext
    distinguished_name = dn

    [ dn ]
    CN = test-csr-32313131.vfidev.com

    [ req_ext ]
    subjectAltName = @alt_names

    [ alt_names ]
    DNS.1 = alt1-test-csr-32313131.vfidev.com
    DNS.2 = alt2-test-csr-32313131.vfidev.com

    EOF
    openssl req -new -config csr.conf -keyout myserver.key -out myserver.csr -passin pass:somepassword -passout pass:anotherpassword
    ```

    **Venafi Cloud**:

    ```text
    vault write venafi-pki/sign/cloud-backend csr=@myserver.csr
    ```

    **Venafi Platform**:

    ```text
    vault write venafi-pki/sign/tpp-backend csr=@myserver.csr
    ```

    **NOTE**: If you get an error on this step, it's most likely caused by a misconfigured CA or a malformed CN value. Feel free to edit the generated CSR when necessary.

### Windows Example

 If you want to run the plugin on Windows, you must restrict the port assignment to a specific range. Otherwise, the plugin will exit with an error. For more information please see [https://github.com/hashicorp/go-plugin/pull/111](https://github.com/hashicorp/go-plugin/pull/111).

* `PLUGIN_MIN_PORT`: Specifies the minimum port value that will be assigned to the listener.
* `PLUGIN_MAX_PORT`: Specifies the maximum port value that will be assigned to the listener.
  
    Example:

    ```bat
    setx PLUGIN_MIN_PORT 55500
    setx PLUGIN_MAX_PORT 55600
    ```

### Demonstrating End-to-End

Here, we'll use a Makefile to encapsulate several command sequences in a single step. For specific details on those commands and their parameters, please review the contents of the [Makefile](Makefile) itself.

1. Export your Venafi Platform and/or Venafi Cloud configuration variables:

    **Venafi Platform Variables**

    ```text
    export TPPUSER=<WebSDK User for Venafi Platform, e.g. "admin">
    export TPPPASSWORD=<Password for WebSDK User, e.g. "password">
    export TPPURL=<URL of Venafi Platform WebSDK, e.g. "https://venafi.example.com/vedsdk">
    export TPPZONE=<Name of the policy folder that will hold all certificates that will be requested>
    export TRUST_BUNDLE=/bundle.pem
    ```

    The syntax for the Venafi Platform policy folder can be tricky. If the policy folder name contains spaces, it must be wrapped in double quotes like this:

    ```text
    export TPPZONE="My Policy" *
    ```

    Also, if the policy folder is not at the root of the policy tree (nested folder), you need to escape the backslash delimiters twice (four backslashes in total):

    ```text
    export TPPZONE="Parent Folder\\\\Child Folder"
    ```

    **Venafi Cloud Variables**

    ```text
    export CLOUDAPIKEY=<API key for Venafi Cloud>
    export CLOUDZONE=<Zone that governs all certificates that are requested, refer to Venafi Cloud UI to get Zone ID>
    export CLOUDURL=<only set when instructed to use a non-production instance of Venafi Cloud>
    ```

1. Run `make prod`.

1. Follow the Vault [unseal instructions](https://https://www.vaultproject.io/docs/commands/operator/unseal/) to enter the unseal key and get the root token.


1. Export the root token to the VAULT_TOKEN variable (see example in the output).

    ```text
    export VAULT_TOKEN="enter-root-token-here"
    ```

1. Check Vault status on http://localhost:8200/ui (root token required) and Consul on http://localhost:8500.

1. To verify that the Vault is working, run `make consul_template_fake -e`.

1. Run the following commands to check Venafi Platform:

    ```text
    make consul_template_tpp -e
    echo|openssl s_client -connect localhost:3443
    ```

    Or go to the URL https://127.0.0.1:3443.

1. Run the following commands to check Venafi Cloud.

    ```text
    make consul_template_cloud -e
    echo|openssl s_client -connect localhost:2443
    ```

    Or go to the URL https://127.0.0.1:2443.

1. You also can verify how the Vault is working without using a HashiCorp Consul Template. Run the following commands for Fake, Platform and Cloud endpoints, respectively:

    ```text
    make fake -e
    make tpp -e
    make cloud -e
    ```

1. Cleanup:

    ```text
    docker-compose down
    docker ps|grep vault-demo-nginx|awk '{print $1}'|xargs docker rm -f
    ```

## Usage Scenarios

First, mount the Venafi plugin. Then, use one of the following sections to get the certificate and private key:

* Use Trust Protection Platform and Node application
* Use Consul-template engine

### Mount Venafi Plugin

To mount the plugin automatically run `make prod` as described in the previous section. To manually mount the plugin:

1. If you want to use a different plugin image, edit the image section under the vault service in the [docker-compose.yaml](docker-compose.yaml) file.

1. Start Docker Compose using the configuration:

    ```text
    docker-compose up -d
    ```

1. Check that all services started using the following commands:

    ```text
    docker-compose ps
    docker-compose logs
    ```

1. Log into the running Vault container:

    ```text
    docker exec -it $(docker-compose ps |grep Up|grep vault_1|awk '{print $1}') sh
    ```

1. Set the `VAULT_ADDR` variable:

    ```text
    export VAULT_ADDR='http://127.0.0.1:8200'
    ```

1. Initialize the Vault:

    ```text
    vault operator init -key-shares=1 -key-threshold=1
    ```

    Here, we initialize the Vault with only one unseal key part. However, this is not recommended for production usage. Read more at [https://www.vaultproject.io/docs/concepts/seal.html](https://www.vaultproject.io/docs/concepts/seal.html).

1. Enter the unseal key. You'll see it as "Unseal Key 1":

    ```text
    vault operator unseal UNSEAL_KEY_HERE
    ```

1. Authenticate with the root token, you will see it as "Initial Root Token":

    ```text
    vault auth
    ```

1. After successful authentication, get the SHA-256 checksum of plugin binary and store it in a variable:

    ```text
    SHA256=`sha256sum "/vault_plugin/venafi-pki-backend" | cut -d' ' -f1`
    echo $SHA256
    ```

1. "Write" the plugin into the Vault:

    ```text
    vault write sys/plugins/catalog/venafi-pki-backend sha_256="$SHA256" command="venafi-pki-backend"
    ```

1. Enable the Venafi secret backend:

    ```text
    vault secrets enable -path=venafi-pki -plugin-name=venafi-pki-backend plugin
    ```

### Use Trust Protection Platform and Node Application

Get the certificate and private key from Trust Protection Platform, and then pass them to the Node application.

1. Set up custom TPP role:

    ```text
    vault write venafi-pki/roles/custom-tpp \
    tpp_url=https://tpp.venafi.example/vedsdk \
    tpp_user=admin \
    tpp_password=password \
    zone=testpolicy\\vault \
    generate_lease=true \
    trust_bundle_file="/opt/venafi/bundle.pem"
    ```

1. To set up proper parameters, please read the path-help for the role configuration:

    ```text
    vault path-help venafi-pki/roles/tpp
    ```

1. Request the certificate:

    ```text
    vault write venafi-pki/issue/custom-tpp common_name="tpp-cert1.venqa.venafi.com" alt_names="tpp-cert1-alt1.venqa.venafi.com,tpp-cert1-alt2.venqa.venafi.com"
    ```

1. List requested certificates:

    ```text
    vault list venafi-pki/certs
    ```

1. Store certificate to the PEM file:

    ```text
    vault read -field=certificate venafi-pki/cert/tpp-cert1.venqa.venafi.com > tls.crt
    ```

1. Store private key to the PEM file:

    ```text
    vault read -field=private_key venafi-pki/cert/tpp-cert1.venqa.venafi.com > tls.key
    ```

1. Run docker container with Node application:

    ```text
    docker run --rm -it --name hello-node-ssl -p 443:443 \
    -v $(pwd)/tls.crt:/etc/certdata/tls.crt:ro \
    -v $(pwd)/tls.key:/etc/certdata/tls.key:ro \
    arykalin/hello-node:v1
    ```

1. Go to the https://localhost to check.

### Use Consul-template Engine

To get the certificate and private key from HashiCorp Consul-template Engine, you need the role from the previous scenario.

1. Get the consul-template from [https://releases.hashicorp.com/consul-template/](https://releases.hashicorp.com/consul-template/).

1. Create config file consul-template.hcl:

    ```text
    cat << EOF > consul-template.hcl

    //Configuration of consul backend
    consul {
    auth {
    enabled  = false
    }
    address = "127.0.0.1:8500"

    retry {
    enabled = true
    attempts = 12
    backoff = "250ms"
    max_backoff = "1m"
    }

    ssl {
    enabled = false
    }
    }

    reload_signal = "SIGHUP"
    kill_signal = "SIGINT"
    max_stale = "10m"
    log_level = "info"
    pid_file = "/tmp/venafi-demo-consul-template.pid"

    //Vault configuration
    vault {
    address = "http://127.0.0.1:8200"
    grace = "5m"
    unwrap_token = false
    renew_token = false
    }

    //template for the certificate file
    template {
    source = "tls.crt.ctmpl"
    destination = "tls.crt"
    }

    //template for the key file
    template {
    source = "tls.key.ctmpl"
    destination = "tls.key"
    command = "/bin/sh -c './app.sh'"
    }
    EOF
    ```

1. Create the template for the certificate file, tls.crt.ctmpl:

    ```text
    cat << EOF > tls.crt.ctmpl
    {{ with secret "venafi-pki/issue/custom-tpp" "common_name=tpp-cert1-consul-template.venqa.venafi.com " }}
    {{ .Data.certificate }}{{ end }}
    EOF
    ```

1. Create the template for the key file, tls.key.ctmpl:

    ```text
    cat << EOF > tls.key.ctmpl
    {{ with secret "venafi-pki/issue/custom-tpp" "common_name=tpp-cert1-consul-template.venqa.venafi.com " }}
    {{ .Data.private_key }}{{ end }}
    EOF
    ```

1. Create the launch script app.sh:

    ```text
    cat << 'EOF' > app.sh
    #!/bin/bash
    cont=hello-node-ssl
    PORT=7443
    docker rm -f $cont || echo "Conrtainer $cont doesn't exists"
    docker run --name $cont -d -p ${PORT}:443 \
    -v $(pwd)/tls.crt:/etc/certdata/tls.crt:ro \
    -v $(pwd)/tls.key:/etc/certdata/tls.key:ro \
    arykalin/hello-node:v1
    echo "app started, check URL https://localhost:${PORT}"
    EOF
    chmod +x app.sh
    ```

1. Export the vault token variable:

    ```text
    export VAULT_TOKEN=YOUR_VAULT_TOKEN_SHOULD_BE_HERE
    ```

1. Run consul template command:

    ```text
    consul-template -once -config=consul-template.hcl -vault-token=$(VAULT_TOKEN)
    ```

1. Use the generated certificate to check https://localhost:7443 for a Hello World app.

1. Delete the container with the running application:

    ```text
    docker rm -f hello-node-ssl
    ```

## Developer Quick Start (Linux only)

1. Configure [Go build environment](https://golang.org/doc/install)).

1. Change to the project directory and make sure you don't have any symbolic links in the path. The Vault doesn't allow symlinks in the plugin paths. For example, `cd $(pwd -P)`.

1. To start the Vault in development mode, run `unset VAULT_TOKEN && make dev_server`.

1. Open the new window in the same directory and run:

    ```text
    unset VAULT_TOKEN
    export VAULT_ADDR='http://127.0.0.1:8200'
    ```

1. Run `vault unseal` and enter the unseal key that is located in the server window.

1. Put the latest VCert code to your $GOPATH.

1. To build the plugin and mount it to the Vault, run `make dev`.

1. To use the configuration with a temporary CA generating the certificate, run `make fake`. Then verify the output. You should see something like this:

    ```text
   vault read -field=Chain venafi-pki/certs/fake|openssl x509 -text -inform pem -noout -certopt no_header,no_version,no_serial,no_signame,no_pubkey,no_sigdump,no_aux
            Issuer: C=US, ST=Utah, L=Salt Lake City, O=Venafi, OU=NOT FOR PRODUCTION, CN=VCert Test Mode CA
            Validity
                Not Before: Jun  4 13:55:03 2018 GMT
                Not After : Sep  2 13:55:03 2018 GMT
            Subject: CN=fake-bnhz5.fake.example.com
            X509v3 extensions:
                X509v3 Extended Key Usage:
                    TLS Web Server Authentication
                X509v3 Basic Constraints: critical
                    CA:FALSE
                X509v3 Authority Key Identifier:
                    keyid:CE:A4:45:0E:F2:D7:D2:6C:F8:02:33:DB:E3:9B:4B:19:AB:E6:F0:07
                X509v3 Subject Alternative Name:
                    DNS:alt-bnhz5.fake.example.com, DNS:alt2-bnhz5.fake.example.com, DNS:fake-bnhz5.fake.example.com
    ```

1. Edit the Makefile and configure credentials for the Venafi Cloud and/or Venafi Platform.

1. To check the Cloud and TPP functionality, run `make cloud` and `make tpp`.

## Deploy New Image for Prod

1. To build the plugin binary and Docker image and deploy it to DockerHub, run `make push`.

## Debug Information

1. Run `make server_debug`.

1. Connect to the dlv server using the debugger setup (pki-backend-debug in idea, for example).

1. Unseal the Vault.

## Testing

We have tests for fake vcert endpoint, if you don't have TPP or Cloud you can test all endpoints using this command:_

```
go test -run  ^TestFake -v github.com/Venafi/vault-pki-backend-venafi/plugin/pki
```

Also you can run integration tests but for it you need to add TPP\Cloud credentials._

Example fro TPP:_
```
export TPPUSER='admin'
export TPPPASSWORD='strongPassword'
export TRUST_BUNDLE="/opt/venafi/bundle.pem"
export TPPURL="https://tpp.example.com:/vedsdk"
export TPPZONE="devops\\\\vcert"

```
Example for Cloud:_
```
export CLOUDZONE="xxxxxxx-xxxxx-xxxx-xxxx-xxxxxxx"
export CLOUDAPIKEY='xxxxxxx-xxxxx-xxxx-xxxx-xxxxxxx'
```

To run tests use make commands:_
```
make test_tpp
make test_cloud
```

There are also e2e tests written on [Ginkgo](https://github.com/onsi/ginkgo).

1. Install the Ginkgo CLI:

    ```bash
    go get -u github.com/onsi/ginkgo/ginkgo
    ```

1. Run:

    ```bash
    cd plugin/pki/test/e2e
    ginkgo -v
    ```
