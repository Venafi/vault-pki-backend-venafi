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

## Demonstrating End-to-End

Here, we'll use a Makefile to encapsulate several command sequences in a single step. For specific details on those commands and their parameters, please review the contents of the [Makefile](Makefile) itself.

1. Export your Venafi Platform and/or Venafi Cloud configuration variables:

    **Venafi Platform Variables**

    ```text
    export TPP_USER=<WebSDK User for Venafi Platform, e.g. "admin">
    export TPP_PASSWORD=<Password for WebSDK User, e.g. "password">
    export TPP_URL=<URL of Venafi Platform WebSDK, e.g. "https://venafi.example.com/vedsdk">
    export TPP_ZONE=<Name of the policy folder that will hold all certificates that will be requested>
    export TRUST_BUNDLE=/bundle.pem
    ```

    The syntax for the Venafi Platform policy folder can be tricky. If the policy folder name contains spaces, it must be wrapped in double quotes like this:

    ```text
    export TPP_ZONE="My Policy" *
    ```

    Also, if the policy folder is not at the root of the policy tree (nested folder), you need to escape the backslash delimiters twice (four backslashes in total):

    ```text
    export TPP_ZONE="Parent Folder\\\\Child Folder"
    ```

    **Venafi Cloud Variables**

    ```text
    export CLOUD_APIKEY=<API key for Venafi Cloud>
    export CLOUD_ZONE=<Zone that governs all certificates that are requested, refer to Venafi Cloud UI to get Zone ID>
    export CLOUD_URL=<only set when instructed to use a non-production instance of Venafi Cloud>
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
export TPP_USER='admin'
export TPP_PASSWORD='strongPassword'
export TRUST_BUNDLE="/opt/venafi/bundle.pem"
export TPP_URL="https://tpp.example.com:/vedsdk"
export TPP_ZONE="devops\\\\vcert"

```
Example for Cloud:_
```
export CLOUD_ZONE="xxxxxxx-xxxxx-xxxx-xxxx-xxxxxxx"
export CLOUD_APIKEY='xxxxxxx-xxxxx-xxxx-xxxx-xxxxxxx'
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
