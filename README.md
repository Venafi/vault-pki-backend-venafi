# Venafi PKI plugin backend for HashiCorp Vault

<img src="https://www.venafi.com/sites/default/files/content/body/Light_background_logo.png" width="330px" height="69px"/>  

This solution enables [HashiCorp Vault](https://www.vaultproject.io/) users to have certificate requests fulfilled by the [Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or [Venafi Cloud](https://www.venafi.com/platform/cloud/devops) ensuring compliance with corporate security policy and providing visibility into certificate issuance enterprise wide.

## Dependencies

* Hashicorp Vault: https://www.vaultproject.io/downloads.html
* Consul Template: https://github.com/hashicorp/consul-template#installation
* Docker Compose: https://docs.docker.com/compose/install/

## Requirements for use with Trust Protection Platform

> Note: The following assume certificates will be enrolled by a Microsoft Active Directory Certificate Services (ADCS) certificate authority. Other CAs will also work with this solution but may have slightly different requirements.

1. The Microsoft CA template appropriate for issuing Vault certificates must be assigned by policy, and should have the "Automatically include CN as DNS SAN" option enabled.

2. The WebSDK user that Vault will be using to authenticate with the Venafi Platform has been granted view, read, write, and create permission to their policy folder.

3. The CRL distribution point and Authority Information Access (AIA) URIs configured for certificates issued by the Microsoft ADCS must start with an HTTP URI (non-default configuration).  If an LDAP URI appears first in the X509v3 extensions, NGINX ingress controllers will fail because they aren't able to retrieve CRL and OCSP information. Example:

```
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

### Establishing Trust between Vault and Trust Protection Platform

It is not common for the Venafi Platform's REST API (WebSDK) to be secured using a certificate issued by a publicly trusted CA, therefore establishing trust for that server certificate is a critical part of your configuration.  Ideally this is done by obtaining the root CA certificate in the issuing chain in PEM format and copying that file to your Vault server (e.g. /opt/venafi/bundle.pem).  You then reference that file using the 'trust_bundle_file' parameter whenever you create a new PKI role in your Vault.

## Quickstart, Step by Step

1. Familiarize yourself with the [HashiCorp Vault Plugin System](https://www.vaultproject.io/docs/internals/plugins.html)

2. Download the current `vault-pki-backend-venafi` release package for your operating system and unzip the plugin to the `/etc/vault/vault_plugins` directory (or a custom directory of our choosing):
    ```
    wget https://github.com/Venafi/vault-pki-backend-venafi/releases/download/v0.3-11.5-alpha.161/venafi-pki-backend_0.3-11.5.161_linux.zip
    unzip venafi-pki-backend_0.3-11.5.161_linux.zip
    mv venafi-pki-backend /etc/vault/vault_plugins
    ```

3. Configure the plugin directory for your Vault by specifying it in the startup configuration file:
    ```
    echo 'plugin_directory = "/etc/vault/vault_plugins"' > vault-config.hcl
    ```

4. Start your Vault (note: if you don't have working configuration you can start it in dev mode):
    ```
    vault server -log-level=debug -dev -config=vault-config.hcl
    ```

5.  Export the VAULT_ADDR environment variable so that the Vault client will interact with the local Vault:
    ```
    export VAULT_ADDR=http://127.0.0.1:8200
    ```

6. Get the SHA-256 checksum of `vault-pki-backend-venafi` plugin binary:
    ```
    SHA256=$(shasum -a 256 /etc/vault/vault_plugins/venafi-pki-backend| cut -d' ' -f1)
    ```

7. Add the `vault-pki-backend-venafi` plugin to the Vault system catalog:
    ```
    vault write sys/plugins/catalog/secret/venafi-pki-backend sha_256="${SHA256}" command="venafi-pki-backend"
    ```

8. Enable the secrets backend for the `venafi-pki-backend` plugin:
    ```
    vault secrets enable -path=venafi-pki -plugin-name=venafi-pki-backend plugin
    ```

9. Create a [PKI role](https://www.vaultproject.io/docs/secrets/pki/index.html) for the `venafi-pki` backend:

    **Venafi Cloud**:
    ```
    vault write venafi-pki/roles/cloud-backend \
        apikey="AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEE" \
        zone="Vault Certificates" \
        generate_lease=true store_by_cn=true store_pkey=true store_by_serial=true ttl=1h max_ttl=1h \
        allowed_domains=example.com \
        allow_subdomains=true
    ```
    
    **Venafi Platform**:
    ```
    vault write venafi-pki/roles/tpp-backend \
        tpp_url="https://tpp.venafi.example:443/vedsdk" \
        tpp_user="local:admin" \
        tpp_password="password" \
        zone="DevOps\\Vault Backend" \
        trust_bundle_file="/opt/venafi/bundle.pem" \
        generate_lease=true store_by_cn=true store_pkey=true store_by_serial=true ttl=1h max_ttl=1h \
        allowed_domains=example.com \
        allow_subdomains=true
    ```
    > Note: Role options can be viewed using `vault path-help vault-pki-backend-venafi/roles/<ROLE_NAME>`

10. Enroll a certificate:

    **Venafi Cloud**:
    ```
    vault write venafi-pki/issue/cloud-backend common_name="test.example.com" alt_names="test-1.example.com,test-2.example.com"
    ```
    
    **Venafi Platform**:
    ```
    vault write venafi-pki/issue/tpp-backend common_name="test.example.com" alt_names="test-1.example.com,test-2.example.com"
    ```

11. Sign CSR  
    **Generate CSR**
    ```
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
    ```
    vault write venafi-pki/sign/cloud-backend csr=@myserver.csr
    ```
    
    **Venafi Platform**:
    ```
    vault write venafi-pki/sign/tpp-backend csr=@myserver.csr
    ```

### Running under Windows
 If you want to run plugin on Windows the following environment variables must specified to restrict the port that will be assigned to be from within a specific range. If not values are provided plugin will exit with error. For more information please see https://github.com/hashicorp/go-plugin/pull/111

  * `PLUGIN_MIN_PORT`: Specifies the minimum port value that will be assigned to the listener.

  * `PLUGIN_MAX_PORT`: Specifies the maximum port value that will be assigned to the listener.
  
  Example:
  ```
  setx PLUGIN_MIN_PORT 55500
  setx PLUGIN_MAX_PORT 55600
  ```
 
 
## Demonstrating End-to-End

> Note: Here we'll use a Makefile to encapsulate several command sequences in a single step. For specific details on those commands and their parameters, please review the contents of the [Makefile](Makefile) itself.

1. Export your Venafi Platform and/or Venafi Cloud configuration variables

    Venafi Platform variables:
    ```
    export TPPUSER=<WebSDK User for Venafi Platform, e.g. "admin">
    export TPPPASSWORD=<Password for WebSDK User, e.g. "password">
    export TPPURL=<URL of Venafi Platform WebSDK, e.g. "https://venafi.example.com/vedsdk">
    export TPPZONE=<Name of the policy folder under which all certificates will be requested>
    export TRUST_BUNDLE=/bundle.pem
    ```

    The syntax for the Venafi Platform policy folder can be tricky. If the policy folder name contains spaces then it must be wrapped in double quotes like this:
    ```
    export TPPZONE="My Policy" * 
    ```

    And if the policy folder is not at the root of the policy tree (nested folder) you need to escape the backslash delimiters twice (four backslashes in total):
    ```
    export TPPZONE="Parent Folder\\\\Child Folder"
    ```

    Venafi Cloud variables:
    ```
    export CLOUDAPIKEY=<API key for Venafi Cloud, e.g. "142231b7-cvb0-412e-886b-6aeght0bc93d">
    export CLOUDZONE=<Zone that governs all certificates that are requested, e.g. "Default">
    export CLOUDURL=<only set when instructed to use a non-production instance of Venafi Cloud>
    ```

2. Run `make prod`

3. Follow the Vault's on screen instructions to enter the unseal key and then the root token

4. Export the root token to the VAULT_TOKEN variable (see example in the output)
    ```
    export VAULT_TOKEN="enter-root-token-here"
    ```

5. Check Vault status on http://localhost:8200/ui (root token required) and Consul on http://localhost:8500

6. Run `make consul_template_fake -e` to check that Vault is working

7. Run the following commands to check Venafi Platform
    ```
    make consul_template_tpp -e
    echo|openssl s_client -connect localhost:3443
    ```

    Or go to the URL https://127.0.0.1:3443

8. Run the following commands to check Venafi Cloud
    ```
    make consul_template_cloud -e
    echo|openssl s_client -connect localhost:2443
    ```

    Or go to the URL https://127.0.0.1:2443

9. You also can check how Vault is working without using a Consul Template by running the following commands for Fake, Platform and Cloud endpoints, respectively:
    ```
    make fake -e
    make tpp -e
    make cloud -e
    ```

10. Cleanup:
    ```
    docker-compose down
    docker ps|grep vault-demo-nginx|awk '{print $1}'|xargs docker rm -f
    ```

## Usage Scenarios

Firstly you need to mount the plugin which you can do by running `make prod` as described in the previous section. You can also do it manually, using following instructions:

1. If you want to use different plugin image, edit the image section under vault service in the [docker-compose.yaml](docker-compose.yaml) file.

2. Start Docker Compose using the configuration:
    ```
    docker-compose up -d
    ```

3. Check that all services started using the following commands:
    ```
    docker-compose ps
    docker-compose logs
    ```

4. Log into the running Vault container:
    ```
    docker exec -it $(docker-compose ps |grep Up|grep vault_1|awk '{print $1}') sh
    ```

5. Set the VAULT_ADDR variable:
    ```
    export VAULT_ADDR='http://127.0.0.1:8200'
    ```

6. Initialize the Vault:
    ```
    vault operator init -key-shares=1 -key-threshold=1
    ```
    Here we intializing the Vault with only 1 unseal key part, this is not recommended for production usage. Read more - https://www.vaultproject.io/docs/concepts/seal.html

7. Enter the unseal key, you'll see it as "Unseal Key 1":
    ```
    vault operator unseal UNSEAL_KEY_HERE
    ```

8. Authenticate with the root token, you will see it as "Initial Root Token":
    ```
    vault auth
    ```

9. After successfull authentication get the SHA-256 checksum of plugin binary and store it in variable:
    ```
    SHA256=`sha256sum "/vault_plugin/venafi-pki-backend" | cut -d' ' -f1`
    echo $SHA256
    ```

10. "Write" the plugin into the Vault:
    ```
    vault write sys/plugins/catalog/venafi-pki-backend sha_256="$SHA256" command="venafi-pki-backend"
    ```

11. Enable the Venafi secret backend:
    ```
    vault secrets enable -path=venafi-pki -plugin-name=venafi-pki-backend plugin
    ```

### Get certificate and private key from TPP and run node application with them.

Setup custom TPP role:

```
vault write venafi-pki/roles/custom-tpp \
    tpp_url=https://tpp.venafi.example/vedsdk \
    tpp_user=admin \
    tpp_password=password \
    zone=testpolicy\\vault \
    generate_lease=true \
    store_by_cn="true" \
    store_by_serial="true" \
    store_pkey="true" \
    trust_bundle_file="/opt/venafi/bundle.pem"
```

To setup proper parameters please read path help for the role configuration:
```
vault path-help venafi-pki/roles/tpp
```

Request the certificate:

```
vault write venafi-pki/issue/custom-tpp common_name="tpp-cert1.venqa.venafi.com" alt_names="tpp-cert1-alt1.venqa.venafi.com,tpp-cert1-alt2.venqa.venafi.com"
```

List requested certificates:

```
vault list venafi-pki/certs
```

Store certificate to the pem file:

```
vault read -field=certificate venafi-pki/cert/tpp-cert1.venqa.venafi.com > tls.crt
```

Store private key to the pem file:

```
vault read -field=private_key venafi-pki/cert/tpp-cert1.venqa.venafi.com > tls.key
```


Run docker container with node application:

```
 docker run --rm -it --name hello-node-ssl -p 443:443 \
 -v $(pwd)/tls.crt:/etc/certdata/tls.crt:ro \
 -v $(pwd)/tls.key:/etc/certdata/tls.key:ro \
 arykalin/hello-node:v1
```

Go to the https://localhost to check.

### Get certificate and private key using consul-template engine

We will use role configured on previous scenario

Get consul-template from here: https://releases.hashicorp.com/consul-template/

Create config file consul-template.hcl

```
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

Create template for the certificate file tls.crt.ctmpl

```
cat << EOF > tls.crt.ctmpl
{{ with secret "venafi-pki/issue/custom-tpp" "common_name=tpp-cert1-consul-template.venqa.venafi.com " }}
{{ .Data.certificate }}{{ end }}
EOF
```

Create template for the key file tls.key.ctmpl

```
cat << EOF > tls.key.ctmpl
{{ with secret "venafi-pki/issue/custom-tpp" "common_name=tpp-cert1-consul-template.venqa.venafi.com " }}
{{ .Data.private_key }}{{ end }}
EOF
```

Create launch script app.sh:

```
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

Export vault token variable

```
export VAULT_TOKEN=YOUR_VAULT_TOKEN_SHOULD_BE_HERE
```

Run consul template command

```
consul-template -once -config=consul-template.hcl -vault-token=$(VAULT_TOKEN)
```

Check URL https://localhost:7443 there will be Hello World app with generated certificate

Delete container with running application

```
docker rm -f hello-node-ssl
```

## Developer Quickstart (Linux only)

1. Configure Go build environement (https://golang.org/doc/install) 

2. Change to the project directory and make sure you don't have any symbolic link in the path (Vault doesn't allow symlinks in the plugin paths). You can do it by running `cd $(pwd -P)`

3. Run `unset VAULT_TOKEN && make dev_server` to start Vault in development mode

4. Open new window in the same directory and run
```
unset VAULT_TOKEN
export VAULT_ADDR='http://127.0.0.1:8200'
```

5. Run `vault unseal` and enter unseal key (look for it in the server window) 

6. Put the latest VCert code to your $GOPATH

7. Run `make dev` to build the plugin and mount it to the Vault

8. Run `make fake` to use the configuration with a temporary CA generating the certificate. Check the output you should see something like this:

```
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

5. Edit Makefile and configure credentials for the Venafi Cloud and/or Venafi Platform

6. Run `make cloud` and `make tpp` to check the Cloud and TPP functionality.

## Deploy new image for prod

1. Run `make push` to build the plugin binary and docker image, then deploy the image to DockerHub.

## Debug information

1. Run `make server_debug`

2. Connect to the dlv server using debugger setup (pki-backend-debug in idea, for example)

3. Unseal the Vault

## Testing

There are integration tests written on Ginkgo: https://github.com/onsi/ginkgo

To run them install Ginkgo CLI:
```
go get -u github.com/onsi/ginkgo/ginkgo
```
and run:
```
cd plugin/pki/test/e2e
ginkgo -v
```
