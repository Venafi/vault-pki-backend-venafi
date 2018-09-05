# Venafi plugin backend for Hashicorp Vault

# Quickstart

## Requirements

1. Hashicorp Vault https://www.vaultproject.io/downloads.html

1. Consul template : https://github.com/hashicorp/consul-template#installation

1. docker-compose: https://docs.docker.com/compose/install/

# Requirements for TPP policy

1. Policy should have default template configured

2. Currently vcert (which is used in Venafi issuers) supports only user provided CSR. So it is must be set in the policy.

3. MSCA configuration should have http URI set before the ldap URI in X509 extensions, otherwise NGINX ingress controller couldn't get certificate chain from URL and OSCP will not work. Example:

```
X509v3 extensions:
    X509v3 Subject Alternative Name:
    DNS:test-cert-manager1.venqa.venafi.com}}
    X509v3 Subject Key Identifier: }}
    61:5B:4D:40:F2:CF:87:D5:75:5E:58:55:EF:E8:9E:02:9D:E1:81:8E}}
    X509v3 Authority Key Identifier: }}
    keyid:3C:AC:9C:A6:0D:A1:30:D4:56:A7:3D:78:BC:23:1B:EC:B4:7B:4D:75}}X509v3 CRL Distribution Points:Full Name:
    URI:http://qavenafica.venqa.venafi.com/CertEnroll/QA%20Venafi%20CA.crl}}
    URI:ldap:///CN=QA%20Venafi%20CA,CN=qavenafica,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=venqa,DC=venafi,DC=com?certificateRevocationList?base?objectClass=cRLDistributionPoint}}{{Authority Information Access: }}
    CA Issuers - URI:http://qavenafica.venqa.venafi.com/CertEnroll/qavenafica.venqa.venafi.com_QA%20Venafi%20CA.crt}}
    CA Issuers - URI:ldap:///CN=QA%20Venafi%20CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=venqa,DC=venafi,DC=com?cACertificate?base?objectClass=certificationAuthority}}
```

4. Option in TPP CA configuration template "Automatically include CN as DNS SAN" should be set to true.


## Step by step
1. Export your Venafi Platform or Cloud configuration variables (or both)

    Platfrom variables:
    ```
    export TPPUSER=<web API user for Venafi Platfrom Example: admin>
    export TPPPASSWORD=<Password for web API user Example: password>
    export TPPURL=<URL of Venafi Platform Example: https://venafi.example.com/vedsdk>
    export TPPZONE=<Prepared Platform policy>
    ```

    Platform policy name could be tricky. If you have spaces enter policy in double quotes:
    ```
    export TPPZONE="My Policy"
    ```

    And if you have backslash (nested policy) you should enter four backslashes:
    ```
    export TPPZONE="first\\\\second"
    ```


    Cloud variables:
    ```
    export CLOUDAPIKEY=<API key for cloud Example: 142231b7-cvb0-412e-886b-6aeght0bc93d>
    export CLOUDZONE=<Cloud policy for requesting certificates Example: Default>
    export CLOUDURL=<Set it only if you want to use non production Cloud>
    ```

1. Run `make prod`

3. Follow instructions: enter unseal key, enter root token

4. Export root token to the VAULT_TOKEN variable (seet example in the output)
    ```
    export VAULT_TOKEN="enter-root-token-here"
    ```

5. Check vault status on http://localhost:8200/ui (need ROOT token) and consul on http://localhost:8500

4. Run `make consul_template_fake -e` to check that vault is working

4. Run following commands to check Paltfrom
    ```

    make consul_template_tpp -e
    echo|openssl s_client -connect localhost:3443
    ```

    Or go to the URL https://127.0.0.1:3443

8. Run following commands to check Cloud
    ```
    make consul_template_cloud -e
    echo|openssl s_client -connect localhost:2443
    ```

    Or go to the URL https://127.0.0.1:2443


10. You also can check how vault is working without consul template by running following commands for Fake, Platform and Cloud endpoints:
    ```
    make fake -e
    make tpp -r
    make cloud -e
    ```

11. Cleanup:
    ```
    docker-compose down
    docker ps|grep vault-demo-nginx|awk '{print $1}'|xargs docker rm -f
    ```

# Usage scenarios

Firstly you need to mount the plugin, you can do it by running `make prod` as it described in previous section. Or manually, using following instructions:

1. If you want to use different plugin image edit image section in vault service in docker-compose.yaml file .

1. Start docker compose configuration:
    ```
    docker-compose up -d
    ```

2. Check that all services started using commands:
    ```
    docker-compose ps
    docker-compose logs
    ```
2. Login into started vault container:
    ```
    docker exec -it $(docker-compose ps |grep Up|grep vault_1|awk '{print $1}') sh
    ```

3. Set VAULT_ADDR variable
    ```
    export VAULT_ADDR='http://127.0.0.1:8200'
    ```

3. Initialize the Vault:
    ```
    vault operator init -key-shares=1 -key-threshold=1
    ```
    Here we intializing the Vault with only 1 unseal key part, this is not recommended for production usage. Read more - https://www.vaultproject.io/docs/concepts/seal.html

4. Enter unseal key, you'll see it as "Unseal Key 1":
    ```
    vault operator unseal UNSEAL_KEY_HEERE
    ```

5. Authenticate with root token, you will see it as "Initial Root Token"
    ```
    vault auth
    ```

6. After successfull authentication get sha 256 checksum of binary plugin and store it in variable:
    ```
    SHA256=`sha256sum "/vault_plugin/venafi-pki-backend" | cut -d' ' -f1`
    echo $SHA256
    ```

7. "Write" plugin into the Vault
    ```
    vault write sys/plugins/catalog/venafi-pki-backend sha_256="$SHA256" command="venafi-pki-backend"
    ```

8. Enable Venafi secret backend
    ```
    vault secrets enable -path=venafi-pki -plugin-name=venafi-pki-backend plugin
    ```

## Get certificate and private key from TPP and run node application with them.

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
    store_pkey="true"
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

## Get certificate and private key using consul-template engine

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

# Developement quickstart (for Linux only)


1. Configure Go build environement (https://golang.org/doc/install) 

2. Change dir to the project directory and make sure you don't have sym link in the path (Vault don't allow symlinks in the plugin paths). You can do it by running `cd $(pwd -P)`

2. Run `unset VAULT_TOKEN && make dev_server` it will start vault in developement mode

2. Open new windown in the same directory unset AUTH_TOKEN and export VAULT_ADDRT
```
unset VAULT_TOKEN
export VAULT_ADDR='http://127.0.0.1:8200'
```

3. Run `vault unseal` and enter unseal key (look for it in the server window) 

4. Put the latest vcert code to your $GOPATH

3. Run `make dev` it will build the plugin and mount it to the vault

4. Run `make fake` it will run configuration which is using fake CA to generate certificate. Check the output you should see something like this:

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

5. Edit Makefile and configure credentials for the Venafi Cloud and TPP

6. Run `make cloud` and `make tpp` to check the cloud and TPP functionality.

# Deploy new image for prod

1. Run `make push`, this will build binary, docker image and deploy it to the docker  hub.

# Debug information

1. run `make server_debug`

2. connect to the dlv server using debuger setup (pki-backend-debug in idea for example)
3. unseal the vault

# Testing
There're integration tests written on Ginkgo: https://github.com/onsi/ginkgo
To run them install ginkgo cli:
```
go get -u github.com/onsi/ginkgo/ginkgo
```
and run:
```
cd plugin/pki/test/e2e
ginkgo -v
```