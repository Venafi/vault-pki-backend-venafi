###Metadata about this makefile and position
MKFILE_PATH := $(lastword $(MAKEFILE_LIST))
CURRENT_DIR := $(patsubst %/,%,$(dir $(realpath $(MKFILE_PATH))))

###Build parameters
IMAGE_NAME := vault-venafi
DOCKER_IMAGE := venafi/$(IMAGE_NAME)
BUILD_TAG := build
PLUGIN_NAME := venafi-pki-backend
PLUGIN_DIR := bin
PLUGIN_PATH := $(PLUGIN_DIR)/$(PLUGIN_NAME)
DIST_DIR := bin/dist
GO_BUILD := go build -ldflags '-s -w -extldflags "-static"' -a
VERSION=`git describe --abbrev=0 --tags`

ifdef BUILD_NUMBER
VERSION:=$(VERSION)+$(BUILD_NUMBER)
endif

ifdef RELEASE_VERSION
ifneq ($(RELEASE_VERSION),none)
VERSION=$(RELEASE_VERSION)
endif
endif

###Demo scripts parameters
VAULT_VERSION := $(shell vault --version|awk '{print $$2}')
VAULT_CONT := $$(docker-compose ps |grep Up|grep vault_1|awk '{print $$1}')
DOCKER_CMD := docker exec -it $(VAULT_CONT)
VAULT_CMD := $(DOCKER_CMD) vault
CT_CMD := consul-template

MOUNT := venafi-pki
FAKE_VENAFI := fakeVenafi
TPP_VENAFI := tppVenafi
CLOUD_VENAFI := cloudVenafi
TOKEN_VENAFI := tppTokenVenafi

FAKE_ROLE := fake
TPP_ROLE := tpp
CLOUD_ROLE := cloud
TOKEN_ROLE := tppToken

ROLE_OPTIONS := generate_lease=true store_by="cn" store_pkey="true" ttl=1h max_ttl=1h

SHA256 := $$(shasum -a 256 "$(PLUGIN_PATH)" | cut -d' ' -f1)
SHA256_DOCKER_CMD := sha256sum "/vault_plugin/venafi-pki-backend" | cut -d' ' -f1

CHECK_CERT_CMD := ./scripts/tools/check-certificate.sh
CERT_TMP_FILE := /tmp/certificate.crt

# Domain used on Venafi Platform demo resources
TPP_DOMAIN := venqa.venafi.com
# Domain used in Venafi Cloud demo resources
CLOUD_DOMAIN := venafi.example.com
# Domain used in fake demo resources
FAKE_DOMAIN := fake.example.com
#Random site name for demo resources
RANDOM_SITE_EXP := $$(head /dev/urandom | docker run --rm -i busybox tr -dc a-z0-9 | head -c 5 ; echo '')

### Exporting variables for demo and tests
.EXPORT_ALL_VARIABLES:
VAULT_ADDR = http://127.0.0.1:8200
#Must be set,otherwise cloud certificates will timeout
VAULT_CLIENT_TIMEOUT = 180s

#List of certificates issuers CN
TPP_ISSUER_CN = QA Venafi CA
CLOUD_ISSUER_CN = DigiCert Test SHA2 Intermediate CA-1
FAKE_ISSUER_CN = VCert Test Mode CA


version:
	echo "$(VERSION)"

#Need to unset VAULT_TOKEN when running vault with dev parameter.
unset:
	unset VAULT_TOKEN


#Build
build:
	env CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 $(GO_BUILD) -o $(PLUGIN_DIR)/linux/$(PLUGIN_NAME) || exit 1
	env CGO_ENABLED=0 GOOS=linux   GOARCH=386   $(GO_BUILD) -o $(PLUGIN_DIR)/linux86/$(PLUGIN_NAME) || exit 1
	env CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 $(GO_BUILD) -o $(PLUGIN_DIR)/darwin/$(PLUGIN_NAME) || exit 1
	env CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 $(GO_BUILD) -o $(PLUGIN_DIR)/darwin_arm/$(PLUGIN_NAME) || exit 1
	env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO_BUILD) -o $(PLUGIN_DIR)/windows/$(PLUGIN_NAME).exe || exit 1
	env CGO_ENABLED=0 GOOS=windows GOARCH=386   $(GO_BUILD) -o $(PLUGIN_DIR)/windows86/$(PLUGIN_NAME).exe || exit 1
	chmod +x $(PLUGIN_DIR)/*
	shasum -a 256 "$(PLUGIN_DIR)/linux/$(PLUGIN_NAME)" | cut -d' ' -f1 > $(PLUGIN_DIR)/linux/$(PLUGIN_NAME).SHA256SUM
	shasum -a 256 "$(PLUGIN_DIR)/linux86/$(PLUGIN_NAME)" | cut -d' ' -f1 > $(PLUGIN_DIR)/linux86/$(PLUGIN_NAME).SHA256SUM
	shasum -a 256 "$(PLUGIN_DIR)/darwin/$(PLUGIN_NAME)" | cut -d' ' -f1 > $(PLUGIN_DIR)/darwin/$(PLUGIN_NAME).SHA256SUM
	shasum -a 256 "$(PLUGIN_DIR)/darwin_arm/$(PLUGIN_NAME)" | cut -d' ' -f1 > $(PLUGIN_DIR)/darwin_arm/$(PLUGIN_NAME).SHA256SUM
	shasum -a 256 "$(PLUGIN_DIR)/windows/$(PLUGIN_NAME).exe" | cut -d' ' -f1 > $(PLUGIN_DIR)/windows/$(PLUGIN_NAME).exe.SHA256SUM
	shasum -a 256 "$(PLUGIN_DIR)/windows86/$(PLUGIN_NAME).exe" | cut -d' ' -f1 > $(PLUGIN_DIR)/windows86/$(PLUGIN_NAME).exe.SHA256SUM

#quickly build linux for testing
quick_build:
	go build -ldflags '-s -w -extldflags "-static"' -a -o $(PLUGIN_DIR)/$(PLUGIN_NAME) || exit 1

compress:
	mkdir -p $(DIST_DIR)
	rm -f $(DIST_DIR)/*
	echo "Path $(CURRENT_DIR)/$(DIST_DIR)/$(PLUGIN_NAME)_$(VERSION)"
	zip -j "$(CURRENT_DIR)/$(DIST_DIR)/$(PLUGIN_NAME)_$(VERSION)_linux.zip" \
		"$(PLUGIN_DIR)/linux/$(PLUGIN_NAME)" \
		"$(PLUGIN_DIR)/linux/$(PLUGIN_NAME)_linux.sig" \
		"$(PLUGIN_DIR)/linux/$(PLUGIN_NAME).SHA256SUM" || exit 1
	zip -j "$(CURRENT_DIR)/$(DIST_DIR)/$(PLUGIN_NAME)_$(VERSION)_linux86.zip" \
		"$(PLUGIN_DIR)/linux86/$(PLUGIN_NAME)" \
		"$(PLUGIN_DIR)/linux86/$(PLUGIN_NAME)_linux86.sig" \
		"$(PLUGIN_DIR)/linux86/$(PLUGIN_NAME).SHA256SUM" || exit 1
	zip -j "$(CURRENT_DIR)/$(DIST_DIR)/$(PLUGIN_NAME)_$(VERSION)_darwin.zip" \
		"$(PLUGIN_DIR)/darwin/$(PLUGIN_NAME)" \
		"$(PLUGIN_DIR)/darwin/$(PLUGIN_NAME)_darwin.sig" \
		"$(PLUGIN_DIR)/darwin/$(PLUGIN_NAME).SHA256SUM" || exit 1
	zip -j "$(CURRENT_DIR)/$(DIST_DIR)/$(PLUGIN_NAME)_$(VERSION)_darwin_arm.zip" \
			"$(PLUGIN_DIR)/darwin_arm/$(PLUGIN_NAME)" \
			"$(PLUGIN_DIR)/darwin_arm/$(PLUGIN_NAME)_darwin_arm.sig" \
			"$(PLUGIN_DIR)/darwin_arm/$(PLUGIN_NAME).SHA256SUM" || exit 1
	zip -j "$(CURRENT_DIR)/$(DIST_DIR)/$(PLUGIN_NAME)_$(VERSION)_windows.zip" \
		"$(PLUGIN_DIR)/windows/$(PLUGIN_NAME).exe" "$(PLUGIN_DIR)/windows/$(PLUGIN_NAME).exe.SHA256SUM" || exit 1
	zip -j "$(CURRENT_DIR)/$(DIST_DIR)/$(PLUGIN_NAME)_$(VERSION)_windows86.zip"\
		"$(PLUGIN_DIR)/windows86/$(PLUGIN_NAME).exe" "$(PLUGIN_DIR)/windows86/$(PLUGIN_NAME).exe.SHA256SUM" || exit 1


build_docker:
	docker build -t $(DOCKER_IMAGE):$(BUILD_TAG) .

test: linter test_go test_e2e

test_go:
	go test -v \
	    -race \
		$$(go list ./... | \
			grep -v '/vendor/' | \
			grep -v '/e2e' \
		)

test_e2e:
	sed -i "s#image:.*$(IMAGE_NAME).*#image: $(DOCKER_IMAGE):$(BUILD_TAG)#" docker-compose.yaml
	cd plugin/pki/e2e && ginkgo -v

test_tpp:
	go test -tags=tpp -run ^TestTPP -v github.com/Venafi/vault-pki-backend-venafi/plugin/pki

test_vaas:
	go test -tags=vaas -run  ^TestVAAS -v github.com/Venafi/vault-pki-backend-venafi/plugin/pki

test_fake:
	go test -run  ^TestFake -v github.com/Venafi/vault-pki-backend-venafi/plugin/pki

test_token:
	go test -run ^TestTokenIntegration$ -v github.com/Venafi/vault-pki-backend-venafi/plugin/pki

push: build build_docker test_e2e
	docker push $(DOCKER_IMAGE):$(BUILD_TAG)


#Developement server tasks
dev_server: unset
	pkill vault || echo "Vault server is not running"
	sed -e 's#__PLUGIN_DIR__#$(PLUGIN_DIR)#' scripts/config/vault/vault-config.hcl.sed > vault-config.hcl
	vault server -log-level=debug -dev -config=vault-config.hcl

dev: quick_build mount_dev

mount_dev: unset
	vault write sys/plugins/catalog/$(PLUGIN_NAME) sha_256="$(SHA256)" command="$(PLUGIN_NAME)"
	vault secrets disable $(MOUNT) || echo "Secrets already disabled"
	vault secrets enable -path=$(MOUNT) -plugin-name=$(PLUGIN_NAME) plugin

dev_server_debug:
	pkill vault || echo "Vault server is not running"
	sed -e 's#__GOPATH__#'$$GOPATH'#' vault-config.hcl.sed > vault-config.hcl
	dlv --listen=:2345 --headless=true --api-version=2 exec -- vault server -log-level=debug -dev -config=vault-config.hcl


#Production server tasks
prod_server_prepare:
	@echo "Using vault client version $(VAULT_VERSION)"
ifeq ($(VAULT_VERSION),v0.10.3)
	@echo "Vault version v0.10.3 have bug which prevents plugin to work properly. Please update your vault client"
	@exit 1
endif

prod_server_up:
	docker-compose up -d
	@echo "Run: docker-compose logs"
	@echo "to see the logs"
	@echo "Run: docker exec -it cault_vault_1 sh"
	@echo "to login into vault container"
	@echo "Waiting until server start"
	sleep 10


prod_server_init:
	$(VAULT_CMD) operator init -key-shares=1 -key-threshold=1
	@echo "To unseal the vault run:"
	@echo "$(VAULT_CMD) operator unseal UNSEAL_KEY"

prod_server_unseal:
	@echo Enter unseal key:
	$(VAULT_CMD) operator unseal

prod_server_login:
	@echo Enter root token:
	$(VAULT_CMD) login

prod_server_down:
	docker-compose down --remove-orphans

prod_server_logs:
	docker-compose logs -f

prod_server_sh:
	$(DOCKER_CMD) sh

prod: prod_server_prepare prod_server_down prod_server_up prod_server_init prod_server_unseal prod_server_login mount_prod
	@echo "Vault started. To run make command export VAULT_TOKEN variable and run make with -e flag, for example:"
	@echo "export VAULT_TOKEN=enter-root-token-here"
	@echo "make cloud -e"

mount_prod:
	$(eval SHA256 := $(shell echo $$($(DOCKER_CMD) $(SHA256_DOCKER_CMD))))
	$(VAULT_CMD) write sys/plugins/catalog/$(PLUGIN_NAME) sha_256="$$SHA256" command="$(PLUGIN_NAME)"
	$(VAULT_CMD) secrets disable $(MOUNT) || echo "Secrets already disabled"
	$(VAULT_CMD) secrets enable -path=$(MOUNT) -plugin-name=$(PLUGIN_NAME) plugin

#Fake role tasks
fake_config_write:
	vault write $(MOUNT)/venafi/$(FAKE_VENAFI) fakemode="true"
	vault write $(MOUNT)/roles/$(FAKE_ROLE) venafi_secret=$(FAKE_VENAFI) $(ROLE_OPTIONS)
fake_config_read:
	vault read $(MOUNT)/venafi/$(FAKE_VENAFI)
	vault read $(MOUNT)/roles/$(FAKE_ROLE)

fake_cert_write:
	$(eval RANDOM_SITE := $(shell echo $(RANDOM_SITE_EXP)))
	@echo "Issuing fake-$(RANDOM_SITE).$(FAKE_DOMAIN)"
		vault write $(MOUNT)/issue/$(FAKE_ROLE) common_name="fake-$(RANDOM_SITE).$(FAKE_DOMAIN)" alt_names="alt-$(RANDOM_SITE).$(FAKE_DOMAIN),alt2-$(RANDOM_SITE).$(FAKE_DOMAIN)"
fake_cert_read_certificate:
	vault read -field=certificate $(MOUNT)/cert/fake-$(RANDOM_SITE).$(FAKE_DOMAIN) > $(CERT_TMP_FILE)
	$(CHECK_CERT_CMD) $(CERT_TMP_FILE)
fake_cert_read_pkey:
	vault read -field=private_key $(MOUNT)/cert/fake-$(RANDOM_SITE).$(FAKE_DOMAIN)|tee /tmp/privateKey.key
	@echo "\nChecking modulus for certificate and key:\n"
	@openssl pkey -in /tmp/privateKey.key -pubout -outform pem| sha256sum
	@openssl x509 -in $(CERT_TMP_FILE) -pubkey -noout -outform pem | sha256sum


fake: fake_config_write fake_cert_write fake_cert_read_certificate fake_cert_read_pkey

#Cloud role tasks
cloud_config_write:
	vault write $(MOUNT)/venafi/$(CLOUD_VENAFI) cloud_url=$(CLOUD_URL) zone="$(CLOUD_ZONE)" apikey=$(CLOUD_APIKEY)
	vault write $(MOUNT)/roles/$(CLOUD_ROLE) venafi_secret=$(CLOUD_VENAFI) $(ROLE_OPTIONS)
cloud_config_read:
	vault read $(MOUNT)/venafi/$(CLOUD_VENAFI)
	vault read $(MOUNT)/roles/$(CLOUD_ROLE)

cloud_cert_write:
	$(eval RANDOM_SITE := $(shell echo $(RANDOM_SITE_EXP)))
	@echo "Issuing cloud-$(RANDOM_SITE).$(CLOUD_DOMAIN)"
	vault write $(MOUNT)/issue/$(CLOUD_ROLE) common_name="cloud-$(RANDOM_SITE).$(CLOUD_DOMAIN)" alt_names="alt-$(RANDOM_SITE).$(CLOUD_DOMAIN),alt2-$(RANDOM_SITE).$(CLOUD_DOMAIN)"
cloud_cert_read_certificate:
	vault read -field=certificate $(MOUNT)/cert/cloud-$(RANDOM_SITE).$(CLOUD_DOMAIN) > $(CERT_TMP_FILE)
	$(CHECK_CERT_CMD) $(CERT_TMP_FILE)
cloud_cert_read_pkey:
	vault read -field=private_key $(MOUNT)/cert/cloud-$(RANDOM_SITE).$(CLOUD_DOMAIN)|tee /tmp/privateKey.key
	@echo "\nChecking modulus for certificate and key:\n"
	@openssl pkey -in /tmp/privateKey.key -pubout -outform pem| sha256sum
	@openssl x509 -in $(CERT_TMP_FILE) -pubkey -noout -outform pem | sha256sum


cloud: cloud_config_write cloud_cert_write cloud_cert_read_certificate cloud_cert_read_pkey


#TPP role tasks
tpp_config_write:
	vault write $(MOUNT)/venafi/$(TPP_VENAFI) tpp_url=$(TPP_URL) tpp_user=$(TPP_USER) tpp_password=$(TPP_PASSWORD) zone="$(TPP_ZONE)" trust_bundle_file=$(TRUST_BUNDLE)
	vault write $(MOUNT)/roles/$(TPP_ROLE) venafi_secret=$(TPP_VENAFI) $(ROLE_OPTIONS)
tpp_config_read:
	vault read $(MOUNT)/venafi/$(TPP_VENAFI)
	vault read $(MOUNT)/roles/$(TPP_ROLE)

tpp_cert_write:
	$(eval RANDOM_SITE := $(shell echo $(RANDOM_SITE_EXP)))
	@echo "Issuing tpp-$(RANDOM_SITE).$(TPP_DOMAIN)"
	vault write $(MOUNT)/issue/$(TPP_ROLE) common_name="tpp-$(RANDOM_SITE).$(TPP_DOMAIN)" alt_names="alt-$(RANDOM_SITE).$(TPP_DOMAIN),alt2-$(RANDOM_SITE).$(TPP_DOMAIN)"
tpp_cert_read_certificate:
	vault read -field=certificate $(MOUNT)/cert/tpp-$(RANDOM_SITE).$(TPP_DOMAIN) > $(CERT_TMP_FILE)
	$(CHECK_CERT_CMD) $(CERT_TMP_FILE)
tpp_cert_read_pkey:
	vault read -field=private_key $(MOUNT)/cert/tpp-$(RANDOM_SITE).$(TPP_DOMAIN)|tee /tmp/privateKey.key
	@echo "\nChecking modulus for certificate and key:\n"
	@openssl pkey -in /tmp/privateKey.key -pubout -outform pem| sha256sum
	@openssl x509 -in $(CERT_TMP_FILE) -pubkey -noout -outform pem | sha256sum


tpp: tpp_config_write tpp_cert_write tpp_cert_read_certificate tpp_cert_read_pkey


#TPP Token tasks
token_config_write:
	vault write $(MOUNT)/venafi/$(TOKEN_VENAFI) url=$(TPP_TOKEN_URL) access_token=$(TPP_ACCESS_TOKEN) zone="$(TPP_ZONE)" trust_bundle_file=$(TRUST_BUNDLE)
	vault write $(MOUNT)/roles/$(TOKEN_ROLE) venafi_secret=$(TOKEN_VENAFI) $(ROLE_OPTIONS)
token_config_read:
	vault read $(MOUNT)/venafi/$(TOKEN_VENAFI)
	vault read $(MOUNT)/roles/$(TOKEN_ROLE)
token_cert_write:
	$(eval RANDOM_SITE := $(shell echo $(RANDOM_SITE_EXP)))
	@echo "Issuing tpp-$(RANDOM_SITE).$(TPP_DOMAIN)"
	vault write $(MOUNT)/issue/$(TOKEN_ROLE) common_name="tppToken-$(RANDOM_SITE).$(TPP_DOMAIN)" alt_names="alt-$(RANDOM_SITE).$(TPP_DOMAIN),alt2-$(RANDOM_SITE).$(TPP_DOMAIN)"
token_cert_read_certificate:
	vault read -field=certificate $(MOUNT)/cert/tppToken-$(RANDOM_SITE).$(TPP_DOMAIN) > $(CERT_TMP_FILE)
	$(CHECK_CERT_CMD) $(CERT_TMP_FILE)
token_cert_read_pkey:
	vault read -field=private_key $(MOUNT)/cert/tppToken-$(RANDOM_SITE).$(TPP_DOMAIN)|tee /tmp/privateKey.key
	@echo "\nChecking modulus for certificate and key:\n"
	@openssl pkey -in /tmp/privateKey.key -pubout -outform pem| sha256sum
	@openssl x509 -in $(CERT_TMP_FILE) -pubkey -noout -outform pem | sha256sum

tpp_token: token_config_write token_cert_write token_cert_read_certificate token_cert_read_pkey


#Consul template tasks
consul_template_tpp: tpp_config_write
	$(CT_CMD) -once -config=scripts/config/nginx/consul-template-tpp.hcl -vault-token=$(VAULT_TOKEN)

consul_template_cloud: cloud_config_write
	$(CT_CMD) -once -config=scripts/config/nginx/consul-template-cloud.hcl -vault-token=$(VAULT_TOKEN)

consul_template_fake: fake_config_write
	$(CT_CMD) -once -config=scripts/config/nginx/consul-template-fake.hcl -vault-token=$(VAULT_TOKEN)

consul_template_tpp_daemon: tpp_config_write
	$(CT_CMD) -config=scripts/config/nginx/consul-template-tpp.hcl -vault-token=$(VAULT_TOKEN)

consul_template_cloud_daemon: cloud_config_write
	$(CT_CMD) -config=scripts/config/nginx/consul-template-cloud.hcl -vault-token=$(VAULT_TOKEN)

consul_template_fake_daemon: fake_config_write
	$(CT_CMD) -config=scripts/config/nginx/consul-template-fake.hcl -vault-token=$(VAULT_TOKEN)

nginx:
	docker rm -f vault-demo-nginx || echo "Container not found"
	docker run --name vault-demo-nginx -p 443:443 -v $$(pwd)/scripts/config/nginx/nginx.conf:/etc/nginx/conf.d/default.conf:ro \
	-v $$(pwd)/scripts/config/nginx/cert:/etc/nginx/ssl -d nginx
	docker logs -f vault-demo-nginx

#Helper tasks
doc:
	@pandoc --from markdown --to dokuwiki README.md > README.dokuwiki
	@pandoc --from markdown --to rst README.md > README.rst

cert_list:
	vault list $(MOUNT)/certs
	@echo "\nTo read the certificate run"
	@echo "vault read $(MOUNT)/cert/<certificate id>"

show_config: fake_config_read cloud_config_read tpp_config_read
config: fake_config_write cloud_config_write tpp_config_write

collect_artifacts:
	rm -rf artifacts
	mkdir -p artifacts
	cp -rv $(DIST_DIR)/*.zip artifacts

linter:
	@golangci-lint --version || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b /go/bin
	golangci-lint run

release:
	echo '```' > release.txt
	cd artifacts; sha256sum * >> ../release.txt
	echo '```' >> release.txt
	go install github.com/tcnksm/ghr@v0.16.2
	ghr -prerelease -n $$RELEASE_VERSION -body="$$(cat ./release.txt)" $$RELEASE_VERSION artifacts/
