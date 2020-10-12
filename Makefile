.DEFAULT_GOAL := build

.PHONY: clean build fmt test

TAG           ?= latest

BUILD_FLAGS   ?=
BINARY        ?= spring-config-decryptor-webhook
ROOT_DIR      := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
LDFLAGS       ?= -w -s

LOCAL_IMAGE   ?= local/$(BINARY)
CLOUD_IMAGE   ?= grepplabs/spring-config-decryptor-webhook:$(TAG)

HELM_BIN	  ?= helm3
HELM_VALUES	  ?= values.yaml
SVC_NAME      ?= spring-config-decryptor-webhook
SVC_NAMESPACE ?= webhook

KUBE_CONTEXT  ?= test-cluster

test:
	GO111MODULE=on go test -mod=vendor -v ./...

build:
	CGO_ENABLED=0 GO111MODULE=on go build -mod=vendor -o $(BINARY) $(BUILD_FLAGS) -ldflags "$(LDFLAGS)" .

fmt:
	go fmt ./...

clean:
	@rm -rf $(BINARY)

.PHONY: deps
deps:
	GO111MODULE=on go get ./...

.PHONY: vendor
vendor:
	GO111MODULE=on go mod vendor

.PHONY: tidy
tidy:
	GO111MODULE=on go mod tidy

.PHONY: docker-build
docker-build:
	docker build -f Dockerfile -t $(LOCAL_IMAGE) .

.PHONY: docker-push
docker-push: docker-build
	docker tag $(LOCAL_IMAGE) $(CLOUD_IMAGE)
	docker push $(CLOUD_IMAGE)

.PHONY: helm-template
helm-template:
	$(HELM_BIN) template $(SVC_NAME) $(ROOT_DIR)/charts/spring-config-decryptor-webhook \
	   -f $(ROOT_DIR)/charts/spring-config-decryptor-webhook/$(HELM_VALUES) \
	   --namespace=$(SVC_NAMESPACE)

.PHONY: helm-install
helm-install:
	$(HELM_BIN) upgrade $(SVC_NAME) $(ROOT_DIR)/charts/spring-config-decryptor-webhook \
	   -f $(ROOT_DIR)/charts/spring-config-decryptor-webhook/$(HELM_VALUES) \
	   --namespace=$(SVC_NAMESPACE) \
	   --install \
	   --create-namespace \
	   --kube-context $(KUBE_CONTEXT)

.PHONY: rollout-restart
rollout-restart:
	kubectl rollout restart deployment $(SVC_NAME) \
		-n $(SVC_NAMESPACE) \
		--context $(KUBE_CONTEXT)
