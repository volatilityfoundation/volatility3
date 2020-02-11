DOCKER_BIN=docker
DOCKER_FLAGS+=
DOCKER_REPOSITORY?=volatility3
DOCKER_TAG?=latest

USERNAME ?= root
ALPINE_VERSION ?= 3.11

.PHONY: all pdbconv volshell vol

all: volshell vol pdbconv

pdbconv:
	@$(DOCKER_BIN) build \
		$(DOCKER_FLAGS)  \
		--rm             \
		--tag $(DOCKER_REPOSITORY)/$@:$(DOCKER_TAG) \
		$@

volshell vol pdbconv:
	@$(DOCKER_BIN) build \
		$(DOCKER_FLAGS)  \
		--rm             \
		--build-arg USERNAME=$(USERNAME) \
		--build-arg ALPINE_VERSION=$(ALPINE_VERSION) \
		--tag $(DOCKER_REPOSITORY)/$@:$(DOCKER_TAG) \
		--target $@ \
		.

.PHONY: clean
clean:
	docker rmi $(DOCKER_REPOSITORY)/pdbconv $(DOCKER_REPOSITORY)/volshell $(DOCKER_REPOSITORY)/vol 
	docker system prune