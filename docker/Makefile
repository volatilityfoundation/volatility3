DOCKER_BIN:=/usr/bin/env docker
DOCKER_FLAGS+=
DOCKER_REPOSITORY:=volatilityfoundation
DOCKER_TAG:=latest

.PHONY: all build scratch

all: build

build:
	@$(DOCKER_BIN) build $(DOCKER_FLAGS) -t $(DOCKER_REPOSITORY)/pdbconv:$(DOCKER_TAG) ./pdbconv
	@$(DOCKER_BIN) build $(DOCKER_FLAGS) -t $(DOCKER_REPOSITORY)/volatility:$(DOCKER_TAG) ./volatility
	@$(DOCKER_BIN) build $(DOCKER_FLAGS) -t $(DOCKER_REPOSITORY)/volshell:$(DOCKER_TAG) ./volshell

scratch:
	@DOCKER_FLAGS+=--no-cache $(MAKE) all
