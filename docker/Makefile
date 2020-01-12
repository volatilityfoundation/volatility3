DOCKER_BIN=docker
DOCKER_FLAGS+=
DOCKER_REPOSITORY?=volatility
DOCKER_TAG?=latest

.PHONY: all dwarf2json pdbconv volatility volshell

all: dwarf2json pdbconv volatility volshell

dwarf2json:
	@$(DOCKER_BIN) build \
		$(DOCKER_FLAGS)  \
		--rm             \
		--tag $(DOCKER_REPOSITORY)/$@:$(DOCKER_TAG) \
		$@

pdbconv:
	@$(DOCKER_BIN) build \
		$(DOCKER_FLAGS)  \
		--rm             \
		--tag $(DOCKER_REPOSITORY)/$@:$(DOCKER_TAG) \
		$@

volatility:
	@$(DOCKER_BIN) build \
		$(DOCKER_FLAGS)  \
		--rm             \
		--tag $(DOCKER_REPOSITORY)/$@:$(DOCKER_TAG) \
		$@

volshell:
	@$(DOCKER_BIN) build \
		$(DOCKER_FLAGS)  \
		--rm             \
		--tag $(DOCKER_REPOSITORY)/$@:$(DOCKER_TAG) \
		$@
