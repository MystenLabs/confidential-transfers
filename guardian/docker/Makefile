# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

REGISTRY := local
OUT := out
SOURCES := $(shell cd ../.. && git ls-files -- Cargo.toml Cargo.lock .cargo guardian/core guardian/enclave guardian/docker)

.DEFAULT_GOAL := eif
.PHONY: eif clean

eif: $(OUT)/nitro.eif

$(OUT)/nitro.eif: $(addprefix ../../,$(SOURCES))
	docker build \
		--pull \
		--tag $(REGISTRY)/guardian-enclave \
		--progress=plain \
		--platform linux/amd64 \
		--provenance=false \
		--output type=local,rewrite-timestamp=true,dest=$(OUT) \
		-f Containerfile \
		../..

clean:
	rm -rf $(OUT)
