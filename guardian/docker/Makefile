# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

GIT_REVISION ?= $(shell git rev-parse HEAD)
IMAGE := contra-guardian-enclave:$(GIT_REVISION)
OUT := out

.PHONY: eif image clean

eif: image
	mkdir -p $(OUT)
	nitro-cli build-enclave --docker-uri $(IMAGE) --output-file $(OUT)/nitro.eif
	nitro-cli describe-eif --eif-path $(OUT)/nitro.eif | tee $(OUT)/describe-eif.json

image:
	docker buildx build ../.. -f Containerfile \
		--build-arg SOURCE_DATE_EPOCH=0 \
		--provenance=false \
		--output type=docker,rewrite-timestamp=true,name=$(IMAGE) \
		--load

clean:
	rm -rf $(OUT)
