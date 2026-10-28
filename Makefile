# security-scans. Run `make tools` once, then `make scan`.
SHELL := /bin/bash
REGISTRY ?= repos.toml
REPO ?=
ENV := source tools/env.sh &&
# -s: ignore user site-packages; secscan itself is imported from this directory.
RUN := $(ENV) cd $(CURDIR) && $$SECSCAN_PYTHON -s -m secscan
REPO_ARG := $(if $(REPO),--repo $(REPO))
RUN_TESTS := $(ENV) cd $(CURDIR) && $$SECSCAN_PYTHON -s -m unittest discover -s tests -t . -v

.PHONY: tools scan diff triage list seeded test lint-ci help

help:
	@sed -n 's/^## //p' Makefile

## make tools          install pinned scanners (tools/versions.env) into tools/bin + conda env secscan
tools:
	scripts/install-tools.sh

## make scan [REPO=x]  clone/update + scan every repo in $(REGISTRY)
scan:
	$(RUN) scan --registry $(REGISTRY) $(REPO_ARG)

## make diff [REPO=x]  new / fixed / still open: latest run vs the one before
diff:
	$(RUN) diff --registry $(REGISTRY) $(REPO_ARG)

## make triage REPO=x  AI triage (Claude Code headless, read-only) of the latest run
triage:
	@test -n "$(REPO)" || { echo "usage: make triage REPO=<name>"; exit 2; }
	$(RUN) triage --registry $(REGISTRY) --repo $(REPO)

## make list           show registered repos
list:
	$(RUN) list --registry $(REGISTRY)

## make seeded         (re)build test-work/seeded-repo and scan it
seeded:
	tests/make-seeded-repo.sh
	$(MAKE) scan REGISTRY=tests/seeded-registry.toml

## make test          unit tests for the runner's own logic
test:
	$(RUN_TESTS)

## make lint-ci        actionlint + zizmor over this project's own workflows
lint-ci:
	$(ENV) actionlint -shellcheck= -pyflakes= .github/workflows/*.yml examples/*.yml && zizmor --offline --persona auditor .github/workflows/*.yml examples/*.yml
