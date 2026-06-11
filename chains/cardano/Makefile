# Tessera — Cardano identity-registry (Aiken / Plutus V3)
#
# Mirrors chains/stellar/Makefile. The Aiken project lives in CONTRACT_DIR; every
# target passes that directory to aiken, so `make` works from chains/cardano/.

CONTRACT_DIR := contracts/identity-registry
BLUEPRINT    := $(CONTRACT_DIR)/plutus.json
AIKEN        := aiken
ANCHOR_MOD   := identity_anchor
ISSUER_MOD   := issuer_registry

.PHONY: help install build check test fmt blueprint policy address clean all dev ci

help:
	@echo "Tessera Cardano contracts — targets:"
	@echo "  install    Install the Aiken toolchain (npm wrapper; pins v1.1.21)"
	@echo "  build      Compile validators and emit the plutus.json blueprint"
	@echo "  check      Type-check and run the on-chain unit tests (aiken check)"
	@echo "  test       Alias for check"
	@echo "  fmt        Format all .ak sources"
	@echo "  blueprint  Build, then print policy ids + preprod script addresses"
	@echo "  policy     Print the identity_anchor policy id"
	@echo "  address    Print the identity_anchor preprod (testnet) script address"
	@echo "  clean      Remove Aiken build artifacts"
	@echo "  all        clean + check + build"
	@echo "  ci         check + build + assert the committed blueprint is up to date"

install:
	@echo "Installing Aiken v1.1.21 via the npm wrapper..."
	@npm install -g @aiken-lang/aiken@1.1.21
	@aiken --version

build:
	@echo "Building validators..."
	@$(AIKEN) build $(CONTRACT_DIR)
	@echo "Blueprint written to $(BLUEPRINT)"

check:
	@echo "Type-checking and running on-chain tests..."
	@$(AIKEN) check $(CONTRACT_DIR)

test: check

fmt:
	@$(AIKEN) fmt $(CONTRACT_DIR)

policy:
	@$(AIKEN) blueprint policy -i $(BLUEPRINT) -m $(ANCHOR_MOD) -v $(ANCHOR_MOD)

address:
	@$(AIKEN) blueprint address -i $(BLUEPRINT) -m $(ANCHOR_MOD) -v $(ANCHOR_MOD)

blueprint: build
	@echo "identity_anchor  policy id : $$($(AIKEN) blueprint policy  -i $(BLUEPRINT) -m $(ANCHOR_MOD) -v $(ANCHOR_MOD))"
	@echo "identity_anchor  address   : $$($(AIKEN) blueprint address -i $(BLUEPRINT) -m $(ANCHOR_MOD) -v $(ANCHOR_MOD))"
	@echo "issuer_registry  policy id : $$($(AIKEN) blueprint policy  -i $(BLUEPRINT) -m $(ISSUER_MOD) -v $(ISSUER_MOD))"
	@echo "issuer_registry  address   : $$($(AIKEN) blueprint address -i $(BLUEPRINT) -m $(ISSUER_MOD) -v $(ISSUER_MOD))"

clean:
	@rm -rf $(CONTRACT_DIR)/build $(CONTRACT_DIR)/artifacts

all: clean check build

dev: check build

ci: check build
	@echo "Asserting the committed blueprint matches source..."
	@git diff --exit-code $(BLUEPRINT)
