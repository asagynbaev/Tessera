# Makefile for ZKP Soroban Contracts
# Simplifies common development tasks

.PHONY: help build test clean optimize deploy-testnet deploy-mainnet install setup

# Default target
help:
	@echo "ZKP Soroban Contract Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make setup           - Install prerequisites and setup environment"
	@echo "  make build           - Build all contracts"
	@echo "  make test            - Run all tests"
	@echo "  make optimize        - Build and optimize contracts"
	@echo "  make clean           - Clean build artifacts"
	@echo "  make deploy-testnet  - Deploy to Stellar testnet"
	@echo "  make deploy-mainnet  - Deploy to Stellar mainnet (requires confirmation)"
	@echo "  make verify          - Verify deployed contract"
	@echo "  make fund-testnet    - Fund testnet account from friendbot"
	@echo ""

# Install prerequisites
setup:
	@echo "Setting up development environment..."
	@rustup target add wasm32v1-none
	@cargo install --locked stellar-cli --features opt || echo "Stellar CLI already installed"
	@echo "Setup complete"

# Build contracts
build:
	@echo "Building contracts..."
	@cargo build --target wasm32v1-none --release
	@echo "Build complete"
	@echo "WASM files:"
	@ls -lh target/wasm32v1-none/release/*.wasm

# Run tests
test:
	@echo "Running tests..."
	@cargo test -- --nocapture
	@echo "All tests passed"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@cargo clean
	@echo "Clean complete"

# Build and optimize contracts
optimize: build
	@echo "Optimizing contracts..."
	@stellar contract optimize \
		--wasm target/wasm32v1-none/release/attestation_verifier.wasm
	@echo "Optimization complete"
	@echo "Optimized WASM:"
	@ls -lh target/wasm32v1-none/release/attestation_verifier.wasm

# Deploy to testnet
deploy-testnet: optimize
	@echo "Deploying to Stellar testnet..."
	@if [ -z "$(SOURCE_ACCOUNT)" ]; then \
		echo "Error: SOURCE_ACCOUNT not set"; \
		echo "Usage: make deploy-testnet SOURCE_ACCOUNT=alice"; \
		exit 1; \
	fi
	@CONTRACT_ID=$$(stellar contract deploy \
		--wasm target/wasm32v1-none/release/attestation_verifier.wasm \
		--source $(SOURCE_ACCOUNT) \
		--network testnet); \
	echo "Contract deployed"; \
	echo "Contract ID: $$CONTRACT_ID"; \
	echo ""; \
	echo "Save this contract ID:"; \
	echo "export ZKP_CONTRACT_ID=$$CONTRACT_ID"

# Deploy to mainnet (requires confirmation)
deploy-mainnet: optimize
	@echo "WARNING: Deploying to MAINNET"
	@echo "This will cost real XLM."
	@echo ""
	@read -p "Are you sure? Type 'yes' to continue: " confirm; \
	if [ "$$confirm" != "yes" ]; then \
		echo "Deployment cancelled"; \
		exit 1; \
	fi
	@if [ -z "$(SOURCE_ACCOUNT)" ]; then \
		echo "Error: SOURCE_ACCOUNT not set"; \
		echo "Usage: make deploy-mainnet SOURCE_ACCOUNT=production-key"; \
		exit 1; \
	fi
	@echo "Deploying to Stellar mainnet..."
	@CONTRACT_ID=$$(stellar contract deploy \
		--wasm target/wasm32v1-none/release/attestation_verifier.wasm \
		--source $(SOURCE_ACCOUNT) \
		--network mainnet); \
	echo "Contract deployed to MAINNET"; \
	echo "Contract ID: $$CONTRACT_ID"; \
	echo ""; \
	echo "Save this contract ID:"; \
	echo "export ZKP_CONTRACT_ID=$$CONTRACT_ID"

# Fund testnet account
fund-testnet:
	@if [ -z "$(ACCOUNT)" ]; then \
		echo "Error: ACCOUNT not set"; \
		echo "Usage: make fund-testnet ACCOUNT=alice"; \
		exit 1; \
	fi
	@echo "Funding testnet account..."
	@stellar keys fund $(ACCOUNT) --network testnet
	@echo "Account funded"

# Verify contract deployment
verify:
	@if [ -z "$(CONTRACT_ID)" ]; then \
		echo "Error: CONTRACT_ID not set"; \
		echo "Usage: make verify CONTRACT_ID=C..."; \
		exit 1; \
	fi
	@echo "Verifying contract $(CONTRACT_ID)..."
	@stellar contract info --id $(CONTRACT_ID) --network testnet || \
		stellar contract info --id $(CONTRACT_ID) --network mainnet
	@echo "Contract verified"

# Lint code
lint:
	@echo "Linting code..."
	@cargo clippy -- -D warnings
	@echo "Lint complete"

# Format code
format:
	@echo "Formatting code..."
	@cargo fmt
	@echo "Format complete"

# Check code quality
check: lint test
	@echo "All checks passed"

# Complete build and test cycle
all: clean build test optimize
	@echo "All tasks complete"

# Install contract (for upgrades)
install:
	@if [ -z "$(SOURCE_ACCOUNT)" ]; then \
		echo "Error: SOURCE_ACCOUNT not set"; \
		echo "Usage: make install SOURCE_ACCOUNT=alice"; \
		exit 1; \
	fi
	@echo "Installing contract WASM..."
	@WASM_HASH=$$(stellar contract install \
		--wasm target/wasm32v1-none/release/attestation_verifier.wasm \
		--source $(SOURCE_ACCOUNT) \
		--network testnet); \
	echo "WASM installed"; \
	echo "WASM Hash: $$WASM_HASH"

# Quick development cycle
dev: build test
	@echo "Development cycle complete"

# CI/CD pipeline
ci: clean check optimize
	@echo "CI pipeline complete"

