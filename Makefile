.PHONY: all build clean test run-example generate-root help

# Binary name
BINARY=amhs-pki-demo

# Build the binary
all: build

build:
	@echo "Building $(BINARY)..."
	go build -o $(BINARY) .
	@echo "Build complete: ./$(BINARY)"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BINARY)
	rm -f *.crt *.key
	rm -f amhs-ca.* mta-* ua-* mtcu-* issuing-ca.*
	@echo "Clean complete"

# Generate root CA
generate-root:
	@echo "Generating root CA..."
	./generate-root-ca.sh

# Run the example workflow
run-example: build generate-root
	@echo "Running example workflow..."
	./example-workflow.sh

# Run basic tests
test: build
	@echo "Running tests..."
	@echo "1. Checking binary exists..."
	@test -f $(BINARY) && echo "✓ Binary exists"
	@echo ""
	@echo "2. Testing help command..."
	@./$(BINARY) 2>&1 | grep -q "AMHS PKI" && echo "✓ Help works"
	@echo ""
	@echo "All tests passed!"

# Install dependencies (if any)
deps:
	@echo "No external dependencies required (using Go standard library)"

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Run linter
lint:
	@echo "Running linter..."
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed, skipping"

# Show help
help:
	@echo "AMHS PKI Demo Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build         - Build the binary"
	@echo "  make clean         - Remove build artifacts and generated certificates"
	@echo "  make generate-root - Generate the root CA certificate"
	@echo "  make run-example   - Run the full example workflow"
	@echo "  make test          - Run basic tests"
	@echo "  make fmt           - Format Go code"
	@echo "  make help          - Show this help message"
	@echo ""
	@echo "Quick start:"
	@echo "  1. make generate-root"
	@echo "  2. make build"
	@echo "  3. ./$(BINARY) generate -type ca -output amhs-ca -validity 5475"
