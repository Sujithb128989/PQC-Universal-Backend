# Makefile for pqc-client-server

# Variables
DOCKER = docker
SERVER_IMAGE_NAME = pqc-server
SERVER_CONTAINER_NAME = pqc-server-container

# Default target
all: build-server

# Build the server Docker image
build-server:
	@echo "Building PQC server image..."
	$(DOCKER) build -t $(SERVER_IMAGE_NAME) -f Dockerfile.server .

# Run the server container
run-server:
	@echo "Running PQC server container..."
	$(DOCKER) run --rm -d -p 50051:50051 --name $(SERVER_CONTAINER_NAME) $(SERVER_IMAGE_NAME)

# Stop the server container
stop-server:
	@echo "Stopping PQC server container..."
	$(DOCKER) stop $(SERVER_CONTAINER_NAME)

# Install the client CLI tool
install-client:
	@echo "Installing client..."
	pip3 install -e ./client

# Package the client for PyPI
package-client:
	@echo "Packaging client..."
	pip3 install build
	cd client && python3 -m build

# Push Docker Image to Docker Hub
# Usage: make push-docker USER=your_dockerhub_username
push-docker:
	@if [ -z "$(USER)" ]; then echo "Error: USER is not set. Usage: make push-docker USER=your_username"; exit 1; fi
	@echo "Logging in to Docker Hub..."
	$(DOCKER) login
	@echo "Tagging image..."
	$(DOCKER) tag $(SERVER_IMAGE_NAME) $(USER)/$(SERVER_IMAGE_NAME):latest
	@echo "Pushing image..."
	$(DOCKER) push $(USER)/$(SERVER_IMAGE_NAME):latest
	@echo "Done! Users can now run: docker run $(USER)/$(SERVER_IMAGE_NAME)"

# Clean up Docker artifacts
clean:
	@echo "Cleaning up..."
	-$(DOCKER) stop $(SERVER_CONTAINER_NAME)
	-$(DOCKER) rm $(SERVER_CONTAINER_NAME)
	-$(DOCKER) rmi $(SERVER_IMAGE_NAME)

.PHONY: all build-server run-server stop-server install-client clean