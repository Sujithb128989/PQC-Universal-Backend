#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}--- PQC C++/Python Hybrid Setup ---${NC}"

echo -e "\n${YELLOW}Step 1: Cleaning up previous Docker runs...${NC}"
sudo docker stop pqc-server-container > /dev/null 2>&1 || true
sudo docker rm pqc-server-container > /dev/null 2>&1 || true
sudo docker stop pqc-cert-generator > /dev/null 2>&1 || true
sudo docker rm pqc-cert-generator > /dev/null 2>&1 || true
mkdir -p certs
echo -e "${GREEN}Cleanup complete.${NC}"

echo -e "\n${YELLOW}Step 2: Building the PQC server image...${NC}"
sudo docker build -t pqc-server -f Dockerfile.server .
echo -e "${GREEN}Server image built successfully!${NC}"

echo -e "\n${YELLOW}Step 3: Generating PQC/TLS certificates...${NC}"
# The generate_certs.sh script takes the output directory as an argument.
sudo docker run --name pqc-cert-generator -v "$(pwd)/certs:/app/certs" pqc-server sh -c "/app/scripts/generate_certs.sh /app/certs && chown -R $(id -u):$(id -g) /app/certs"
sudo docker rm pqc-cert-generator > /dev/null 2>&1
echo -e "${GREEN}Certificates generated successfully.${NC}"

echo -e "\n${YELLOW}Step 4: Running end-to-end integration test...${NC}"

echo "Starting C++ server in the background..."
CONTAINER_ID=$(sudo docker run -d -p 50051:50051 -p 8080:8080 --name pqc-server-container -v "$(pwd)/certs:/app/certs:ro" pqc-server)

trap 'echo -e "\n${YELLOW}Stopping server...${NC}"; sudo docker stop $CONTAINER_ID; sudo docker rm $CONTAINER_ID' EXIT

echo "Waiting for server to initialize..."
sleep 5

echo "--- Tailing server logs ---"
sudo docker logs --tail 20 $CONTAINER_ID
echo "---------------------------"

# The client will be run inside the container to ensure it uses the same OQS-enabled OpenSSL
echo "Running Python client inside the container..."
sudo docker exec $CONTAINER_ID /app/scripts/run_client.sh

echo "Testing HTTP Gateway..."
# Wait for HTTP server to start
sleep 2
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health)
if [ "$HTTP_STATUS" -eq 200 ]; then
    echo -e "${GREEN}✓ HTTP Gateway is reachable (Status: 200)${NC}"
else
    echo -e "${RED}✗ HTTP Gateway failed (Status: $HTTP_STATUS)${NC}"
    exit 1
fi

echo -e "\n${GREEN}--- Integration Test Passed ---${NC}"
echo -e "${GREEN}--- Setup Complete! ---${NC}"
