#!/bin/sh
set -e

# Configuration
SERVER_ADDRESS="--server localhost:50051"
CERT_OPTIONS="--ca-cert /app/certs/ca.crt --client-key /app/certs/client.key --client-cert /app/certs/client.crt"
CLIENT_BIN="/opt/venv/bin/pqc-client"

echo "--- Running PQC Python Client ---"

# Check if client binary exists
if [ ! -f "$CLIENT_BIN" ]; then
    echo "Error: Client binary not found at $CLIENT_BIN"
    echo "Contents of /opt/venv/bin:"
    ls -l /opt/venv/bin
    exit 1
fi

# 1. Health Check
echo "Checking server health..."
$CLIENT_BIN health $SERVER_ADDRESS $CERT_OPTIONS

# 2. Store a message (using positional argument)
echo ""
echo "Storing message..."
STORE_OUTPUT=$($CLIENT_BIN store "pqc-is-working" $SERVER_ADDRESS $CERT_OPTIONS)
echo "$STORE_OUTPUT"

# Extract the message ID from the output
# Expected format: "✓ Message stored successfully. ID: 0"
MESSAGE_ID=$(echo "$STORE_OUTPUT" | grep -oP 'ID: \K\d+')

if [ -z "$MESSAGE_ID" ]; then
    echo "Error: Failed to extract message ID from store response"
    exit 1
fi

echo "Extracted message ID: $MESSAGE_ID"

# 3. Retrieve the message
echo ""
echo "Retrieving message with ID $MESSAGE_ID..."
$CLIENT_BIN retrieve $MESSAGE_ID $SERVER_ADDRESS $CERT_OPTIONS

echo ""
echo "--- PQC Client Test Complete ---"
