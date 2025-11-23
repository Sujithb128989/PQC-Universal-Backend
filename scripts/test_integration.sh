#!/bin/bash

# A simple integration test for the PQC client-server application.

set -e # Exit immediately if a command exits with a non-zero status.

# --- Configuration ---
SERVER_ADDRESS="localhost:50051"
TEST_MESSAGE="pqc-is-working"
CERTS_DIR="certs"

# --- Helper Functions ---
function cleanup {
    echo "--- Cleaning up ---"
    make stop-server
}

# --- Test Execution ---
echo "--- Starting Integration Test ---"

# 1. Check for certificates
if [ ! -d "$CERTS_DIR" ] || [ ! -f "$CERTS_DIR/ca.crt" ]; then
    echo "Error: Certificates not found. Please run the generation script first."
    exit 1
fi

# 2. Ensure the client is installed
echo "--> Installing client..."
make install-client

# 3. Start the server in the background
echo "--> Starting server..."
make run-server
# Give the server a moment to start up
sleep 5

# 4. Set trap to ensure server is stopped even if test fails
trap cleanup EXIT

# 5. Store a message
echo "--> Storing message: '$TEST_MESSAGE'"
STORE_OUTPUT=$(pqc-client store $SERVER_ADDRESS --message "$TEST_MESSAGE")
MESSAGE_ID=$(echo $STORE_OUTPUT | awk -F 'ID: ' '{print $2}')

if [ -z "$MESSAGE_ID" ]; then
    echo "Error: Failed to get message ID from store command."
    exit 1
fi
echo "Message stored with ID: $MESSAGE_ID"

# 6. Retrieve the message
echo "--> Retrieving message with ID: $MESSAGE_ID"
RETRIEVED_MESSAGE=$(pqc-client retrieve $SERVER_ADDRESS $MESSAGE_ID | awk -F 'Retrieved message: ' '{print $2}')

# 7. Verify the message
echo "--> Verifying message..."
if [ "$RETRIEVED_MESSAGE" == "$TEST_MESSAGE" ]; then
    echo "Success: Retrieved message matches original message."
else
    echo "Error: Retrieved message ('$RETRIEVED_MESSAGE') does not match original ('$TEST_MESSAGE')."
    exit 1
fi

echo "--- Integration Test Passed ---"
# The 'trap' will handle the cleanup.