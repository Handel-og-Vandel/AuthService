#!/bin/bash

# Run the e2e tests

base_url="http://localhost:5000/api/v1/auth"

# Test Version endoint
curl -s --location "${base_url}/version" | grep -q "HaaV Authentication Service"
if [ $? -eq 0 ]; then
    echo "Version endpoint test passed"
else
    echo "Version endpoint test failed"
    exit 1
fi

# # Test Login enpoint (no User service)
curl -s -X POST --location "${base_url}/login" \
    -d "{\"username\": \"testuser1\", \"password\": \"12345678\"}" \
    -H "Content-Type: application/json" | grep -q "Failed to retrieve user data for testuser1"
if [ $? -eq 0 ]; then
    echo "Login test passed"
else
    echo "Login test failed"
    exit 1
fi