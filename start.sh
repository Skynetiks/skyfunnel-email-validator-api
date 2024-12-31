#!/bin/bash

# Build the Go binary
echo "Building the Go binary..."
go build -o skyfunnel-email-verifier-api

# Run the built binary
echo "Starting the application..."
./skyfunnel-email-verifier-api
