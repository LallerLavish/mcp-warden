#!/usr/bin/env bash

# Stop execution if any sub-command fails
set -e

# Use full absolute paths to prevent context loss inside the inspector
EXEC_WARDEN="/home/ubuntu/mcp-warden/warden/target/debug/warden"
POLICY_PATH="/home/ubuntu/mcp-warden/testing/demo/demo.toml"
TARGET_WEATHER="/home/ubuntu/mcp-warden/testing/mcp_weather/target/debug/mcp_weather"

exec "$EXEC_WARDEN" --policy "$POLICY_PATH" -- "$TARGET_WEATHER" "$@"