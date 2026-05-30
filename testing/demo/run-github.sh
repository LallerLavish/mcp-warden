#!/usr/bin/env bash
set -e

EXEC_WARDEN="/home/ubuntu/mcp-warden/warden/target/debug/warden"
POLICY_PATH="/home/ubuntu/mcp-warden/testing/demo/github.toml"
TARGET_GIT="/home/ubuntu/mcp-warden/testing/bin/github-mcp-server"


exec "$EXEC_WARDEN" --policy "$POLICY_PATH" -- "$TARGET_GIT" stdio "$@"