#!/usr/bin/env bash
# Full OAuth 2.1 authorization-code + PKCE flow against the real HTTP endpoints,
# including code replay and verifier-mismatch refusals.
set -euo pipefail
cd "$(dirname "$0")/.."

.venv/bin/python -m demos.oauth_flow
