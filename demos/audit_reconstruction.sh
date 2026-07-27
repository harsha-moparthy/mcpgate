#!/usr/bin/env bash
# Reconstruct a full mixed session (allows + denials) from the audit trail alone,
# then prove the trail has not been altered.
set -euo pipefail
cd "$(dirname "$0")/.."

.venv/bin/python -m demos.audit_reconstruction
