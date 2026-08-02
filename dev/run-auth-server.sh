#!/usr/bin/env bash
# Terminal 1: the auth server, with SAML swapped out for DevProvider.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=env.sh
source ./env.sh

# PYTHONPATH so `dev_provider.DevProvider` is importable without packaging it.
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"

echo "auth server -> http://127.0.0.1:8000   (login bypass ACTIVE)"
exec uv run auth_server --config ./authhub_config.py
