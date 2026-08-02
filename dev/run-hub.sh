#!/usr/bin/env bash
# Terminal 2: a real JupyterHub running the real ExternalAuthenticator.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=env.sh
source ./env.sh

if [ ! -x "./node_modules/.bin/configurable-http-proxy" ]; then
  echo "configurable-http-proxy is missing. Run:  npm install   (installs into ./node_modules, not globally)" >&2
  exit 1
fi

echo "jupyterhub  -> http://127.0.0.1:8081"
exec uv run jupyterhub --config ./jupyterhub_config.py
