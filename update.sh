#!/bin/sh
# Pull the latest version from GitHub and rebuild the container.
set -e
cd "$(dirname "$0")"
git pull --ff-only
docker compose up -d --build --pull always
docker image prune -f >/dev/null
docker compose ps
echo "Mini ASM is running on http://localhost:3001"
