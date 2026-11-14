#!/bin/sh
# Pull the latest version from GitHub and rebuild the container.
set -e
cd "$(dirname "$0")"
git pull --ff-only

# First run: ask for the sign-in details and keep them in .env (never committed).
if [ ! -f .env ]; then
    echo "No .env found. Choose the username and password for the sign-in page."
    printf "Username: "; read -r user
    printf "Password: "; stty -echo; read -r pass; stty echo; echo
    [ -n "$user" ] && [ -n "$pass" ] || { echo "Username and password cannot be empty."; exit 1; }
    umask 077
    printf 'ASM_USERNAME=%s\nASM_PASSWORD=%s\n' "$user" "$pass" > .env
    echo "Saved to .env"
fi

docker compose up -d --build --pull always
docker image prune -f >/dev/null
docker compose ps
echo "Mini ASM is running on http://localhost:3001"
