#!/bin/sh
set -e
# Bring the database on the mounted volume up to date, then start the server.
node node_modules/prisma/build/index.js migrate deploy
exec node server.js
