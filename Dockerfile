# syntax=docker/dockerfile:1

# Mini ASM container image. Multi-stage so the final image holds only the
# standalone server, the Prisma engine and the migrations.
FROM node:24-alpine AS base
# Pull in the latest Alpine security patches.
RUN apk upgrade --no-cache
# Prisma 5 looks for OpenSSL in /lib, current Alpine keeps it in /usr/lib.
RUN [ -e /lib/libssl.so.3 ] || ln -s /usr/lib/libssl.so.3 /lib/libssl.so.3
WORKDIR /app

FROM base AS build
ENV NEXT_TELEMETRY_DISABLED=1 DATABASE_URL=file:/tmp/build.db
COPY package.json package-lock.json ./
COPY prisma ./prisma
RUN npm ci
COPY . .
RUN npm run build

FROM base AS runner
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3001 \
    HOSTNAME=0.0.0.0 \
    DATABASE_URL=file:/data/asm.db
# npm and friends are not needed at runtime and only add attack surface.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx \
           /opt/yarn* /usr/local/bin/yarn /usr/local/bin/yarnpkg /usr/local/bin/corepack \
           /usr/local/lib/node_modules/corepack \
    && mkdir -p /data && chown node:node /data
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
COPY --from=build --chown=node:node /app/prisma ./prisma
# Prisma CLI and engines, used once at start to apply migrations.
COPY --from=build --chown=node:node /app/node_modules/prisma ./node_modules/prisma
COPY --from=build --chown=node:node /app/node_modules/@prisma ./node_modules/@prisma
COPY --chown=node:node docker-entrypoint.sh ./
USER node
VOLUME /data
EXPOSE 3001
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/').then(r=>process.exit(r.status<500?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["/bin/sh", "./docker-entrypoint.sh"]
