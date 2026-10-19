# node:22-alpine, pinned by digest (multi-arch index). Dependabot bumps it.
FROM node:25-alpine@sha256:bdf2cca6fe3dabd014ea60163eca3f0f7015fbd5c7ee1b0e9ccb4ced6eb02ef4

LABEL org.opencontainers.image.source="https://github.com/danoszz/penthera"
LABEL org.opencontainers.image.description="Penthera — security scanner for web apps"

WORKDIR /penthera

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY bin ./bin
COPY src ./src
COPY lib ./lib
COPY skills ./skills
COPY docs ./docs
COPY pentest.config.example.js ./

ENV NODE_ENV=production
ENV NO_COLOR=1

RUN mkdir -p /penthera/reports && chown node:node /penthera/reports
USER node

ENTRYPOINT ["node", "bin/penthera.js"]
CMD ["--help"]
