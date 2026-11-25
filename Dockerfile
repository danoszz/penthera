# node:22-alpine, pinned by digest (multi-arch index). Dependabot bumps it.
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a

LABEL org.opencontainers.image.source="https://github.com/danoszz/penthera"
LABEL org.opencontainers.image.description="Offline, rule-based security checks for your repo, dependencies, AI agent config and local app."

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
