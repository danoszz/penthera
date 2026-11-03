# node:22-alpine, pinned by digest (multi-arch index). Dependabot bumps it.
FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914

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
