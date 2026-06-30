FROM node:20-alpine

LABEL org.opencontainers.image.source="https://github.com/danoszz/penthera"
LABEL org.opencontainers.image.description="Penthera — lightweight security scanner for web apps"

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

ENTRYPOINT ["node", "bin/penthera.js"]
CMD ["--help"]
