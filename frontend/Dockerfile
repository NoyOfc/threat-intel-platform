# Development image for the ThreatScope UI (Vite dev server).
FROM node:24-slim

ENV NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false

WORKDIR /app

# The base image ships an unprivileged "node" user; install and run as it.
RUN chown node:node /app
USER node

COPY --chown=node:node package.json package-lock.json ./
# --ignore-scripts: dependency lifecycle scripts never run during install.
RUN npm ci --ignore-scripts

COPY --chown=node:node . .

EXPOSE 5173

CMD ["npm", "run", "dev"]
