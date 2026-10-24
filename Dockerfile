FROM node:22.18-bookworm-slim
ENV NODE_ENV=production HOST=0.0.0.0 PORT=8787 BERKIOS_DB=/data/berkios-users.sqlite
WORKDIR /app
COPY package.json ./
RUN mkdir -p /data && chown -R node:node /data /app
COPY --chown=node:node server.js ./server.js
USER node
EXPOSE 8787
CMD ["node", "--experimental-sqlite", "server.js"]
