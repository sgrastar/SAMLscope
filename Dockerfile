# syntax=docker/dockerfile:1.7

FROM node:24.11.1-bookworm-slim@sha256:48abc13a19400ca3985071e287bd405a1d99306770eb81d61202fb6b65cf0b57 AS web-build
WORKDIR /src
COPY LICENSE LICENSING.md ./
COPY LICENSES/source-notices.json LICENSES/source-notices.json
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build -- --outDir /src/web/build/dist

FROM eclipse-temurin:21.0.12_8-jdk-noble@sha256:75ce56643243c3db632be2ef259625fb42ee3be1334389659f7a1a61acb78783 AS java-build
WORKDIR /src
COPY . .
COPY --from=web-build /src/web/build/dist /src/web/build/dist
RUN ./gradlew :api:installDist -x :web:buildWeb --no-daemon

FROM eclipse-temurin:21.0.12_8-jre-noble@sha256:96975602e131485862eb8cd32927face8a06d7591a5e865944b634a701d9df72
RUN groupadd --system --gid 10001 samlscope \
    && useradd --system --uid 10001 --gid samlscope --home-dir /opt/samlscope --shell /usr/sbin/nologin samlscope \
    && mkdir -p /opt/samlscope /data \
    && chown -R samlscope:samlscope /opt/samlscope /data
COPY --from=java-build --chown=samlscope:samlscope /src/api/build/install/samlscope/ /opt/samlscope/
USER 10001:10001
WORKDIR /opt/samlscope
ENV SAMLSCOPE_DATA_DIR=/data \
    SAMLSCOPE_HTTP_PORT=8080
EXPOSE 8080
ENTRYPOINT ["/opt/samlscope/bin/samlscope"]
