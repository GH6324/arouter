# Build stage
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
ARG BUILD_VERSION=dev
RUN BUILD_VERSION="${BUILD_VERSION:-$(cat VERSION 2>/dev/null || echo dev)}" \
  && go build -ldflags "-X main.buildVersion=${BUILD_VERSION}" -o /out/arouter ./cmd/controller

# Runtime stage
FROM alpine:3.23
WORKDIR /app

COPY --from=build /out/arouter /app/arouter

RUN mkdir -p /app/web
# 前端构建产物放在 cmd/controller/web/dist（已预构建或可通过外部挂载）
COPY --from=build /src/cmd/controller/web/dist /app/web/dist
RUN chmod +x /app/arouter
# Optional: default to SQLite db in /app/data/arouter.db
RUN mkdir -p /app/data
ENV DB_PATH=/app/data/arouter.db
ENV WEB_DIST=/app/web/dist
ENV CONTROLLER_ADDR=:8080
EXPOSE 8080
CMD ["/app/arouter"]
