# syntax=docker/dockerfile:1
FROM golang:1.26.6-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/zentloop ./cmd/zentloop

FROM alpine:3.24.1
RUN apk add --no-cache tzdata ca-certificates libmaxminddb su-exec \
    && addgroup -S -g 101 zentloop && adduser -S -D -H -u 100 -G zentloop zentloop \
    && mkdir -p /data /site /app \
    && chown -R zentloop:zentloop /data /site /app
COPY --from=build /out/zentloop /app/zentloop
COPY --chmod=755 docker-entrypoint.sh /app/docker-entrypoint.sh
COPY --chown=zentloop:zentloop site/ /site/
EXPOSE 22 22222 8080 9090
VOLUME ["/data", "/site"]
ENTRYPOINT ["/app/docker-entrypoint.sh"]
