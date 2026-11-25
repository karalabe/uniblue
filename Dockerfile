# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/uniblue ./cmd/uniblue

RUN mkdir -p /out/data/.cache /out/tmp && \
    chmod 1777 /out/tmp && \
    echo "uniblue:x:10001:10001:uniblue:/data:/sbin/nologin" > /out/passwd && \
    echo "uniblue:x:10001:" > /out/group

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /out/passwd /etc/passwd
COPY --from=builder /out/group /etc/group
COPY --from=builder --chown=10001:10001 /out/data /data
COPY --from=builder /out/tmp /tmp
COPY --from=builder /out/uniblue /usr/local/bin/uniblue

ENV XDG_CACHE_HOME=/data/.cache
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080

USER 10001:10001

ENTRYPOINT ["/usr/local/bin/uniblue"]
CMD ["serve", "-config", "/data/config.yaml", "-listen", "0.0.0.0:8080"]
