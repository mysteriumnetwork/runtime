# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/runtime-cli ./cmd/runtime-cli

FROM alpine:3.23

RUN apk add --no-cache ca-certificates curl runc

COPY --from=build /out/runtime-cli /usr/local/bin/runtime-cli
COPY docker/subuid /etc/subuid
COPY docker/subgid /etc/subgid
COPY --chmod=0555 docker/runtime-demo /usr/local/bin/runtime-demo

VOLUME ["/var/lib/mysterium-runtime"]

ENTRYPOINT ["/usr/local/bin/runtime-cli"]
CMD ["-runtime-dir", "/var/lib/mysterium-runtime", "-command", "capabilities"]
