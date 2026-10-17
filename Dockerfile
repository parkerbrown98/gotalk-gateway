# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/gotalk-gateway ./cmd/gotalk-gateway

# Distroless: no shell or package manager, runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gotalk-gateway /gotalk-gateway
EXPOSE 8090
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 CMD ["/gotalk-gateway", "healthcheck"]
ENTRYPOINT ["/gotalk-gateway"]
CMD ["serve"]
