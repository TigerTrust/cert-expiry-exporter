# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w" -o /out/exporter ./cmd/exporter

FROM gcr.io/distroless/static:nonroot
USER nonroot:nonroot
COPY --from=build /out/exporter /exporter
EXPOSE 8080 8081
ENTRYPOINT ["/exporter"]
