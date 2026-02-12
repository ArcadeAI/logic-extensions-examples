FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Cache dependency downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy shared package and example source
COPY pkg/ pkg/
COPY examples/user_blocking/ examples/user_blocking/

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -trimpath -o /bin/server ./examples/user_blocking

FROM gcr.io/distroless/static-debian12

COPY --from=builder /bin/server /bin/server

EXPOSE 8080

ENTRYPOINT ["/bin/server"]
