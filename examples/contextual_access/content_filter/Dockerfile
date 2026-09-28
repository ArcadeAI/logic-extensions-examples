FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Cache dependency downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy shared package and example source
COPY pkg/ pkg/
COPY examples/contextual_access/content_filter/ examples/contextual_access/content_filter/

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -trimpath -o /bin/server ./examples/contextual_access/content_filter

FROM gcr.io/distroless/static-debian12

COPY --from=builder /bin/server /bin/server

EXPOSE 8888

ENTRYPOINT ["/bin/server"]
