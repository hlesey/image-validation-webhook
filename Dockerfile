FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS builder
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /image-validation-webhook .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /image-validation-webhook /image-validation-webhook
USER 65532:65532
ENTRYPOINT ["/image-validation-webhook"]
