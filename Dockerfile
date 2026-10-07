# The k0s-monitor image: the static binary on a distroless base, run as a
# non-root user. Build for both architectures with
#   docker buildx build --platform linux/amd64,linux/arm64 .
# Set it up once, then run it (see README, "Container"):
#   docker run --rm -it -v k0s-monitor-etc:/etc/k0s-monitor -v k0s-monitor-data:/var/lib/k0s-monitor IMAGE init --san HOSTNAME
#   docker run -d -p 8443:8443 -v k0s-monitor-etc:/etc/k0s-monitor -v k0s-monitor-data:/var/lib/k0s-monitor IMAGE

FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS=linux TARGETARCH=amd64 VERSION=dev COMMIT=unknown DATE=unknown
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X k0s_monitor/internal/version.Version=$VERSION -X k0s_monitor/internal/version.Commit=$COMMIT -X k0s_monitor/internal/version.Date=$DATE" \
      -o /out/k0s-monitor ./cmd/k0s-monitor && \
    mkdir -p /out/etc/k0s-monitor/packs /out/var/lib/k0s-monitor

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/k0s-monitor /usr/local/bin/k0s-monitor
# The directories belong to the image's user, so new volumes do too.
COPY --from=build --chown=65532:65532 /out/etc/k0s-monitor /etc/k0s-monitor
COPY --from=build --chown=65532:65532 /out/var/lib/k0s-monitor /var/lib/k0s-monitor
VOLUME ["/etc/k0s-monitor", "/var/lib/k0s-monitor"]
EXPOSE 8443
ENV K0S_MONITOR_CONTAINER=1
ENTRYPOINT ["/usr/local/bin/k0s-monitor"]
CMD ["serve"]
