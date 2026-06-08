# syntax=docker/dockerfile:1
#
# Runtime image for the MeshCheck Node agent: FROM scratch, nothing but the
# pre-built static binary and a CA bundle. Like deploy/Dockerfile it does NOT
# compile anything — it packages the artifacts produced by deploy/build.Dockerfile
# into dist/. Build dist/ first (see the Makefile):
#
#   make build      # compiles meshcheck-api and meshcheck-agent into dist/
#
# The agent performs outbound HTTPS checks, so it needs the CA bundle. It runs
# as root: it opens ICMP sockets for ping Checks and persists its signing key
# under /data. A hardened deployment would narrow this with CAP_NET_RAW and a
# dedicated user; the simulated VPS fleet keeps it simple.

FROM scratch

COPY dist/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY dist/meshcheck-agent /bin/meshcheck-agent

ENTRYPOINT ["/bin/meshcheck-agent"]
