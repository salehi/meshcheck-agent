# syntax=docker/dockerfile:1
#
# Minimal codegen base: a Go toolchain plus protoc. Installing the Go plugin
# and running protoc are left to proto/compose.yaml, so this image stays a
# plain, reusable "Go + protoc" environment.

FROM golang:1.23-alpine

RUN apk add --no-cache protobuf
