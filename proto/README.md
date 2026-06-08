# Agent Protocol — Protobuf Definitions

[`agent.proto`](agent.proto) is the single source of truth for every message
on the Node ↔ Platform bidirectional stream — transport, handshake, lifecycle,
and the rules each side obeys.

## Generated code

`protoc` generates **message structs only** — there are no gRPC service stubs,
because the transport is framed Protobuf over WebSocket with no gRPC runtime.
The generated file is committed at
[`../pkg/agentpb/agent.pb.go`](../pkg/agentpb/agent.pb.go).

## Regenerating

Run after any change to `agent.proto`, from the agent repository root:

```sh
docker-compose -f proto/compose.yaml run --rm codegen
```

This builds a small codegen container (`proto/codegen.Dockerfile`) and runs it
against the repository — no Go or `protoc` needs to be installed on the host.
Commit the regenerated `agent.pb.go` alongside the `.proto` change.

## Wire format

Each WebSocket binary frame carries exactly one marshalled `Envelope`. The
`oneof body` selects the message type. New message types and fields are added
additively within a major protocol version; see the *Versioning* section of
the protocol doc.
