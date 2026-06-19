# mesh-protocol

Wire framing and protobuf payload types for MeshRustic.

## Provenance

All definitions in this crate are **original PicaMesh work**. Field numbers and
types follow the public LoRa mesh wire specification so MeshRustic nodes can
exchange packets with other compatible devices on the air. No source files from
the Meshtastic firmware repository or other third-party trees are copied into
this crate.

## Layout

| File | Purpose |
|------|---------|
| `proto/meshwire/packet.proto` | Core routing + signal-routing payloads |
| `proto/meshwire/portnums.proto` | Port numbers used for classification |
| `proto/meshwire/config.proto` | Device role enum for `User` decode |
| `src/header.rs` | 16-byte LoRa `PacketHeader` |
| `src/portnum.rs` | Rate-limit and QoS buckets by port number |

Regenerate prost bindings with the `prost` feature enabled (`protoc` required).

The 16-byte LoRa header matches the public mesh air interface (`PACKET_HEADER_LEN == 16`).
