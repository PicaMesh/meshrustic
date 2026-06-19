//! LoRa mesh wire-format types shared by firmware and host tests.
#![cfg_attr(not(feature = "prost"), no_std)]

pub mod constants;
pub mod direct;
pub mod header;
pub mod portnum;

#[cfg(feature = "prost")]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/meshwire.rs"));
}

#[cfg(feature = "prost")]
pub use proto::SignalRoutingInfo;
#[cfg(feature = "prost")]
pub use proto::{Data, MeshPacket, PortNum, RouteDiscovery, Routing, SignalNeighbor, User};

pub use constants::*;
pub use direct::is_direct_packet;
pub use header::{DecodeError, EncodedPacket, PacketHeader, ParsedPacket};
pub use portnum::num;
pub use portnum::{qos_tier, rate_limit_bucket, QosTier, RateLimitBucket};
