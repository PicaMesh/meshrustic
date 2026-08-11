use std::io::Result;

fn main() -> Result<()> {
    if std::env::var("CARGO_FEATURE_PROST").is_ok() {
        prost_build::Config::new().compile_protos(
            &[
                "proto/meshwire/packet.proto",
                "proto/meshwire/channel.proto",
                "proto/meshwire/admin.proto",
                "proto/meshwire/config.proto",
                "proto/meshwire/portnums.proto",
            ],
            &["proto"],
        )?;
    }
    Ok(())
}
