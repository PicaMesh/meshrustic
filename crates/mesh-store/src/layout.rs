//! Flash record layout for NodeConfig (versioned, extensible).
//!
//! # Layout map (little-endian, `STORE_RECORD_LEN` = 256)
//!
//! | Offset | Len | Status | Content |
//! |--------|-----|--------|---------|
//! | 0 | 4 | frozen | Magic `MRST` (`0x4D525354`) |
//! | 4 | 4 | frozen | `STORE_VERSION` (current = 3) |
//! | 8 | 4 | frozen | `node_num` |
//! | 12 | 32 | frozen | `private_key` |
//! | 44 | 32 | frozen | `public_key` |
//! | 76 | 1 | frozen | channel key length (0/16/32) |
//! | 77 | 32 | frozen | channel key bytes |
//! | 109 | 1 | frozen | region code |
//! | 110 | 1 | frozen | modem_preset |
//! | 111 | 4 | frozen | frequency_mhz (`f32`) |
//! | 115 | 1 | frozen | spreading_factor |
//! | 116 | 1 | frozen | coding_rate |
//! | 117 | 1 | frozen | sync_word |
//! | 118 | 1 | frozen | hop_limit |
//! | 119 | 1 | frozen | tx_power_dbm |
//! | 120 | 1 | frozen | use_preset (0/1) |
//! | 121 | 3 | reserved | must encode as 0; ignore on decode (future flags) |
//! | 124 | 96 | frozen | `admin_public_keys[3][32]` |
//! | 220 | 32 | reserved | forward-compatible padding — encode 0; do not reinterpret |
//! | 252 | 4 | frozen | CRC32 over bytes `[0..252)` |
//!
//! Additive settings: prefer consuming reserved bytes with a version bump only when
//! semantics are incompatible. Always migrate older versions into `NodeConfig`.

use crate::config::{LoRaConfig, NodeConfig, ADMIN_KEY_SLOTS};
use mesh_crypto::CryptoKey;
use mesh_radio::EU_868;

pub const STORE_MAGIC: u32 = 0x4D52_5354; // "MRST"
/// Current on-disk version (v3 = v2 field map + documented reserved region / migration).
pub const STORE_VERSION: u32 = 3;
pub const STORE_VERSION_V1: u32 = 1;
pub const STORE_VERSION_V2: u32 = 2;
pub const STORE_RECORD_LEN: usize = 256;
pub const STORE_RECORD_LEN_V1: usize = 128;
/// Start of forward-compatible reserved tail (before CRC).
pub const STORE_RESERVED_START: usize = 220;
pub const STORE_RESERVED_END: usize = 252;
pub const STORE_CRC_OFFSET: usize = 252;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    TooShort,
    BadMagic,
    BadVersion,
    BadCrc,
}

/// Serialize `NodeConfig` into a fixed-size flash record (current version).
pub fn encode(config: &NodeConfig, out: &mut [u8]) -> Result<usize, StoreError> {
    if out.len() < STORE_RECORD_LEN {
        return Err(StoreError::TooShort);
    }

    out.fill(0);
    out[0..4].copy_from_slice(&STORE_MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&STORE_VERSION.to_le_bytes());
    out[8..12].copy_from_slice(&config.node_num.to_le_bytes());
    out[12..44].copy_from_slice(&config.private_key);
    out[44..76].copy_from_slice(&config.public_key);

    let key_len = config.channel_key.length.max(0) as u8;
    out[76] = key_len;
    let copy_len = (key_len as usize).min(32).min(config.channel_key.bytes.len());
    out[77..77 + copy_len].copy_from_slice(&config.channel_key.bytes[..copy_len]);

    let lora = config.lora;
    out[109] = lora.region.code;
    out[110] = lora.modem_preset;
    out[111..115].copy_from_slice(&lora.frequency_mhz.to_le_bytes());
    out[115] = lora.spreading_factor;
    out[116] = lora.coding_rate;
    out[117] = lora.sync_word;
    out[118] = lora.hop_limit;
    out[119] = lora.tx_power_dbm;
    out[120] = if lora.use_preset { 1 } else { 0 };
    // 121..124 reserved (zeros)

    for i in 0..ADMIN_KEY_SLOTS {
        let off = 124 + i * 32;
        out[off..off + 32].copy_from_slice(&config.admin_public_keys[i]);
    }
    // 220..252 reserved — left zero for forward compatibility

    let crc = crc32(&out[..STORE_CRC_OFFSET]);
    out[STORE_CRC_OFFSET..STORE_RECORD_LEN].copy_from_slice(&crc.to_le_bytes());
    Ok(STORE_RECORD_LEN)
}

/// Decode a flash record; migrate older versions into the latest `NodeConfig`.
pub fn decode(buf: &[u8]) -> Result<NodeConfig, StoreError> {
    if buf.len() < STORE_RECORD_LEN_V1 {
        return Err(StoreError::TooShort);
    }

    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if magic != STORE_MAGIC {
        return Err(StoreError::BadMagic);
    }
    let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    match version {
        STORE_VERSION_V1 => decode_v1(buf),
        STORE_VERSION_V2 | STORE_VERSION => decode_v2_or_v3(buf),
        _ => Err(StoreError::BadVersion),
    }
}

fn decode_v2_or_v3(buf: &[u8]) -> Result<NodeConfig, StoreError> {
    if buf.len() < STORE_RECORD_LEN {
        return Err(StoreError::TooShort);
    }

    let stored_crc =
        u32::from_le_bytes(buf[STORE_CRC_OFFSET..STORE_RECORD_LEN].try_into().unwrap());
    let computed = crc32(&buf[..STORE_CRC_OFFSET]);
    if stored_crc != computed {
        return Err(StoreError::BadCrc);
    }

    let mut private_key = [0u8; 32];
    let mut public_key = [0u8; 32];
    private_key.copy_from_slice(&buf[12..44]);
    public_key.copy_from_slice(&buf[44..76]);

    let channel_key = decode_channel_key(buf[76], &buf[77..109]);

    let frequency_mhz = f32::from_le_bytes(buf[111..115].try_into().unwrap());
    let lora = LoRaConfig {
        region: EU_868,
        modem_preset: buf[110],
        frequency_mhz,
        bandwidth_khz: bandwidth_for_preset(buf[110]),
        spreading_factor: buf[115],
        coding_rate: buf[116],
        sync_word: buf[117],
        hop_limit: buf[118],
        tx_power_dbm: buf[119],
        use_preset: buf[120] != 0,
    };

    let mut admin_public_keys = [[0u8; 32]; ADMIN_KEY_SLOTS];
    for i in 0..ADMIN_KEY_SLOTS {
        let off = 124 + i * 32;
        admin_public_keys[i].copy_from_slice(&buf[off..off + 32]);
    }

    Ok(NodeConfig {
        node_num: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        private_key,
        public_key,
        channel_key,
        lora,
        admin_public_keys,
    })
}

/// Migrate a v1 (128-byte) record: load fields, zero admin keys.
fn decode_v1(buf: &[u8]) -> Result<NodeConfig, StoreError> {
    if buf.len() < STORE_RECORD_LEN_V1 {
        return Err(StoreError::TooShort);
    }

    let stored_crc = u32::from_le_bytes(buf[124..128].try_into().unwrap());
    let computed = crc32(&buf[..124]);
    if stored_crc != computed {
        return Err(StoreError::BadCrc);
    }

    let mut private_key = [0u8; 32];
    let mut public_key = [0u8; 32];
    private_key.copy_from_slice(&buf[12..44]);
    public_key.copy_from_slice(&buf[44..76]);

    let channel_key = decode_channel_key(buf[76], &buf[77..109]);

    let frequency_mhz = f32::from_le_bytes(buf[98..102].try_into().unwrap());
    let modem_preset = buf[97];
    let lora = LoRaConfig {
        region: EU_868,
        modem_preset,
        frequency_mhz,
        bandwidth_khz: bandwidth_for_preset(modem_preset),
        spreading_factor: buf[102],
        coding_rate: buf[103],
        sync_word: buf[104],
        hop_limit: buf[105],
        tx_power_dbm: buf[106],
        use_preset: true,
    };

    Ok(NodeConfig {
        node_num: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        private_key,
        public_key,
        channel_key,
        lora,
        admin_public_keys: [[0u8; 32]; ADMIN_KEY_SLOTS],
    })
}

fn decode_channel_key(key_len: u8, bytes: &[u8]) -> CryptoKey {
    let mut channel_key = CryptoKey::none();
    if key_len == 16 && bytes.len() >= 16 {
        channel_key = CryptoKey::from_bytes(&bytes[..16]);
    } else if key_len == 32 && bytes.len() >= 32 {
        channel_key = CryptoKey::from_bytes(&bytes[..32]);
    }
    channel_key
}

fn bandwidth_for_preset(modem_preset: u8) -> f32 {
    mesh_radio::modem_preset_params(modem_preset, false).bandwidth_khz
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Encode a legacy v1 record (tests / migration tooling).
#[cfg(test)]
fn encode_v1_for_test(config: &NodeConfig, out: &mut [u8]) -> Result<usize, StoreError> {
    if out.len() < STORE_RECORD_LEN_V1 {
        return Err(StoreError::TooShort);
    }
    out.fill(0);
    out[0..4].copy_from_slice(&STORE_MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&STORE_VERSION_V1.to_le_bytes());
    out[8..12].copy_from_slice(&config.node_num.to_le_bytes());
    out[12..44].copy_from_slice(&config.private_key);
    out[44..76].copy_from_slice(&config.public_key);
    let key_len = config.channel_key.length.max(0) as u8;
    out[76] = key_len;
    let copy_len = (key_len as usize).min(32);
    out[77..77 + copy_len].copy_from_slice(&config.channel_key.bytes[..copy_len]);
    let lora = config.lora;
    out[96] = lora.region.code;
    out[97] = lora.modem_preset;
    out[98..102].copy_from_slice(&lora.frequency_mhz.to_le_bytes());
    out[102] = lora.spreading_factor;
    out[103] = lora.coding_rate;
    out[104] = lora.sync_word;
    out[105] = lora.hop_limit;
    out[106] = lora.tx_power_dbm;
    let crc = crc32(&out[..124]);
    out[124..128].copy_from_slice(&crc.to_le_bytes());
    Ok(STORE_RECORD_LEN_V1)
}

/// Encode a v2 record (same field map as v3) for migration tests.
#[cfg(test)]
fn encode_v2_for_test(config: &NodeConfig, out: &mut [u8]) -> Result<usize, StoreError> {
    encode(config, out)?;
    out[4..8].copy_from_slice(&STORE_VERSION_V2.to_le_bytes());
    let crc = crc32(&out[..STORE_CRC_OFFSET]);
    out[STORE_CRC_OFFSET..STORE_RECORD_LEN].copy_from_slice(&crc.to_le_bytes());
    Ok(STORE_RECORD_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NodeConfig, DEFAULT_PSK};
    use crate::keygen::generate_keypair;
    use mesh_crypto::CryptoKey;
    use mesh_radio::MODEM_SHORT_FAST;

    #[test]
    fn flash_round_trip_v3() {
        let device_id = [0xAAu8; 16];
        let (priv_key, pub_key) = generate_keypair(Some(&device_id), 42);
        let mut config = NodeConfig::first_boot(0x1234_5678, priv_key, pub_key);
        config.admin_public_keys[0] = [0x11; 32];
        config.admin_public_keys[2] = [0x33; 32];
        config.lora.apply_modem_preset(MODEM_SHORT_FAST);

        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), STORE_VERSION);
        assert!(buf[STORE_RESERVED_START..STORE_RESERVED_END]
            .iter()
            .all(|&b| b == 0));
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded.node_num, config.node_num);
        assert_eq!(decoded.private_key, priv_key);
        assert_eq!(decoded.public_key, pub_key);
        assert_eq!(decoded.lora.modem_preset, MODEM_SHORT_FAST);
        assert!(decoded.lora.use_preset);
        assert_eq!(decoded.channel_key.length, 16);
        assert_eq!(decoded.admin_public_keys[0], [0x11; 32]);
        assert_eq!(decoded.admin_public_keys[1], [0u8; 32]);
        assert_eq!(decoded.admin_public_keys[2], [0x33; 32]);
    }

    #[test]
    fn reserved_tail_nonzero_still_decodes_and_reencode_zeros() {
        let config = NodeConfig::first_boot(1, [1; 32], [2; 32]);
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();
        buf[STORE_RESERVED_START] = 0xAB;
        let crc = crc32(&buf[..STORE_CRC_OFFSET]);
        buf[STORE_CRC_OFFSET..STORE_RECORD_LEN].copy_from_slice(&crc.to_le_bytes());
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded.node_num, 1);
        encode(&decoded, &mut buf).unwrap();
        assert!(buf[STORE_RESERVED_START..STORE_RESERVED_END]
            .iter()
            .all(|&b| b == 0));
    }

    #[test]
    fn custom_channel_key_survives_round_trip() {
        let custom = [0x5Au8; 16];
        let mut config = NodeConfig::first_boot(1, [1; 32], [2; 32]);
        config.channel_key = CryptoKey::from_bytes(&custom);
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();
        assert_ne!(&buf[77..93], &DEFAULT_PSK);
        assert_eq!(&buf[77..93], &custom);
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded.channel_key.bytes[..16], custom);
    }

    #[test]
    fn bad_crc_rejected() {
        let config = NodeConfig::first_boot(1, [1; 32], [2; 32]);
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();
        buf[20] ^= 0xFF;
        assert_eq!(decode(&buf), Err(StoreError::BadCrc));
    }

    #[test]
    fn unknown_version_rejected() {
        let config = NodeConfig::first_boot(1, [1; 32], [2; 32]);
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();
        buf[4..8].copy_from_slice(&99u32.to_le_bytes());
        let crc = crc32(&buf[..STORE_CRC_OFFSET]);
        buf[STORE_CRC_OFFSET..STORE_RECORD_LEN].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(decode(&buf), Err(StoreError::BadVersion));
    }

    #[test]
    fn v1_migrates_with_empty_admin_keys() {
        let mut config = NodeConfig::first_boot(0xAABB, [9; 32], [8; 32]);
        config.channel_key = CryptoKey::from_bytes(&[0xCCu8; 16]);
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode_v1_for_test(&config, &mut buf).unwrap();
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded.node_num, 0xAABB);
        assert_eq!(decoded.channel_key.bytes[..16], [0xCCu8; 16]);
        assert_eq!(decoded.admin_public_keys, [[0u8; 32]; 3]);
        encode(&decoded, &mut buf).unwrap();
        assert_eq!(
            u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            STORE_VERSION
        );
    }

    #[test]
    fn v2_migrates_to_v3_on_rewrite() {
        let mut config = NodeConfig::first_boot(3, [3; 32], [4; 32]);
        config.admin_public_keys[1] = [0xEE; 32];
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode_v2_for_test(&config, &mut buf).unwrap();
        assert_eq!(
            u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            STORE_VERSION_V2
        );
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded.admin_public_keys[1], [0xEE; 32]);
        encode(&decoded, &mut buf).unwrap();
        assert_eq!(
            u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            STORE_VERSION
        );
    }

    #[test]
    fn admin_key_counts_0_to_3() {
        for n in 0..=3 {
            let mut config = NodeConfig::first_boot(1, [1; 32], [2; 32]);
            for i in 0..n {
                config.admin_public_keys[i] = [0x10 + i as u8; 32];
            }
            let mut buf = [0u8; STORE_RECORD_LEN];
            encode(&config, &mut buf).unwrap();
            let decoded = decode(&buf).unwrap();
            for i in 0..n {
                assert_eq!(decoded.admin_public_keys[i], [0x10 + i as u8; 32]);
            }
            for i in n..3 {
                assert_eq!(decoded.admin_public_keys[i], [0u8; 32]);
            }
        }
    }
}
