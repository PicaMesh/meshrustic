use crate::config::{LoRaConfig, NodeConfig, DEFAULT_PSK};
use mesh_crypto::CryptoKey;

pub const STORE_MAGIC: u32 = 0x4D52_5354; // "MRST"
pub const STORE_VERSION: u32 = 1;
pub const STORE_RECORD_LEN: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    TooShort,
    BadMagic,
    BadVersion,
    BadCrc,
}

/// Serialize `NodeConfig` into a fixed-size flash record.
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
    out[77..77 + DEFAULT_PSK.len()].copy_from_slice(&DEFAULT_PSK);

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
    Ok(STORE_RECORD_LEN)
}

/// Decode a flash record written by [`encode`].
pub fn decode(buf: &[u8]) -> Result<NodeConfig, StoreError> {
    if buf.len() < STORE_RECORD_LEN {
        return Err(StoreError::TooShort);
    }

    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if magic != STORE_MAGIC {
        return Err(StoreError::BadMagic);
    }
    let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if version != STORE_VERSION {
        return Err(StoreError::BadVersion);
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

    let key_len = buf[76];
    let mut channel_key = CryptoKey::none();
    if key_len == 16 {
        channel_key = CryptoKey::from_bytes(&buf[77..93]);
    } else if key_len == 32 {
        channel_key = CryptoKey::from_bytes(&buf[77..109]);
    }

    let frequency_mhz = f32::from_le_bytes(buf[98..102].try_into().unwrap());
    let lora = LoRaConfig {
        region: mesh_radio::EU_868,
        modem_preset: buf[97],
        frequency_mhz,
        bandwidth_khz: 250.0,
        spreading_factor: buf[102],
        coding_rate: buf[103],
        sync_word: buf[104],
        hop_limit: buf[105],
        tx_power_dbm: buf[106],
    };

    Ok(NodeConfig {
        node_num: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        private_key,
        public_key,
        channel_key,
        lora,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use crate::keygen::generate_keypair;

    #[test]
    fn flash_round_trip() {
        let device_id = [0xAAu8; 16];
        let (priv_key, pub_key) = generate_keypair(Some(&device_id), 42);
        let config = NodeConfig::first_boot(0x1234_5678, priv_key, pub_key);

        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded.node_num, config.node_num);
        assert_eq!(decoded.private_key, priv_key);
        assert_eq!(decoded.public_key, pub_key);
        assert_eq!(decoded.lora.modem_preset, config.lora.modem_preset);
        assert_eq!(decoded.channel_key.length, 16);
    }
}
