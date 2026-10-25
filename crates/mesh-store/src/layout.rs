use crate::config::{
    LoRaConfig, NodeConfig, ADMIN_KEY_SLOTS, OWNER_LONG_NAME_MAX, OWNER_SHORT_NAME_MAX,
};
use mesh_crypto::CryptoKey;
use mesh_radio::EU_868;

pub const STORE_MAGIC: u32 = 0x4D52_5354;
pub const STORE_VERSION: u32 = 5;
pub const STORE_VERSION_V1: u32 = 1;
pub const STORE_VERSION_V2: u32 = 2;
pub const STORE_VERSION_V3: u32 = 3;
pub const STORE_VERSION_V4: u32 = 4;
pub const STORE_RECORD_LEN: usize = 304;
pub const STORE_RECORD_LEN_V4: usize = 256;
pub const STORE_RECORD_LEN_V1: usize = 128;
pub const STORE_SHORT_NAME_LEN_OFFSET: usize = 238;
pub const STORE_SHORT_NAME_OFFSET: usize = 239;
pub const STORE_LONG_NAME_LEN_OFFSET: usize = 243;
pub const STORE_LONG_NAME_OFFSET: usize = 244;
pub const STORE_RESERVED_START: usize = 283;
pub const STORE_RESERVED_END: usize = 300;
pub const STORE_CRC_OFFSET: usize = 300;
pub const STORE_CRC_OFFSET_V4: usize = 252;
#[cfg(test)]
pub const STORE_DEVICE_UPDATE_INTERVAL_OFFSET: usize = 220;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    TooShort,
    BadMagic,
    BadVersion,
    BadCrc,
    BadConfig,
}

pub fn encode(config: &NodeConfig, out: &mut [u8]) -> Result<usize, StoreError> {
    if out.len() < STORE_RECORD_LEN {
        return Err(StoreError::TooShort);
    }

    if !config.lora.frequency_mhz.is_finite() || config.lora.frequency_mhz <= 0.0 {
        return Err(StoreError::BadConfig);
    }
    out.fill(0);
    out[0..4].copy_from_slice(&STORE_MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&STORE_VERSION.to_le_bytes());
    out[8..12].copy_from_slice(&config.node_num.to_le_bytes());
    out[12..44].copy_from_slice(&config.private_key);
    out[44..76].copy_from_slice(&config.public_key);

    let key_len = config.channel_key.len() as u8;
    out[76] = key_len;
    let copy_len = (key_len as usize)
        .min(32)
        .min(config.channel_key.bytes.len());
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
    out[121] = if lora.ok_to_mqtt { 1 } else { 0 };
    out[122] = config.device_role;

    for i in 0..ADMIN_KEY_SLOTS {
        let off = 124 + i * 32;
        out[off..off + 32].copy_from_slice(&config.admin_public_keys[i]);
    }
    out[220..224].copy_from_slice(&config.device_update_interval_secs.to_le_bytes());
    out[224..228].copy_from_slice(&config.position_broadcast_secs.to_le_bytes());
    out[228] = u8::from(config.fixed_position);
    out[229] = u8::from(config.has_fixed_coords);
    out[230..234].copy_from_slice(&config.latitude_i.to_le_bytes());
    out[234..238].copy_from_slice(&config.longitude_i.to_le_bytes());
    encode_owner_names(config, out);

    let crc = crc32(&out[..STORE_CRC_OFFSET]);
    out[STORE_CRC_OFFSET..STORE_RECORD_LEN].copy_from_slice(&crc.to_le_bytes());
    Ok(STORE_RECORD_LEN)
}

fn encode_owner_names(config: &NodeConfig, out: &mut [u8]) {
    let short_len = (config.short_name_len as usize).min(OWNER_SHORT_NAME_MAX);
    out[STORE_SHORT_NAME_LEN_OFFSET] = short_len as u8;
    out[STORE_SHORT_NAME_OFFSET..STORE_SHORT_NAME_OFFSET + short_len]
        .copy_from_slice(&config.short_name[..short_len]);
    let long_len = (config.long_name_len as usize).min(OWNER_LONG_NAME_MAX);
    out[STORE_LONG_NAME_LEN_OFFSET] = long_len as u8;
    out[STORE_LONG_NAME_OFFSET..STORE_LONG_NAME_OFFSET + long_len]
        .copy_from_slice(&config.long_name[..long_len]);
}

fn decode_owner_names(buf: &[u8]) -> ([u8; OWNER_SHORT_NAME_MAX], u8, [u8; OWNER_LONG_NAME_MAX], u8) {
    let mut short_name = [0u8; OWNER_SHORT_NAME_MAX];
    let mut long_name = [0u8; OWNER_LONG_NAME_MAX];
    let short_raw = buf[STORE_SHORT_NAME_LEN_OFFSET];
    let long_raw = buf[STORE_LONG_NAME_LEN_OFFSET];
    let short_len = if (short_raw as usize) <= OWNER_SHORT_NAME_MAX {
        short_raw as usize
    } else {
        0
    };
    let long_len = if (long_raw as usize) <= OWNER_LONG_NAME_MAX {
        long_raw as usize
    } else {
        0
    };
    if short_len > 0 {
        short_name[..short_len].copy_from_slice(
            &buf[STORE_SHORT_NAME_OFFSET..STORE_SHORT_NAME_OFFSET + short_len],
        );
    }
    if long_len > 0 {
        long_name[..long_len]
            .copy_from_slice(&buf[STORE_LONG_NAME_OFFSET..STORE_LONG_NAME_OFFSET + long_len]);
    }
    (short_name, short_len as u8, long_name, long_len as u8)
}

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
        STORE_VERSION_V2 | STORE_VERSION_V3 | STORE_VERSION_V4 => decode_v2_to_v4(buf, version),
        STORE_VERSION => decode_v5(buf),
        _ => Err(StoreError::BadVersion),
    }
}

fn decode_v2_to_v4(buf: &[u8], version: u32) -> Result<NodeConfig, StoreError> {
    if buf.len() < STORE_RECORD_LEN_V4 {
        return Err(StoreError::TooShort);
    }

    let stored_crc =
        u32::from_le_bytes(buf[STORE_CRC_OFFSET_V4..STORE_RECORD_LEN_V4].try_into().unwrap());
    let computed = crc32(&buf[..STORE_CRC_OFFSET_V4]);
    if stored_crc != computed {
        return Err(StoreError::BadCrc);
    }

    parse_v2_body(buf, version)
}

fn decode_v5(buf: &[u8]) -> Result<NodeConfig, StoreError> {
    if buf.len() < STORE_RECORD_LEN {
        return Err(StoreError::TooShort);
    }

    let stored_crc =
        u32::from_le_bytes(buf[STORE_CRC_OFFSET..STORE_RECORD_LEN].try_into().unwrap());
    let computed = crc32(&buf[..STORE_CRC_OFFSET]);
    if stored_crc != computed {
        return Err(StoreError::BadCrc);
    }

    let mut cfg = parse_v2_body(buf, STORE_VERSION_V4)?;
    let (short_name, short_name_len, long_name, long_name_len) = decode_owner_names(buf);
    cfg.short_name = short_name;
    cfg.short_name_len = short_name_len;
    cfg.long_name = long_name;
    cfg.long_name_len = long_name_len;
    Ok(cfg)
}

fn parse_v2_body(buf: &[u8], version: u32) -> Result<NodeConfig, StoreError> {
    let mut private_key = [0u8; 32];
    let mut public_key = [0u8; 32];
    private_key.copy_from_slice(&buf[12..44]);
    public_key.copy_from_slice(&buf[44..76]);

    let channel_key = decode_channel_key(buf[76], &buf[77..109])?;

    let frequency_mhz = f32::from_le_bytes(buf[111..115].try_into().unwrap());
    if !frequency_mhz.is_finite() || frequency_mhz <= 0.0 {
        return Err(StoreError::BadConfig);
    }
    let modem_preset = mesh_radio::normalize_modem_preset(buf[110]);
    let lora = LoRaConfig {
        region: EU_868,
        modem_preset,
        frequency_mhz,
        bandwidth_khz: bandwidth_for_preset(modem_preset),
        spreading_factor: buf[115],
        coding_rate: buf[116],
        sync_word: buf[117],
        hop_limit: buf[118],
        tx_power_dbm: buf[119],
        use_preset: buf[120] != 0,
        ok_to_mqtt: if version >= STORE_VERSION_V4 {
            buf[121] != 0
        } else {
            true
        },
    };

    let mut admin_public_keys = [[0u8; 32]; ADMIN_KEY_SLOTS];
    for (i, key) in admin_public_keys.iter_mut().enumerate() {
        let off = 124 + i * 32;
        key.copy_from_slice(&buf[off..off + 32]);
    }

    let device_update_interval_secs = u32::from_le_bytes(buf[220..224].try_into().unwrap());
    let position_broadcast_secs = u32::from_le_bytes(buf[224..228].try_into().unwrap());
    let fixed_position = buf[228] != 0;
    let has_fixed_coords = buf[229] != 0;
    let latitude_i = i32::from_le_bytes(buf[230..234].try_into().unwrap());
    let longitude_i = i32::from_le_bytes(buf[234..238].try_into().unwrap());
    let device_role = buf[122];

    Ok(NodeConfig {
        node_num: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        private_key,
        public_key,
        channel_key,
        lora,
        admin_public_keys,
        device_update_interval_secs,
        device_role,
        position_broadcast_secs,
        fixed_position,
        latitude_i,
        longitude_i,
        has_fixed_coords,
        short_name: [0; OWNER_SHORT_NAME_MAX],
        short_name_len: 0,
        long_name: [0; OWNER_LONG_NAME_MAX],
        long_name_len: 0,
    })
}

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

    let channel_key = {
        // Legacy v1 radio bytes overwrote part of a 256-bit key; accepting it would silently install a
        // corrupt channel key.
        if buf[76] == 32 {
            return Err(StoreError::BadConfig);
        }
        decode_channel_key(buf[76], &buf[77..96])?
    };

    let frequency_mhz = f32::from_le_bytes(buf[98..102].try_into().unwrap());
    let modem_preset = mesh_radio::normalize_modem_preset(buf[97]);
    if !frequency_mhz.is_finite() || frequency_mhz <= 0.0 {
        return Err(StoreError::BadConfig);
    }
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
        ok_to_mqtt: true,
    };

    Ok(NodeConfig {
        node_num: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        private_key,
        public_key,
        channel_key,
        lora,
        admin_public_keys: [[0u8; 32]; ADMIN_KEY_SLOTS],
        device_update_interval_secs: 0,
        device_role: 0,
        position_broadcast_secs: 0,
        fixed_position: false,
        latitude_i: 0,
        longitude_i: 0,
        has_fixed_coords: false,
        short_name: [0; OWNER_SHORT_NAME_MAX],
        short_name_len: 0,
        long_name: [0; OWNER_LONG_NAME_MAX],
        long_name_len: 0,
    })
}

fn decode_channel_key(key_len: u8, bytes: &[u8]) -> Result<CryptoKey, StoreError> {
    match key_len {
        0 => Ok(CryptoKey::none()),
        16 | 32 if bytes.len() >= key_len as usize => {
            Ok(CryptoKey::from_bytes(&bytes[..key_len as usize]))
        }
        _ => Err(StoreError::BadConfig),
    }
}

fn bandwidth_for_preset(modem_preset: u8) -> f32 {
    mesh_radio::modem_preset_params(modem_preset, false).bandwidth_khz
}

pub(crate) fn crc32(data: &[u8]) -> u32 {
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
    let key_len = config.channel_key.len() as u8;
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

#[cfg(test)]
fn encode_v4_sized(config: &NodeConfig, out: &mut [u8], version: u32) -> Result<usize, StoreError> {
    if out.len() < STORE_RECORD_LEN_V4 {
        return Err(StoreError::TooShort);
    }
    encode(config, out)?;
    // Shrink a v5 encode down to the legacy 256-byte record for migration tests.
    out[4..8].copy_from_slice(&version.to_le_bytes());
    out[STORE_SHORT_NAME_LEN_OFFSET..STORE_RECORD_LEN_V4].fill(0);
    let crc = crc32(&out[..STORE_CRC_OFFSET_V4]);
    out[STORE_CRC_OFFSET_V4..STORE_RECORD_LEN_V4].copy_from_slice(&crc.to_le_bytes());
    Ok(STORE_RECORD_LEN_V4)
}

#[cfg(test)]
fn encode_v2_for_test(config: &NodeConfig, out: &mut [u8]) -> Result<usize, StoreError> {
    encode_v4_sized(config, out, STORE_VERSION_V2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NodeConfig, DEFAULT_PSK};
    use crate::keygen::generate_keypair;
    use mesh_crypto::CryptoKey;
    use mesh_radio::MODEM_SHORT_FAST;

    #[test]
    fn ok_to_mqtt_off_survives_round_trip() {
        let (priv_key, pub_key) = generate_keypair([0x5Au8; 32], &[0; 8]);
        let mut config = NodeConfig::first_boot(0x1234_5678, priv_key, pub_key);
        assert!(config.lora.ok_to_mqtt, "on by default");
        config.lora.ok_to_mqtt = false;
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();
        assert_eq!(buf[121], 0);
        assert!(!decode(&buf).unwrap().lora.ok_to_mqtt);
    }

    #[test]
    fn v3_record_migrates_with_ok_to_mqtt_on() {
        let (priv_key, pub_key) = generate_keypair([0x5Bu8; 32], &[0; 8]);
        let mut config = NodeConfig::first_boot(0x1234_5678, priv_key, pub_key);
        config.lora.ok_to_mqtt = false;
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode_v4_sized(&config, &mut buf, STORE_VERSION_V3).unwrap();
        buf[121] = 0;
        let crc = crc32(&buf[..STORE_CRC_OFFSET_V4]);
        buf[STORE_CRC_OFFSET_V4..STORE_RECORD_LEN_V4].copy_from_slice(&crc.to_le_bytes());
        let decoded = decode(&buf[..STORE_RECORD_LEN_V4]).unwrap();
        assert!(decoded.lora.ok_to_mqtt, "pre-v4 records take the default");
        assert_eq!(decoded.short_name_len, 0);
        assert_eq!(decoded.long_name_len, 0);
        let mut again = [0u8; STORE_RECORD_LEN];
        encode(&decoded, &mut again).unwrap();
        assert_eq!(
            u32::from_le_bytes(again[4..8].try_into().unwrap()),
            STORE_VERSION
        );
        assert_eq!(again[121], 1);
    }

    #[test]
    fn owner_names_survive_v5_round_trip() {
        let mut config = NodeConfig::first_boot(1, [1; 32], [2; 32]);
        config.short_name[..3].copy_from_slice(b"ABC");
        config.short_name_len = 3;
        config.long_name[..9].copy_from_slice(b"CabinNode");
        config.long_name_len = 9;
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();
        assert_eq!(buf[STORE_SHORT_NAME_LEN_OFFSET], 3);
        assert_eq!(&buf[STORE_SHORT_NAME_OFFSET..STORE_SHORT_NAME_OFFSET + 3], b"ABC");
        assert_eq!(buf[STORE_LONG_NAME_LEN_OFFSET], 9);
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded.short_name_len, 3);
        assert_eq!(&decoded.short_name[..3], b"ABC");
        assert_eq!(decoded.long_name_len, 9);
        assert_eq!(&decoded.long_name[..9], b"CabinNode");
    }

    #[test]
    fn v4_record_migrates_to_empty_names() {
        let mut config = NodeConfig::first_boot(7, [7; 32], [8; 32]);
        config.short_name[..2].copy_from_slice(b"XX");
        config.short_name_len = 2;
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode_v4_sized(&config, &mut buf, STORE_VERSION_V4).unwrap();
        let decoded = decode(&buf[..STORE_RECORD_LEN_V4]).unwrap();
        assert_eq!(decoded.short_name_len, 0);
        assert_eq!(decoded.long_name_len, 0);
        let mut again = [0u8; STORE_RECORD_LEN];
        encode(&decoded, &mut again).unwrap();
        assert_eq!(
            u32::from_le_bytes(again[4..8].try_into().unwrap()),
            STORE_VERSION
        );
        assert_eq!(again[STORE_SHORT_NAME_LEN_OFFSET], 0);
        assert_eq!(again[STORE_LONG_NAME_LEN_OFFSET], 0);
    }

    #[test]
    fn invalid_owner_name_lengths_decode_as_empty() {
        let config = NodeConfig::first_boot(1, [1; 32], [2; 32]);
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();
        buf[STORE_SHORT_NAME_LEN_OFFSET] = 5;
        buf[STORE_LONG_NAME_LEN_OFFSET] = 40;
        let crc = crc32(&buf[..STORE_CRC_OFFSET]);
        buf[STORE_CRC_OFFSET..STORE_RECORD_LEN].copy_from_slice(&crc.to_le_bytes());
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded.short_name_len, 0);
        assert_eq!(decoded.long_name_len, 0);
    }

    #[test]
    fn flash_round_trip_v3() {
        let device_id = [0xAAu8; 16];
        let (priv_key, pub_key) = generate_keypair([device_id[0]; 32], &[0; 8]);
        let mut config = NodeConfig::first_boot(0x1234_5678, priv_key, pub_key);
        config.admin_public_keys[0] = [0x11; 32];
        config.admin_public_keys[2] = [0x33; 32];
        config.lora.apply_modem_preset(MODEM_SHORT_FAST);

        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();
        assert_eq!(
            u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            STORE_VERSION
        );
        assert!(buf[STORE_RESERVED_START..STORE_RESERVED_END]
            .iter()
            .all(|&b| b == 0));
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded.node_num, config.node_num);
        assert_eq!(decoded.private_key, priv_key);
        assert_eq!(decoded.public_key, pub_key);
        assert_eq!(decoded.lora.modem_preset, MODEM_SHORT_FAST);
        assert!(decoded.lora.use_preset);
        assert_eq!(decoded.channel_key.len(), 16);
        assert_eq!(decoded.admin_public_keys[0], [0x11; 32]);
        assert_eq!(decoded.admin_public_keys[1], [0u8; 32]);
        assert_eq!(decoded.admin_public_keys[2], [0x33; 32]);
    }

    #[test]
    fn invalid_stored_modem_preset_migrates_to_default() {
        let mut config = NodeConfig::first_boot(1, [1; 32], [2; 32]);
        config.lora.modem_preset = u8::MAX;
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();

        let decoded = decode(&buf).expect("invalid preset is migrated");
        assert_eq!(decoded.lora.modem_preset, mesh_radio::MODEM_DEFAULT_PRESET);
        assert_eq!(
            decoded.lora.bandwidth_khz,
            mesh_radio::modem_preset_params(mesh_radio::MODEM_DEFAULT_PRESET, false).bandwidth_khz
        );
    }

    #[test]
    fn device_update_interval_survives_round_trip() {
        let mut config = NodeConfig::first_boot(1, [1; 32], [2; 32]);
        config.device_update_interval_secs = 600;
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();
        assert_eq!(
            u32::from_le_bytes(
                buf[STORE_DEVICE_UPDATE_INTERVAL_OFFSET..STORE_DEVICE_UPDATE_INTERVAL_OFFSET + 4]
                    .try_into()
                    .unwrap()
            ),
            600
        );
        assert_eq!(decode(&buf).unwrap().device_update_interval_secs, 600);
    }

    #[test]
    fn device_role_survives_round_trip() {
        let mut config = NodeConfig::first_boot(1, [1; 32], [2; 32]);
        config.device_role = 2;
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();
        assert_eq!(buf[122], 2);
        assert_eq!(decode(&buf).unwrap().device_role, 2);
    }

    #[test]
    fn older_flash_with_zero_role_byte_stays_client() {
        let config = NodeConfig::first_boot(1, [1; 32], [2; 32]);
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();
        assert_eq!(buf[122], 0);
        assert_eq!(decode(&buf).unwrap().device_role, 0);
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

    #[test]
    fn fixed_position_survives_round_trip() {
        let mut config = NodeConfig::first_boot(1, [1; 32], [2; 32]);
        config.position_broadcast_secs = 7_200;
        config.fixed_position = true;
        config.has_fixed_coords = true;
        config.latitude_i = -33_000_001;
        config.longitude_i = 151_000_002;
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut buf).unwrap();
        let decoded = decode(&buf).unwrap();
        assert_eq!(decoded.position_broadcast_secs, 7_200);
        assert!(decoded.fixed_position);
        assert!(decoded.has_fixed_coords);
        assert_eq!(decoded.latitude_i, -33_000_001);
        assert_eq!(decoded.longitude_i, 151_000_002);
        assert!(buf[STORE_RESERVED_START..STORE_RESERVED_END]
            .iter()
            .all(|&b| b == 0));
    }

    #[test]
    fn invalid_stored_key_length_is_not_downgraded_to_plaintext() {
        let config = NodeConfig::first_boot(1, [0; 32], [0; 32]);
        let mut wire = [0; STORE_RECORD_LEN];
        encode(&config, &mut wire).unwrap();
        wire[76] = 17;
        let crc = crc32(&wire[..STORE_CRC_OFFSET]);
        wire[STORE_CRC_OFFSET..].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(decode(&wire), Err(StoreError::BadConfig));
    }
}
