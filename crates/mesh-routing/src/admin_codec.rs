//! Hand-rolled AdminMessage / Config wire codecs (public LoRa mesh admin format, v1 subset).

use crate::nodeinfo::NodeInfoIdentity;

/// `ADMIN_APP` port number.
pub const ADMIN_APP: u32 = 6;

/// `ConfigType` values used by `get_config_request`.
pub const CONFIG_TYPE_DEVICE: u32 = 0;
pub const CONFIG_TYPE_LORA: u32 = 5;
pub const CONFIG_TYPE_SECURITY: u32 = 7;
pub const CONFIG_TYPE_SESSIONKEY: u32 = 8;

/// `RegionCode.EU_868`.
pub const REGION_EU_868: u32 = 3;

/// `Channel.Role` values.
pub const CHANNEL_ROLE_DISABLED: u32 = 0;
pub const CHANNEL_ROLE_PRIMARY: u32 = 1;
pub const CHANNEL_ROLE_SECONDARY: u32 = 2;

/// Session passkey length on the wire (AdminMessage field 101).
pub const SESSION_PASSKEY_LEN: usize = 8;

/// Max configurable admin keys in SecurityConfig.
pub const MAX_ADMIN_KEYS: usize = 3;

/// Max channel name bytes we encode/decode.
pub const CHANNEL_NAME_MAX: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireLoRaConfig {
    pub use_preset: bool,
    pub modem_preset: u32,
    pub region: u32,
    pub hop_limit: u32,
    pub tx_power: i32,
}

impl Default for WireLoRaConfig {
    fn default() -> Self {
        Self {
            use_preset: true,
            modem_preset: mesh_radio::MODEM_SHORT_SLOW as u32,
            region: REGION_EU_868,
            hop_limit: 3,
            tx_power: 27,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireDeviceConfig {
    pub role: u32,
}

impl Default for WireDeviceConfig {
    fn default() -> Self {
        Self {
            role: crate::nodeinfo::DEVICE_ROLE_ROUTER,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireSecurityConfig {
    pub public_key: [u8; 32],
    pub has_public_key: bool,
    pub private_key: [u8; 32],
    pub has_private_key: bool,
    pub admin_keys: [[u8; 32]; MAX_ADMIN_KEYS],
    pub admin_key_count: u8,
    pub is_managed: bool,
    pub admin_channel_enabled: bool,
}

impl Default for WireSecurityConfig {
    fn default() -> Self {
        Self {
            public_key: [0; 32],
            has_public_key: false,
            private_key: [0; 32],
            has_private_key: false,
            admin_keys: [[0; 32]; MAX_ADMIN_KEYS],
            admin_key_count: 0,
            is_managed: false,
            admin_channel_enabled: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireChannelSettings {
    pub psk: [u8; 32],
    pub psk_len: u8,
    pub name: [u8; CHANNEL_NAME_MAX],
    pub name_len: u8,
    pub id: u32,
    pub has_id: bool,
}

impl Default for WireChannelSettings {
    fn default() -> Self {
        Self {
            psk: [0; 32],
            psk_len: 0,
            name: [0; CHANNEL_NAME_MAX],
            name_len: 0,
            id: 0,
            has_id: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireChannel {
    pub index: i32,
    pub role: u32,
    pub settings: WireChannelSettings,
    pub has_settings: bool,
}

impl Default for WireChannel {
    fn default() -> Self {
        Self {
            index: 0,
            role: CHANNEL_ROLE_DISABLED,
            settings: WireChannelSettings::default(),
            has_settings: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigPayload {
    Empty,
    Device(WireDeviceConfig),
    Lora(WireLoRaConfig),
    Security(WireSecurityConfig),
    Sessionkey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceMetadata {
    pub firmware_version: [u8; 32],
    pub firmware_version_len: u8,
    pub hw_model: u32,
}

impl Default for DeviceMetadata {
    fn default() -> Self {
        Self {
            firmware_version: [0; 32],
            firmware_version_len: 0,
            hw_model: 0,
        }
    }
}

impl DeviceMetadata {
    pub fn meshrustic_default(hw_model: u32) -> Self {
        let ver = b"MeshRustic";
        let mut out = Self::default();
        out.firmware_version[..ver.len()].copy_from_slice(ver);
        out.firmware_version_len = ver.len() as u8;
        out.hw_model = hw_model;
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminPayload {
    None,
    GetChannelRequest(u32),
    GetChannelResponse(WireChannel),
    GetOwnerRequest,
    GetOwnerResponse(NodeInfoIdentity),
    GetConfigRequest(u32),
    GetConfigResponse(ConfigPayload),
    GetModuleConfigRequest(u32),
    GetModuleConfigResponse,
    GetDeviceMetadataRequest,
    GetDeviceMetadataResponse(DeviceMetadata),
    SetConfig(ConfigPayload),
    BeginEditSettings,
    CommitEditSettings,
    RebootSeconds(i32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminMessage {
    pub session_passkey: [u8; SESSION_PASSKEY_LEN],
    pub has_session_passkey: bool,
    pub payload: AdminPayload,
}

impl Default for AdminMessage {
    fn default() -> Self {
        Self {
            session_passkey: [0; SESSION_PASSKEY_LEN],
            has_session_passkey: false,
            payload: AdminPayload::None,
        }
    }
}

/// Encode `Config` oneof payload bytes (no AdminMessage wrapper).
pub fn encode_config(config: &ConfigPayload) -> heapless::Vec<u8, 240> {
    let mut out = heapless::Vec::new();
    match config {
        ConfigPayload::Empty => {}
        ConfigPayload::Device(dev) => {
            let inner = encode_device_config(dev);
            push_bytes_field(&mut out, 1, &inner);
        }
        ConfigPayload::Lora(lora) => {
            let inner = encode_lora_config(lora);
            push_bytes_field(&mut out, 6, &inner);
        }
        ConfigPayload::Security(sec) => {
            let inner = encode_security_config(sec);
            push_bytes_field(&mut out, 8, &inner);
        }
        ConfigPayload::Sessionkey => {
            // Empty SessionkeyConfig message on field 9.
            push_bytes_field(&mut out, 9, &[]);
        }
    }
    out
}

pub fn encode_device_config(dev: &WireDeviceConfig) -> heapless::Vec<u8, 16> {
    let mut out = heapless::Vec::new();
    if dev.role != 0 {
        push_varint_field(&mut out, 1, dev.role);
    }
    out
}

pub fn encode_lora_config(lora: &WireLoRaConfig) -> heapless::Vec<u8, 64> {
    let mut out = heapless::Vec::new();
    if lora.use_preset {
        push_varint_field(&mut out, 1, 1);
    }
    if lora.modem_preset != 0 {
        push_varint_field(&mut out, 2, lora.modem_preset);
    }
    if lora.region != 0 {
        push_varint_field(&mut out, 7, lora.region);
    }
    if lora.hop_limit != 0 {
        push_varint_field(&mut out, 8, lora.hop_limit);
    }
    if lora.tx_power != 0 {
        push_svarint_field(&mut out, 11, lora.tx_power);
    }
    out
}

pub fn encode_security_config(sec: &WireSecurityConfig) -> heapless::Vec<u8, 200> {
    let mut out = heapless::Vec::new();
    if sec.has_public_key {
        push_bytes_field(&mut out, 1, &sec.public_key);
    }
    if sec.has_private_key {
        push_bytes_field(&mut out, 2, &sec.private_key);
    }
    let count = (sec.admin_key_count as usize).min(MAX_ADMIN_KEYS);
    for i in 0..count {
        push_bytes_field(&mut out, 3, &sec.admin_keys[i]);
    }
    if sec.is_managed {
        push_varint_field(&mut out, 4, 1);
    }
    if sec.admin_channel_enabled {
        push_varint_field(&mut out, 8, 1);
    }
    out
}

pub fn encode_channel(ch: &WireChannel) -> heapless::Vec<u8, 96> {
    let mut out = heapless::Vec::new();
    if ch.index != 0 {
        push_svarint_field(&mut out, 1, ch.index);
    }
    if ch.has_settings {
        let inner = encode_channel_settings(&ch.settings);
        push_bytes_field(&mut out, 2, &inner);
    }
    if ch.role != 0 {
        push_varint_field(&mut out, 3, ch.role);
    }
    out
}

pub fn encode_channel_settings(settings: &WireChannelSettings) -> heapless::Vec<u8, 80> {
    let mut out = heapless::Vec::new();
    if settings.psk_len > 0 {
        let len = (settings.psk_len as usize).min(32);
        push_bytes_field(&mut out, 2, &settings.psk[..len]);
    }
    if settings.name_len > 0 {
        let len = (settings.name_len as usize).min(CHANNEL_NAME_MAX);
        push_bytes_field(&mut out, 3, &settings.name[..len]);
    }
    if settings.has_id {
        // fixed32 field 4
        push_tag(&mut out, 4, 5);
        let _ = out.extend_from_slice(&settings.id.to_le_bytes());
    }
    out
}

/// Decode a `Config` protobuf (fields 1 / 6 / 8 / 9).
pub fn decode_config(payload: &[u8]) -> Option<ConfigPayload> {
    let mut result = ConfigPayload::Empty;
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                result = ConfigPayload::Device(decode_device_config(&payload[ni..end])?);
                i = end;
            }
            (6, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                result = ConfigPayload::Lora(decode_lora_config(&payload[ni..end])?);
                i = end;
            }
            (8, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                result = ConfigPayload::Security(decode_security_config(&payload[ni..end])?);
                i = end;
            }
            (9, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                result = ConfigPayload::Sessionkey;
                i = end;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    Some(result)
}

pub fn decode_device_config(payload: &[u8]) -> Option<WireDeviceConfig> {
    let mut dev = WireDeviceConfig::default();
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                dev.role = v;
                i = ni;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    Some(dev)
}

pub fn decode_lora_config(payload: &[u8]) -> Option<WireLoRaConfig> {
    let mut lora = WireLoRaConfig::default();
    lora.use_preset = false;
    lora.modem_preset = 0;
    lora.region = 0;
    lora.hop_limit = 0;
    lora.tx_power = 0;
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                lora.use_preset = v != 0;
                i = ni;
            }
            (2, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                lora.modem_preset = v;
                i = ni;
            }
            (7, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                lora.region = v;
                i = ni;
            }
            (8, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                lora.hop_limit = v;
                i = ni;
            }
            (11, 0) => {
                let (v, ni) = read_svarint(payload, i)?;
                lora.tx_power = v;
                i = ni;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    Some(lora)
}

pub fn decode_security_config(payload: &[u8]) -> Option<WireSecurityConfig> {
    let mut sec = WireSecurityConfig::default();
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                let slice = &payload[ni..end];
                if slice.len() == 32 {
                    sec.public_key.copy_from_slice(slice);
                    sec.has_public_key = true;
                }
                i = end;
            }
            (2, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                let slice = &payload[ni..end];
                if slice.len() == 32 {
                    sec.private_key.copy_from_slice(slice);
                    sec.has_private_key = true;
                }
                i = end;
            }
            (3, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                let slice = &payload[ni..end];
                if slice.len() == 32 && (sec.admin_key_count as usize) < MAX_ADMIN_KEYS {
                    let slot = sec.admin_key_count as usize;
                    sec.admin_keys[slot].copy_from_slice(slice);
                    sec.admin_key_count += 1;
                }
                i = end;
            }
            (4, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                sec.is_managed = v != 0;
                i = ni;
            }
            (8, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                sec.admin_channel_enabled = v != 0;
                i = ni;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    Some(sec)
}

pub fn decode_channel(payload: &[u8]) -> Option<WireChannel> {
    let mut ch = WireChannel::default();
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 0) => {
                let (v, ni) = read_svarint(payload, i)?;
                ch.index = v;
                i = ni;
            }
            (2, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                ch.settings = decode_channel_settings(&payload[ni..end])?;
                ch.has_settings = true;
                i = end;
            }
            (3, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                ch.role = v;
                i = ni;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    Some(ch)
}

pub fn decode_channel_settings(payload: &[u8]) -> Option<WireChannelSettings> {
    let mut settings = WireChannelSettings::default();
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (2, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                let slice = &payload[ni..end];
                let copy = slice.len().min(32);
                settings.psk[..copy].copy_from_slice(&slice[..copy]);
                settings.psk_len = copy as u8;
                i = end;
            }
            (3, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                let slice = &payload[ni..end];
                let copy = slice.len().min(CHANNEL_NAME_MAX);
                settings.name[..copy].copy_from_slice(&slice[..copy]);
                settings.name_len = copy as u8;
                i = end;
            }
            (4, 5) => {
                if i + 4 > payload.len() {
                    return None;
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&payload[i..i + 4]);
                settings.id = u32::from_le_bytes(buf);
                settings.has_id = true;
                i += 4;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    Some(settings)
}

pub fn encode_admin_message(msg: &AdminMessage) -> heapless::Vec<u8, 240> {
    let mut out = heapless::Vec::new();
    match &msg.payload {
        AdminPayload::None => {}
        AdminPayload::GetChannelRequest(index_plus_one) => {
            push_varint_field(&mut out, 1, *index_plus_one);
        }
        AdminPayload::GetChannelResponse(ch) => {
            let inner = encode_channel(ch);
            push_bytes_field(&mut out, 2, &inner);
        }
        AdminPayload::GetOwnerRequest => {
            push_varint_field(&mut out, 3, 1);
        }
        AdminPayload::GetOwnerResponse(identity) => {
            let user = encode_owner_user(0, identity);
            push_bytes_field(&mut out, 4, &user);
        }
        AdminPayload::GetConfigRequest(config_type) => {
            push_varint_field(&mut out, 5, *config_type);
        }
        AdminPayload::GetConfigResponse(config) => {
            let inner = encode_config(config);
            push_bytes_field(&mut out, 6, &inner);
        }
        AdminPayload::GetModuleConfigRequest(config_type) => {
            push_varint_field(&mut out, 7, *config_type);
        }
        AdminPayload::GetModuleConfigResponse => {
            // Empty ModuleConfig message.
            push_bytes_field(&mut out, 8, &[]);
        }
        AdminPayload::GetDeviceMetadataRequest => {
            push_varint_field(&mut out, 12, 1);
        }
        AdminPayload::GetDeviceMetadataResponse(meta) => {
            let inner = encode_device_metadata(meta);
            push_bytes_field(&mut out, 13, &inner);
        }
        AdminPayload::SetConfig(config) => {
            let inner = encode_config(config);
            push_bytes_field(&mut out, 34, &inner);
        }
        AdminPayload::BeginEditSettings => {
            push_varint_field(&mut out, 64, 1);
        }
        AdminPayload::CommitEditSettings => {
            push_varint_field(&mut out, 65, 1);
        }
        AdminPayload::RebootSeconds(secs) => {
            push_svarint_field(&mut out, 97, *secs);
        }
    }
    if msg.has_session_passkey {
        push_bytes_field(&mut out, 101, &msg.session_passkey);
    }
    out
}

pub fn decode_admin_message(payload: &[u8]) -> Option<AdminMessage> {
    let mut msg = AdminMessage::default();
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                msg.payload = AdminPayload::GetChannelRequest(v);
                i = ni;
            }
            (2, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                msg.payload = AdminPayload::GetChannelResponse(decode_channel(&payload[ni..end])?);
                i = end;
            }
            (3, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                if v != 0 {
                    msg.payload = AdminPayload::GetOwnerRequest;
                }
                i = ni;
            }
            (4, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                if let Some(identity) = crate::nodeinfo::decode_user(&payload[ni..end]) {
                    msg.payload = AdminPayload::GetOwnerResponse(identity);
                }
                i = end;
            }
            (5, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                msg.payload = AdminPayload::GetConfigRequest(v);
                i = ni;
            }
            (6, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                msg.payload = AdminPayload::GetConfigResponse(decode_config(&payload[ni..end])?);
                i = end;
            }
            (7, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                msg.payload = AdminPayload::GetModuleConfigRequest(v);
                i = ni;
            }
            (8, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                // Empty ModuleConfig body is fine.
                msg.payload = AdminPayload::GetModuleConfigResponse;
                i = end;
            }
            (12, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                if v != 0 {
                    msg.payload = AdminPayload::GetDeviceMetadataRequest;
                }
                i = ni;
            }
            (13, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                msg.payload =
                    AdminPayload::GetDeviceMetadataResponse(decode_device_metadata(&payload[ni..end])?);
                i = end;
            }
            (34, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                msg.payload = AdminPayload::SetConfig(decode_config(&payload[ni..end])?);
                i = end;
            }
            (64, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                if v != 0 {
                    msg.payload = AdminPayload::BeginEditSettings;
                }
                i = ni;
            }
            (65, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                if v != 0 {
                    msg.payload = AdminPayload::CommitEditSettings;
                }
                i = ni;
            }
            (97, 0) => {
                let (v, ni) = read_svarint(payload, i)?;
                msg.payload = AdminPayload::RebootSeconds(v);
                i = ni;
            }
            (101, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                let slice = &payload[ni..end];
                if slice.len() == SESSION_PASSKEY_LEN {
                    msg.session_passkey.copy_from_slice(slice);
                    msg.has_session_passkey = true;
                }
                i = end;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    Some(msg)
}

fn encode_owner_user(node_num: u32, identity: &NodeInfoIdentity) -> heapless::Vec<u8, 240> {
    // Reuse NODEINFO User encoding; node_num 0 still emits id if needed by clients.
    crate::nodeinfo::encode_user(node_num, identity)
}

fn encode_device_metadata(meta: &DeviceMetadata) -> heapless::Vec<u8, 64> {
    let mut out = heapless::Vec::new();
    let ver = &meta.firmware_version[..meta.firmware_version_len as usize];
    if !ver.is_empty() {
        push_bytes_field(&mut out, 1, ver);
    }
    if meta.hw_model != 0 {
        push_varint_field(&mut out, 3, meta.hw_model);
    }
    out
}

fn decode_device_metadata(payload: &[u8]) -> Option<DeviceMetadata> {
    let mut meta = DeviceMetadata::default();
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni + len as usize;
                if end > payload.len() {
                    return None;
                }
                let slice = &payload[ni..end];
                let copy_len = slice.len().min(32);
                meta.firmware_version[..copy_len].copy_from_slice(&slice[..copy_len]);
                meta.firmware_version_len = copy_len as u8;
                i = end;
            }
            (3, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                meta.hw_model = v;
                i = ni;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    Some(meta)
}

fn read_varint(data: &[u8], mut idx: usize) -> Option<(u32, usize)> {
    let mut result = 0u32;
    let mut shift = 0u32;
    for _ in 0..5 {
        if idx >= data.len() {
            return None;
        }
        let byte = data[idx];
        idx += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Some((result, idx));
        }
        shift += 7;
    }
    None
}

fn read_svarint(data: &[u8], idx: usize) -> Option<(i32, usize)> {
    let (v, ni) = read_varint(data, idx)?;
    let decoded = ((v >> 1) as i32) ^ (-((v & 1) as i32));
    Some((decoded, ni))
}

fn skip_field(data: &[u8], idx: usize, wire: u8) -> Option<usize> {
    match wire {
        0 => {
            let (_, i) = read_varint(data, idx)?;
            Some(i)
        }
        2 => {
            let (len, mut i) = read_varint(data, idx)?;
            i += len as usize;
            if i > data.len() {
                None
            } else {
                Some(i)
            }
        }
        1 | 5 => Some(idx + if wire == 1 { 8 } else { 4 }),
        _ => None,
    }
}

fn push_tag<const N: usize>(out: &mut heapless::Vec<u8, N>, field: u32, wire: u8) {
    push_varint(out, (field << 3) | u32::from(wire));
}

fn push_varint_field<const N: usize>(out: &mut heapless::Vec<u8, N>, field: u32, value: u32) {
    push_tag(out, field, 0);
    push_varint(out, value);
}

fn push_svarint_field<const N: usize>(out: &mut heapless::Vec<u8, N>, field: u32, value: i32) {
    let zigzag = ((value << 1) ^ (value >> 31)) as u32;
    push_varint_field(out, field, zigzag);
}

fn push_bytes_field<const N: usize>(out: &mut heapless::Vec<u8, N>, field: u32, data: &[u8]) {
    push_tag(out, field, 2);
    push_varint(out, data.len() as u32);
    let _ = out.extend_from_slice(data);
}

fn push_varint<const N: usize>(out: &mut heapless::Vec<u8, N>, mut v: u32) {
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        let _ = out.push(byte);
        if v == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh_radio::MODEM_SHORT_FAST;

    #[test]
    fn admin_get_set_lora_round_trip_golden() {
        let mut msg = AdminMessage::default();
        msg.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_LORA);
        msg.has_session_passkey = true;
        msg.session_passkey = [1, 2, 3, 4, 5, 6, 7, 8];
        let encoded = encode_admin_message(&msg);
        let decoded = decode_admin_message(&encoded).unwrap();
        assert_eq!(decoded.payload, AdminPayload::GetConfigRequest(CONFIG_TYPE_LORA));
        assert!(decoded.has_session_passkey);
        assert_eq!(decoded.session_passkey, msg.session_passkey);

        let lora = WireLoRaConfig {
            use_preset: true,
            modem_preset: MODEM_SHORT_FAST as u32,
            region: REGION_EU_868,
            hop_limit: 3,
            tx_power: 27,
        };
        let mut set = AdminMessage::default();
        set.payload = AdminPayload::SetConfig(ConfigPayload::Lora(lora));
        set.has_session_passkey = true;
        set.session_passkey = [9, 8, 7, 6, 5, 4, 3, 2];
        let set_bytes = encode_admin_message(&set);
        let set_decoded = decode_admin_message(&set_bytes).unwrap();
        match set_decoded.payload {
            AdminPayload::SetConfig(ConfigPayload::Lora(got)) => {
                assert_eq!(got, lora);
            }
            other => panic!("unexpected payload: {:?}", other),
        }
        assert_eq!(set_decoded.session_passkey, set.session_passkey);
    }

    #[test]
    fn admin_security_admin_keys_round_trip() {
        let mut sec = WireSecurityConfig::default();
        sec.has_public_key = true;
        sec.public_key = [0x11; 32];
        sec.has_private_key = true;
        sec.private_key = [0x22; 32];
        sec.admin_keys[0] = [0xAA; 32];
        sec.admin_keys[1] = [0xBB; 32];
        sec.admin_key_count = 2;
        sec.is_managed = true;
        sec.admin_channel_enabled = false;

        let config = ConfigPayload::Security(sec);
        let bytes = encode_config(&config);
        let decoded = decode_config(&bytes).unwrap();
        match decoded {
            ConfigPayload::Security(got) => {
                assert!(got.has_public_key);
                assert_eq!(got.public_key, sec.public_key);
                assert!(got.has_private_key);
                assert_eq!(got.private_key, sec.private_key);
                assert_eq!(got.admin_key_count, 2);
                assert_eq!(got.admin_keys[0], sec.admin_keys[0]);
                assert_eq!(got.admin_keys[1], sec.admin_keys[1]);
                assert!(got.is_managed);
                assert!(!got.admin_channel_enabled);
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn admin_sessionkey_and_edit_fields() {
        let mut msg = AdminMessage::default();
        msg.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_SESSIONKEY);
        let bytes = encode_admin_message(&msg);
        assert_eq!(
            decode_admin_message(&bytes).unwrap().payload,
            AdminPayload::GetConfigRequest(CONFIG_TYPE_SESSIONKEY)
        );

        let mut begin = AdminMessage::default();
        begin.payload = AdminPayload::BeginEditSettings;
        begin.has_session_passkey = true;
        begin.session_passkey = [0xFE; 8];
        let begin_bytes = encode_admin_message(&begin);
        let begin_dec = decode_admin_message(&begin_bytes).unwrap();
        assert_eq!(begin_dec.payload, AdminPayload::BeginEditSettings);
        assert_eq!(begin_dec.session_passkey, [0xFE; 8]);

        let mut commit = AdminMessage::default();
        commit.payload = AdminPayload::CommitEditSettings;
        let commit_bytes = encode_admin_message(&commit);
        assert_eq!(
            decode_admin_message(&commit_bytes).unwrap().payload,
            AdminPayload::CommitEditSettings
        );

        let mut reboot = AdminMessage::default();
        reboot.payload = AdminPayload::RebootSeconds(5);
        let reboot_bytes = encode_admin_message(&reboot);
        assert_eq!(
            decode_admin_message(&reboot_bytes).unwrap().payload,
            AdminPayload::RebootSeconds(5)
        );
    }

    #[test]
    fn admin_skips_unknown_fields() {
        // Field 99 (unknown) varint + get_config_request LORA.
        let mut bytes = heapless::Vec::<u8, 32>::new();
        push_varint_field(&mut bytes, 99, 42);
        push_varint_field(&mut bytes, 5, CONFIG_TYPE_LORA);
        let decoded = decode_admin_message(&bytes).unwrap();
        assert_eq!(decoded.payload, AdminPayload::GetConfigRequest(CONFIG_TYPE_LORA));
    }

    #[test]
    fn lora_field_numbers_golden() {
        let lora = WireLoRaConfig {
            use_preset: true,
            modem_preset: 5,
            region: 3,
            hop_limit: 0,
            tx_power: 0,
        };
        let bytes = encode_lora_config(&lora);
        // use_preset=true → field 1 varint 1: 08 01
        // modem_preset=5 → field 2 varint 5: 10 05
        // region=3 → field 7 varint 3: 38 03
        // hop_limit/tx_power omitted when zero
        assert_eq!(bytes.as_slice(), &[0x08, 0x01, 0x10, 0x05, 0x38, 0x03]);
    }

    #[test]
    fn channel_primary_and_disabled_round_trip() {
        let mut settings = WireChannelSettings::default();
        settings.psk[0] = 0x01;
        settings.psk_len = 1;
        let primary = WireChannel {
            index: 0,
            role: CHANNEL_ROLE_PRIMARY,
            settings,
            has_settings: true,
        };
        let encoded = encode_channel(&primary);
        let decoded = decode_channel(&encoded).unwrap();
        assert_eq!(decoded.role, CHANNEL_ROLE_PRIMARY);
        assert_eq!(decoded.settings.psk_len, 1);
        assert_eq!(decoded.settings.psk[0], 0x01);

        let disabled = WireChannel {
            index: 1,
            role: CHANNEL_ROLE_DISABLED,
            settings: WireChannelSettings::default(),
            has_settings: false,
        };
        let encoded = encode_channel(&disabled);
        let decoded = decode_channel(&encoded).unwrap();
        assert_eq!(decoded.index, 1);
        assert_eq!(decoded.role, CHANNEL_ROLE_DISABLED);
    }

    #[test]
    fn sessionkey_empty_config_encodes_field_9() {
        let bytes = encode_config(&ConfigPayload::Sessionkey);
        assert_eq!(bytes.as_slice(), &[0x4a, 0x00]); // field 9, length 0
    }
}
