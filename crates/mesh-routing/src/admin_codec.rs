use crate::nodeinfo::NodeInfoIdentity;
use crate::protobuf::{read_varint, skip_field};

pub const ADMIN_APP: u32 = 6;

pub const CONFIG_TYPE_DEVICE: u32 = 0;
pub const CONFIG_TYPE_POSITION: u32 = 1;
pub const CONFIG_TYPE_LORA: u32 = 5;
pub const CONFIG_TYPE_SECURITY: u32 = 7;
pub const CONFIG_TYPE_SESSIONKEY: u32 = 8;

pub const MODULE_CONFIG_TYPE_TELEMETRY: u32 = 5;

pub const REGION_EU_868: u32 = 3;

pub const CHANNEL_ROLE_DISABLED: u32 = 0;
pub const CHANNEL_ROLE_PRIMARY: u32 = 1;
pub const CHANNEL_ROLE_SECONDARY: u32 = 2;

pub const SESSION_PASSKEY_LEN: usize = 8;

pub const MAX_ADMIN_KEYS: usize = 3;

pub const CHANNEL_NAME_MAX: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireLoRaConfig {
    pub use_preset: bool,
    pub modem_preset: u32,
    pub region: u32,
    pub hop_limit: u32,
    pub tx_power: i32,
    pub config_ok_to_mqtt: bool,
}

impl Default for WireLoRaConfig {
    fn default() -> Self {
        Self {
            use_preset: true,
            modem_preset: mesh_radio::MODEM_DEFAULT_PRESET as u32,
            region: REGION_EU_868,
            hop_limit: 3,
            tx_power: 27,
            config_ok_to_mqtt: true,
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
            role: crate::nodeinfo::DEVICE_ROLE_CLIENT,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct WirePositionConfig {
    pub position_broadcast_secs: u32,
    pub fixed_position: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct WireFixedPosition {
    pub latitude_i: i32,
    pub longitude_i: i32,
    pub has_latitude_i: bool,
    pub has_longitude_i: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigPayload {
    Empty,
    Device(WireDeviceConfig),
    Position(WirePositionConfig),
    Lora(WireLoRaConfig),
    Security(WireSecurityConfig),
    Sessionkey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct WireTelemetryConfig {
    pub device_update_interval: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleConfigPayload {
    Empty,
    Telemetry(WireTelemetryConfig),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DeviceMetadata {
    pub firmware_version: [u8; 32],
    pub firmware_version_len: u8,
    pub hw_model: u32,
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
    GetModuleConfigResponse(ModuleConfigPayload),
    GetDeviceMetadataRequest,
    GetDeviceMetadataResponse(DeviceMetadata),
    SetConfig(ConfigPayload),
    SetModuleConfig(ModuleConfigPayload),
    SetFixedPosition(WireFixedPosition),
    RemoveFixedPosition,
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

pub fn encode_config(config: &ConfigPayload) -> heapless::Vec<u8, 240> {
    let mut out = heapless::Vec::new();
    match config {
        ConfigPayload::Empty => {}
        ConfigPayload::Device(dev) => {
            let inner = encode_device_config(dev);
            push_bytes_field(&mut out, 1, &inner);
        }
        ConfigPayload::Position(pos) => {
            let inner = encode_position_config(pos);
            push_bytes_field(&mut out, 2, &inner);
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
            push_bytes_field(&mut out, 9, &[]);
        }
    }
    out
}

pub fn encode_position_config(pos: &WirePositionConfig) -> heapless::Vec<u8, 16> {
    let mut out = heapless::Vec::new();
    if pos.position_broadcast_secs != 0 {
        push_varint_field(&mut out, 1, pos.position_broadcast_secs);
    }
    if pos.fixed_position {
        push_varint_field(&mut out, 3, 1);
    }
    out
}

pub fn decode_position_config(payload: &[u8]) -> Option<WirePositionConfig> {
    let mut pos = WirePositionConfig::default();
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        if field == 0 {
            return None;
        }
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                pos.position_broadcast_secs = v;
                i = ni;
            }
            (3, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                pos.fixed_position = v != 0;
                i = ni;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    Some(pos)
}

fn decode_fixed_position_admin(payload: &[u8]) -> Option<WireFixedPosition> {
    let mut pos = WireFixedPosition::default();
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        if field == 0 {
            return None;
        }
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 5) if i + 4 <= payload.len() => {
                pos.latitude_i = i32::from_le_bytes(payload[i..i + 4].try_into().ok()?);
                pos.has_latitude_i = true;
                i += 4;
            }
            (2, 5) if i + 4 <= payload.len() => {
                pos.longitude_i = i32::from_le_bytes(payload[i..i + 4].try_into().ok()?);
                pos.has_longitude_i = true;
                i += 4;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    Some(pos)
}

fn encode_fixed_position_admin(pos: &WireFixedPosition) -> heapless::Vec<u8, 16> {
    let mut out = heapless::Vec::new();
    if pos.has_latitude_i {
        push_tag(&mut out, 1, 5);
        let _ = out.extend_from_slice(&pos.latitude_i.to_le_bytes());
    }
    if pos.has_longitude_i {
        push_tag(&mut out, 2, 5);
        let _ = out.extend_from_slice(&pos.longitude_i.to_le_bytes());
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
    if lora.config_ok_to_mqtt {
        push_varint_field(&mut out, 105, 1);
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

pub fn encode_telemetry_config(tel: &WireTelemetryConfig) -> heapless::Vec<u8, 16> {
    let mut out = heapless::Vec::new();
    if tel.device_update_interval != 0 {
        push_varint_field(&mut out, 1, tel.device_update_interval);
    }
    out
}

pub fn encode_module_config(config: &ModuleConfigPayload) -> heapless::Vec<u8, 64> {
    let mut out = heapless::Vec::new();
    match config {
        ModuleConfigPayload::Empty => {}
        ModuleConfigPayload::Telemetry(tel) => {
            let inner = encode_telemetry_config(tel);
            push_bytes_field(&mut out, 6, &inner);
        }
    }
    out
}

pub fn decode_telemetry_config(payload: &[u8]) -> Option<WireTelemetryConfig> {
    let mut tel = WireTelemetryConfig::default();
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        if field == 0 {
            return None;
        }
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                tel.device_update_interval = v;
                i = ni;
            }
            _ => {
                i = skip_field(payload, i, wire)?;
            }
        }
        idx = i;
    }
    Some(tel)
}

pub fn decode_module_config(payload: &[u8]) -> Option<ModuleConfigPayload> {
    let mut result = ModuleConfigPayload::Empty;
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        if field == 0 {
            return None;
        }
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (6, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
                if end > payload.len() {
                    return None;
                }
                result =
                    ModuleConfigPayload::Telemetry(decode_telemetry_config(&payload[ni..end])?);
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

pub fn encode_channel(ch: &WireChannel) -> heapless::Vec<u8, 96> {
    let mut out = heapless::Vec::new();
    if ch.index != 0 {
        push_int32_field(&mut out, 1, ch.index);
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
        push_tag(&mut out, 4, 5);
        let _ = out.extend_from_slice(&settings.id.to_le_bytes());
    }
    out
}

pub fn decode_config(payload: &[u8]) -> Option<ConfigPayload> {
    let mut result = ConfigPayload::Empty;
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        if field == 0 {
            return None;
        }
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
                if end > payload.len() {
                    return None;
                }
                result = ConfigPayload::Device(decode_device_config(&payload[ni..end])?);
                i = end;
            }
            (2, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
                if end > payload.len() {
                    return None;
                }
                result = ConfigPayload::Position(decode_position_config(&payload[ni..end])?);
                i = end;
            }
            (6, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
                if end > payload.len() {
                    return None;
                }
                result = ConfigPayload::Lora(decode_lora_config(&payload[ni..end])?);
                i = end;
            }
            (8, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
                if end > payload.len() {
                    return None;
                }
                result = ConfigPayload::Security(decode_security_config(&payload[ni..end])?);
                i = end;
            }
            (9, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
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
        if field == 0 {
            return None;
        }
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
    let mut lora = WireLoRaConfig {
        use_preset: false,
        modem_preset: 0,
        region: 0,
        hop_limit: 0,
        tx_power: 0,
        config_ok_to_mqtt: false,
    };
    let mut idx = 0usize;
    while idx < payload.len() {
        let (tag, mut i) = read_varint(payload, idx)?;
        let field = tag >> 3;
        if field == 0 {
            return None;
        }
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
            (105, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                lora.config_ok_to_mqtt = v != 0;
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
        if field == 0 {
            return None;
        }
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
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
                let end = ni.checked_add(len as usize)?;
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
                let end = ni.checked_add(len as usize)?;
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
        if field == 0 {
            return None;
        }
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 0) => {
                let (v, ni) = read_int32(payload, i)?;
                ch.index = v;
                i = ni;
            }
            (2, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
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
        if field == 0 {
            return None;
        }
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (2, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
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
                let end = ni.checked_add(len as usize)?;
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
        AdminPayload::GetModuleConfigResponse(config) => {
            let inner = encode_module_config(config);
            push_bytes_field(&mut out, 8, &inner);
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
        AdminPayload::SetModuleConfig(config) => {
            let inner = encode_module_config(config);
            push_bytes_field(&mut out, 35, &inner);
        }
        AdminPayload::SetFixedPosition(pos) => {
            let inner = encode_fixed_position_admin(pos);
            push_bytes_field(&mut out, 41, &inner);
        }
        AdminPayload::RemoveFixedPosition => {
            push_varint_field(&mut out, 42, 1);
        }
        AdminPayload::BeginEditSettings => {
            push_varint_field(&mut out, 64, 1);
        }
        AdminPayload::CommitEditSettings => {
            push_varint_field(&mut out, 65, 1);
        }
        AdminPayload::RebootSeconds(secs) => {
            push_int32_field(&mut out, 97, *secs);
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
        if field == 0 {
            return None;
        }
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                msg.payload = AdminPayload::GetChannelRequest(v);
                i = ni;
            }
            (2, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
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
                let end = ni.checked_add(len as usize)?;
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
                let end = ni.checked_add(len as usize)?;
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
                let end = ni.checked_add(len as usize)?;
                if end > payload.len() {
                    return None;
                }
                msg.payload =
                    AdminPayload::GetModuleConfigResponse(decode_module_config(&payload[ni..end])?);
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
                let end = ni.checked_add(len as usize)?;
                if end > payload.len() {
                    return None;
                }
                msg.payload = AdminPayload::GetDeviceMetadataResponse(decode_device_metadata(
                    &payload[ni..end],
                )?);
                i = end;
            }
            (34, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
                if end > payload.len() {
                    return None;
                }
                msg.payload = AdminPayload::SetConfig(decode_config(&payload[ni..end])?);
                i = end;
            }
            (35, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
                if end > payload.len() {
                    return None;
                }
                msg.payload =
                    AdminPayload::SetModuleConfig(decode_module_config(&payload[ni..end])?);
                i = end;
            }
            (41, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
                if end > payload.len() {
                    return None;
                }
                msg.payload =
                    AdminPayload::SetFixedPosition(decode_fixed_position_admin(&payload[ni..end])?);
                i = end;
            }
            (42, 0) => {
                let (v, ni) = read_varint(payload, i)?;
                if v != 0 {
                    msg.payload = AdminPayload::RemoveFixedPosition;
                }
                i = ni;
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
                let (v, ni) = read_int32(payload, i)?;
                msg.payload = AdminPayload::RebootSeconds(v);
                i = ni;
            }
            (101, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
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
    crate::nodeinfo::encode_user(node_num, identity)
}

fn encode_device_metadata(meta: &DeviceMetadata) -> heapless::Vec<u8, 64> {
    let mut out = heapless::Vec::new();
    let ver = &meta.firmware_version
        [..(meta.firmware_version_len as usize).min(meta.firmware_version.len())];
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
        if field == 0 {
            return None;
        }
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, 2) => {
                let (len, ni) = read_varint(payload, i)?;
                let end = ni.checked_add(len as usize)?;
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

fn read_int32(data: &[u8], idx: usize) -> Option<(i32, usize)> {
    let (v, end) = crate::protobuf::read_varint64(data, idx)?;
    Some((v as i32, end))
}

fn push_int32_field<const N: usize>(out: &mut heapless::Vec<u8, N>, field: u32, value: i32) {
    push_tag(out, field, 0);
    let mut v = value as i64 as u64;
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        let _ = out.push(byte | if v != 0 { 0x80 } else { 0 });
        if v == 0 {
            break;
        }
    }
}

fn read_svarint(data: &[u8], idx: usize) -> Option<(i32, usize)> {
    let (v, ni) = read_varint(data, idx)?;
    let decoded = ((v >> 1) as i32) ^ (-((v & 1) as i32));
    Some((decoded, ni))
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
        let msg = AdminMessage {
            payload: AdminPayload::GetConfigRequest(CONFIG_TYPE_LORA),
            has_session_passkey: true,
            session_passkey: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let encoded = encode_admin_message(&msg);
        let decoded = decode_admin_message(&encoded).unwrap();
        assert_eq!(
            decoded.payload,
            AdminPayload::GetConfigRequest(CONFIG_TYPE_LORA)
        );
        assert!(decoded.has_session_passkey);
        assert_eq!(decoded.session_passkey, msg.session_passkey);

        let lora = WireLoRaConfig {
            use_preset: true,
            modem_preset: MODEM_SHORT_FAST as u32,
            region: REGION_EU_868,
            hop_limit: 3,
            tx_power: 27,
            config_ok_to_mqtt: false,
        };
        let set = AdminMessage {
            payload: AdminPayload::SetConfig(ConfigPayload::Lora(lora)),
            has_session_passkey: true,
            session_passkey: [9, 8, 7, 6, 5, 4, 3, 2],
        };
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
        let mut sec = WireSecurityConfig {
            has_public_key: true,
            public_key: [0x11; 32],
            has_private_key: true,
            private_key: [0x22; 32],
            ..Default::default()
        };
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
        let msg = AdminMessage {
            payload: AdminPayload::GetConfigRequest(CONFIG_TYPE_SESSIONKEY),
            ..Default::default()
        };
        let bytes = encode_admin_message(&msg);
        assert_eq!(
            decode_admin_message(&bytes).unwrap().payload,
            AdminPayload::GetConfigRequest(CONFIG_TYPE_SESSIONKEY)
        );

        let begin = AdminMessage {
            payload: AdminPayload::BeginEditSettings,
            has_session_passkey: true,
            session_passkey: [0xFE; 8],
        };
        let begin_bytes = encode_admin_message(&begin);
        let begin_dec = decode_admin_message(&begin_bytes).unwrap();
        assert_eq!(begin_dec.payload, AdminPayload::BeginEditSettings);
        assert_eq!(begin_dec.session_passkey, [0xFE; 8]);

        let commit = AdminMessage {
            payload: AdminPayload::CommitEditSettings,
            ..Default::default()
        };
        let commit_bytes = encode_admin_message(&commit);
        assert_eq!(
            decode_admin_message(&commit_bytes).unwrap().payload,
            AdminPayload::CommitEditSettings
        );

        let reboot = AdminMessage {
            payload: AdminPayload::RebootSeconds(5),
            ..Default::default()
        };
        let reboot_bytes = encode_admin_message(&reboot);
        assert_eq!(
            decode_admin_message(&reboot_bytes).unwrap().payload,
            AdminPayload::RebootSeconds(5)
        );
    }

    #[test]
    fn admin_skips_unknown_fields() {
        let mut bytes = heapless::Vec::<u8, 32>::new();
        push_varint_field(&mut bytes, 99, 42);
        push_varint_field(&mut bytes, 5, CONFIG_TYPE_LORA);
        let decoded = decode_admin_message(&bytes).unwrap();
        assert_eq!(
            decoded.payload,
            AdminPayload::GetConfigRequest(CONFIG_TYPE_LORA)
        );
    }

    #[test]
    fn lora_field_numbers_golden() {
        let lora = WireLoRaConfig {
            use_preset: true,
            modem_preset: 5,
            region: 3,
            hop_limit: 0,
            tx_power: 0,
            config_ok_to_mqtt: false,
        };
        let bytes = encode_lora_config(&lora);
        assert_eq!(bytes.as_slice(), &[0x08, 0x01, 0x10, 0x05, 0x38, 0x03]);
    }

    #[test]
    fn lora_long_fast_encodes_zero_preset() {
        use mesh_radio::MODEM_LONG_FAST;
        let lora = WireLoRaConfig {
            use_preset: true,
            modem_preset: MODEM_LONG_FAST as u32,
            region: REGION_EU_868,
            hop_limit: 3,
            tx_power: 27,
            config_ok_to_mqtt: false,
        };
        let bytes = encode_lora_config(&lora);
        assert_eq!(
            bytes.as_slice(),
            &[0x08, 0x01, 0x10, 0x00, 0x38, 0x03, 0x40, 0x03, 0x58, 0x36]
        );
        let decoded = decode_lora_config(&bytes).unwrap();
        assert_eq!(decoded.modem_preset, MODEM_LONG_FAST as u32);
        assert!(decoded.use_preset);
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
        assert_eq!(bytes.as_slice(), &[0x4a, 0x00]);
    }

    #[test]
    fn position_config_keeps_cadence_and_fixed_flag_only() {
        let raw = [0x08, 0xA0, 0x38, 0x10, 0x01, 0x18, 0x01, 0x68, 0x01];
        let pos = decode_position_config(&raw).unwrap();
        assert_eq!(pos.position_broadcast_secs, 7200);
        assert!(pos.fixed_position);
        let encoded = encode_position_config(&pos);
        let again = decode_position_config(&encoded).unwrap();
        assert_eq!(again, pos);
        assert!(!encoded.as_slice().windows(2).any(|w| w == [0x10, 0x01]));
    }

    #[test]
    fn set_fixed_position_round_trips_lat_lon() {
        let msg = AdminMessage {
            payload: AdminPayload::SetFixedPosition(WireFixedPosition {
                latitude_i: 52_520_000,
                longitude_i: 13_405_000,
                has_latitude_i: true,
                has_longitude_i: true,
            }),
            ..Default::default()
        };
        let bytes = encode_admin_message(&msg);
        match decode_admin_message(&bytes).unwrap().payload {
            AdminPayload::SetFixedPosition(pos) => {
                assert_eq!(pos.latitude_i, 52_520_000);
                assert_eq!(pos.longitude_i, 13_405_000);
                assert!(pos.has_latitude_i && pos.has_longitude_i);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn int32_fields_match_protobuf_instead_of_zigzag() {
        let channel = WireChannel {
            index: 1,
            ..WireChannel::default()
        };
        assert_eq!(encode_channel(&channel).as_slice(), &[8, 1]);
        let msg = AdminMessage {
            payload: AdminPayload::RebootSeconds(-1),
            ..AdminMessage::default()
        };
        let wire = encode_admin_message(&msg);
        assert_eq!(wire.len(), 12);
        assert_eq!(decode_admin_message(&wire), Some(msg));
        let positive = AdminMessage {
            payload: AdminPayload::RebootSeconds(5),
            ..AdminMessage::default()
        };
        assert_eq!(encode_admin_message(&positive).as_slice(), &[0x88, 0x06, 5]);
    }
}
