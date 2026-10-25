use mesh_crypto::sha256_in_place;
use mesh_store::{
    NodeConfig, ADMIN_KEY_SLOTS, BUILTIN_ADMIN_PUBLIC_KEYS, EMPTY_ADMIN_KEY, OWNER_LONG_NAME_MAX,
    OWNER_SHORT_NAME_MAX,
};

use crate::admin_codec::{
    decode_admin_message, encode_admin_message, AdminMessage, AdminPayload, ConfigPayload,
    DeviceMetadata, ModuleConfigPayload, WireChannel, WireChannelSettings, WireDeviceConfig,
    WireLoRaConfig, WirePositionConfig, WireSecurityConfig, WireTelemetryConfig,
    CHANNEL_ROLE_DISABLED, CHANNEL_ROLE_PRIMARY, CONFIG_TYPE_DEVICE, CONFIG_TYPE_LORA,
    CONFIG_TYPE_POSITION, CONFIG_TYPE_SECURITY, CONFIG_TYPE_SESSIONKEY, MAX_ADMIN_KEYS,
    MODULE_CONFIG_TYPE_TELEMETRY, REGION_EU_868, SESSION_PASSKEY_LEN,
};
use crate::nodeinfo::{
    is_known_device_role, sanitize_device_role, NodeInfoIdentity, DEVICE_ROLE_CLIENT,
    HW_MODEL_NRF52_PROMICRO_DIY,
};
use crate::position::coerce_position_broadcast_secs;
use crate::telemetry::min_device_update_interval_secs;
use mesh_crypto::DEFAULT_PSK;
use mesh_radio::{eu868_config_for_preset, MAX_TX_POWER_DBM};

pub const ADMIN_SESSION_TTL_MS: u32 = 300_000;

pub const ADMIN_PRESET_REBOOT_SECS: i32 = 2;

pub const ROUTING_ERROR_BAD_REQUEST: u32 = 32;
pub const ROUTING_ERROR_ADMIN_BAD_SESSION_KEY: u32 = 36;
pub const ROUTING_ERROR_ADMIN_PUBLIC_KEY_UNAUTHORIZED: u32 = 37;
pub const ROUTING_ERROR_PKI_FAILED: u32 = 34;
pub const ROUTING_ERROR_PKI_UNKNOWN_PUBKEY: u32 = 35;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdminState {
    pub session_passkey: [u8; SESSION_PASSKEY_LEN],
    pub session_valid_until_ms: u32,
    pub has_session: bool,
    pub passkey_counter: u32,
    pub editing: bool,
    pub buffered_lora: Option<WireLoRaConfig>,
    pub buffered_admin_keys: Option<[[u8; 32]; ADMIN_KEY_SLOTS]>,
    pub buffered_device_update_interval_secs: Option<u32>,
    pub buffered_device_role: Option<u32>,
    pub buffered_position: Option<WirePositionConfig>,
    pub buffered_owner: Option<OwnerNames>,
    pub admin_public_keys: [[u8; 32]; ADMIN_KEY_SLOTS],
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub modem_preset: u8,
    pub use_preset: bool,
    pub hop_limit: u8,
    pub tx_power_dbm: u8,
    pub ok_to_mqtt: bool,
    pub device_update_interval_secs: u32,
    pub device_role: u32,
    pub position_broadcast_secs: u32,
    pub fixed_position: bool,
    pub latitude_i: i32,
    pub longitude_i: i32,
    pub has_fixed_coords: bool,
    pub short_name: [u8; OWNER_SHORT_NAME_MAX],
    pub short_name_len: u8,
    pub long_name: [u8; OWNER_LONG_NAME_MAX],
    pub long_name_len: u8,
    pub pending_reboot_seconds: Option<i32>,
    pub config_dirty: bool,
    #[cfg(any(test, feature = "std"))]
    builtin_override: Option<[[u8; 32]; 2]>,
}

impl Default for AdminState {
    fn default() -> Self {
        Self::new()
    }
}

impl AdminState {
    pub const fn new() -> Self {
        Self {
            session_passkey: [0; SESSION_PASSKEY_LEN],
            session_valid_until_ms: 0,
            has_session: false,
            passkey_counter: 0,
            editing: false,
            buffered_lora: None,
            buffered_admin_keys: None,
            buffered_device_update_interval_secs: None,
            buffered_device_role: None,
            buffered_position: None,
            buffered_owner: None,
            admin_public_keys: [EMPTY_ADMIN_KEY; ADMIN_KEY_SLOTS],
            private_key: [0; 32],
            public_key: [0; 32],
            modem_preset: mesh_radio::MODEM_DEFAULT_PRESET,
            use_preset: true,
            hop_limit: mesh_radio::DEFAULT_HOP_LIMIT,
            tx_power_dbm: MAX_TX_POWER_DBM,
            ok_to_mqtt: true,
            device_update_interval_secs: 0,
            device_role: DEVICE_ROLE_CLIENT,
            position_broadcast_secs: 0,
            fixed_position: false,
            latitude_i: 0,
            longitude_i: 0,
            has_fixed_coords: false,
            short_name: [0; OWNER_SHORT_NAME_MAX],
            short_name_len: 0,
            long_name: [0; OWNER_LONG_NAME_MAX],
            long_name_len: 0,
            pending_reboot_seconds: None,
            config_dirty: false,
            #[cfg(any(test, feature = "std"))]
            builtin_override: None,
        }
    }
}

impl AdminState {
    pub fn from_node_config(cfg: &NodeConfig) -> Self {
        let mut s = Self::default();
        s.import_node_config(cfg);
        s
    }

    pub fn import_node_config(&mut self, cfg: &NodeConfig) {
        self.admin_public_keys = cfg.admin_public_keys;
        self.private_key = cfg.private_key;
        self.public_key = cfg.public_key;
        self.modem_preset = mesh_radio::normalize_modem_preset(cfg.lora.modem_preset);
        self.use_preset = cfg.lora.use_preset;
        self.hop_limit = cfg.lora.effective_hop_limit();
        self.tx_power_dbm = cfg.lora.tx_power_dbm.min(MAX_TX_POWER_DBM);
        self.ok_to_mqtt = cfg.lora.ok_to_mqtt;
        self.device_update_interval_secs = cfg.device_update_interval_secs;
        self.device_role = sanitize_device_role(u32::from(cfg.device_role));
        self.position_broadcast_secs = cfg.position_broadcast_secs;
        self.fixed_position = cfg.fixed_position;
        self.latitude_i = cfg.latitude_i;
        self.longitude_i = cfg.longitude_i;
        self.has_fixed_coords = cfg.has_fixed_coords;
        self.short_name = cfg.short_name;
        self.short_name_len = cfg.short_name_len.min(OWNER_SHORT_NAME_MAX as u8);
        self.long_name = cfg.long_name;
        self.long_name_len = cfg.long_name_len.min(OWNER_LONG_NAME_MAX as u8);
    }

    pub fn export_to_node_config(&self, cfg: &mut NodeConfig) {
        cfg.admin_public_keys = self.admin_public_keys;
        cfg.lora.apply_modem_preset(self.modem_preset);
        cfg.lora.use_preset = self.use_preset;
        cfg.lora.hop_limit = self.hop_limit;
        cfg.lora.tx_power_dbm = self.tx_power_dbm;
        cfg.lora.ok_to_mqtt = self.ok_to_mqtt;
        cfg.private_key = self.private_key;
        cfg.public_key = self.public_key;
        cfg.device_update_interval_secs = self.device_update_interval_secs;
        cfg.device_role = sanitize_device_role(self.device_role) as u8;
        cfg.position_broadcast_secs = self.position_broadcast_secs;
        cfg.fixed_position = self.fixed_position;
        cfg.latitude_i = self.latitude_i;
        cfg.longitude_i = self.longitude_i;
        cfg.has_fixed_coords = self.has_fixed_coords;
        let short_len = (self.short_name_len as usize).min(OWNER_SHORT_NAME_MAX);
        cfg.short_name = [0; OWNER_SHORT_NAME_MAX];
        cfg.short_name[..short_len].copy_from_slice(&self.short_name[..short_len]);
        cfg.short_name_len = short_len as u8;
        let long_len = (self.long_name_len as usize).min(OWNER_LONG_NAME_MAX);
        cfg.long_name = [0; OWNER_LONG_NAME_MAX];
        cfg.long_name[..long_len].copy_from_slice(&self.long_name[..long_len]);
        cfg.long_name_len = long_len as u8;
    }

    /// Copy live owner name lengths/bytes from a NodeInfo advert (capped to flash limits).
    pub fn apply_owner_from_advert(&mut self, advert: &crate::nodeinfo::NodeInfoAdvert) {
        let short_len = (advert.short_name_len as usize)
            .min(OWNER_SHORT_NAME_MAX)
            .min(advert.short_name.len());
        self.short_name = [0; OWNER_SHORT_NAME_MAX];
        self.short_name[..short_len].copy_from_slice(&advert.short_name[..short_len]);
        self.short_name_len = short_len as u8;
        let long_len = (advert.long_name_len as usize)
            .min(OWNER_LONG_NAME_MAX)
            .min(advert.long_name.len());
        self.long_name = [0; OWNER_LONG_NAME_MAX];
        self.long_name[..long_len].copy_from_slice(&advert.long_name[..long_len]);
        self.long_name_len = long_len as u8;
    }

    pub fn broadcasts_fixed_position(&self) -> bool {
        self.fixed_position
            && self.has_fixed_coords
            && !(self.latitude_i == 0 && self.longitude_i == 0)
    }

    pub fn coerce_position_interval(&mut self) -> bool {
        let next = coerce_position_broadcast_secs(self.position_broadcast_secs, self.device_role);
        if next == self.position_broadcast_secs {
            return false;
        }
        self.position_broadcast_secs = next;
        true
    }

    pub fn effective_builtin_admin_keys(&self) -> [[u8; 32]; 2] {
        #[cfg(any(test, feature = "std"))]
        if let Some(keys) = self.builtin_override {
            return keys;
        }
        BUILTIN_ADMIN_PUBLIC_KEYS
    }

    #[cfg(any(test, feature = "std"))]
    pub fn set_builtin_admin_public_keys_for_test(&mut self, keys: [[u8; 32]; 2]) {
        self.builtin_override = Some(keys);
    }

    pub fn is_authorized(&self, remote_pk: &[u8; 32]) -> bool {
        self.effective_builtin_admin_keys()
            .iter()
            .any(|k| k == remote_pk)
            || self
                .admin_public_keys
                .iter()
                .any(|k| k != &EMPTY_ADMIN_KEY && k == remote_pk)
    }

    pub fn candidate_pki_keys(&self) -> heapless::Vec<[u8; 32], 8> {
        let mut out = heapless::Vec::new();
        for k in &self.effective_builtin_admin_keys() {
            let _ = out.push(*k);
        }
        for k in &self.admin_public_keys {
            if k != &EMPTY_ADMIN_KEY {
                let _ = out.push(*k);
            }
        }
        out
    }

    fn issue_session(&mut self, now_ms: u32) -> [u8; SESSION_PASSKEY_LEN] {
        let mut material = [0u8; 64];
        material[..32].copy_from_slice(&self.private_key);
        material[32..36].copy_from_slice(&now_ms.to_le_bytes());
        material[36..40].copy_from_slice(&self.passkey_counter.to_le_bytes());
        self.passkey_counter = self.passkey_counter.wrapping_add(1);
        material[40] = 0xA5;
        material[41] = 0x5A;
        sha256_in_place(&mut material, 42);
        let mut pk = [0u8; SESSION_PASSKEY_LEN];
        pk.copy_from_slice(&material[..SESSION_PASSKEY_LEN]);
        self.session_passkey = pk;
        self.session_valid_until_ms = now_ms.wrapping_add(ADMIN_SESSION_TTL_MS);
        self.has_session = true;
        pk
    }

    fn session_ok(&self, msg: &AdminMessage, now_ms: u32) -> bool {
        if !self.has_session || !msg.has_session_passkey {
            return false;
        }
        if now_ms.wrapping_sub(self.session_valid_until_ms) < 0x8000_0000 {
            return false;
        }
        msg.session_passkey == self.session_passkey
    }
}

/// Owner name bytes ready to apply to AdminState / NodeInfoIdentity (flash limits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerNames {
    pub short_name: [u8; OWNER_SHORT_NAME_MAX],
    pub short_name_len: u8,
    pub long_name: [u8; OWNER_LONG_NAME_MAX],
    pub long_name_len: u8,
    pub is_licensed: bool,
}

impl Default for OwnerNames {
    fn default() -> Self {
        Self {
            short_name: [0; OWNER_SHORT_NAME_MAX],
            short_name_len: 0,
            long_name: [0; OWNER_LONG_NAME_MAX],
            long_name_len: 0,
            is_licensed: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AdminOutcome {
    pub response: Option<AdminMessage>,
    pub routing_error: Option<u32>,
    pub routing_ok: bool,
    pub apply_modem_preset: Option<u8>,
    pub apply_device_role: Option<u32>,
    pub apply_owner: Option<OwnerNames>,
    pub config_dirty: bool,
    pub reboot_seconds: Option<i32>,
    pub broadcast_position: bool,
}

pub fn admin_request_is_idempotent_read(payload: &AdminPayload) -> bool {
    matches!(
        payload,
        AdminPayload::GetChannelRequest(_)
            | AdminPayload::GetOwnerRequest
            | AdminPayload::GetConfigRequest(_)
            | AdminPayload::GetModuleConfigRequest(_)
            | AdminPayload::GetDeviceMetadataRequest
    )
}

pub fn handle_admin(
    state: &mut AdminState,
    remote_pk: &[u8; 32],
    identity: &NodeInfoIdentity,
    node_num: u32,
    channel_psk: &[u8],
    channel_hash: u8,
    _device_role: u32,
    payload: &[u8],
    now_ms: u32,
) -> AdminOutcome {
    let mut outcome = AdminOutcome::default();
    let Some(msg) = decode_admin_message(payload) else {
        return outcome;
    };

    if !state.is_authorized(remote_pk) {
        outcome.routing_error = Some(ROUTING_ERROR_ADMIN_PUBLIC_KEY_UNAUTHORIZED);
        return outcome;
    }

    match msg.payload {
        AdminPayload::GetChannelRequest(index_plus_one) => {
            let passkey = state.issue_session(now_ms);
            let ch = channel_for_request(index_plus_one, channel_psk, channel_hash);
            let resp = AdminMessage {
                payload: AdminPayload::GetChannelResponse(ch),
                has_session_passkey: true,
                session_passkey: passkey,
            };
            outcome.response = Some(resp);
        }
        AdminPayload::GetOwnerRequest => {
            let passkey = state.issue_session(now_ms);
            let resp = AdminMessage {
                payload: AdminPayload::GetOwnerResponse(*identity),
                has_session_passkey: true,
                session_passkey: passkey,
            };
            let _ = node_num;
            outcome.response = Some(resp);
        }
        AdminPayload::GetDeviceMetadataRequest => {
            let passkey = state.issue_session(now_ms);
            let resp = AdminMessage {
                payload: AdminPayload::GetDeviceMetadataResponse(
                    DeviceMetadata::meshrustic_default(HW_MODEL_NRF52_PROMICRO_DIY),
                ),
                has_session_passkey: true,
                session_passkey: passkey,
            };
            outcome.response = Some(resp);
        }
        AdminPayload::GetModuleConfigRequest(config_type) => {
            let passkey = state.issue_session(now_ms);
            let module = if config_type == MODULE_CONFIG_TYPE_TELEMETRY {
                ModuleConfigPayload::Telemetry(WireTelemetryConfig {
                    device_update_interval: state.device_update_interval_secs,
                })
            } else {
                ModuleConfigPayload::Empty
            };
            let resp = AdminMessage {
                payload: AdminPayload::GetModuleConfigResponse(module),
                has_session_passkey: true,
                session_passkey: passkey,
            };
            outcome.response = Some(resp);
        }
        AdminPayload::GetConfigRequest(config_type) => {
            let passkey = state.issue_session(now_ms);
            let config = match config_type {
                CONFIG_TYPE_DEVICE => ConfigPayload::Device(WireDeviceConfig {
                    role: state.device_role,
                }),
                CONFIG_TYPE_POSITION => ConfigPayload::Position(WirePositionConfig {
                    position_broadcast_secs: state.position_broadcast_secs,
                    fixed_position: state.fixed_position,
                }),
                CONFIG_TYPE_LORA => ConfigPayload::Lora(WireLoRaConfig {
                    use_preset: state.use_preset,
                    modem_preset: state.modem_preset as u32,
                    region: REGION_EU_868,
                    hop_limit: state.hop_limit as u32,
                    tx_power: state.tx_power_dbm as i32,
                    config_ok_to_mqtt: state.ok_to_mqtt,
                }),
                CONFIG_TYPE_SECURITY => ConfigPayload::Security(security_get(state)),
                CONFIG_TYPE_SESSIONKEY => ConfigPayload::Sessionkey,
                _ => ConfigPayload::Empty,
            };
            let resp = AdminMessage {
                payload: AdminPayload::GetConfigResponse(config),
                has_session_passkey: true,
                session_passkey: passkey,
            };
            outcome.response = Some(resp);
        }
        AdminPayload::BeginEditSettings => {
            if !state.session_ok(&msg, now_ms) {
                outcome.routing_error = Some(ROUTING_ERROR_ADMIN_BAD_SESSION_KEY);
                return outcome;
            }
            state.editing = true;
            state.buffered_lora = None;
            state.buffered_admin_keys = None;
            state.buffered_device_update_interval_secs = None;
            state.buffered_device_role = None;
            state.buffered_position = None;
            state.buffered_owner = None;
            outcome.routing_ok = true;
        }
        AdminPayload::CommitEditSettings => {
            if !state.session_ok(&msg, now_ms) {
                outcome.routing_error = Some(ROUTING_ERROR_ADMIN_BAD_SESSION_KEY);
                return outcome;
            }
            let mut candidate = *state;
            let mut preset_changed = None;
            if let Some(lora) = candidate.buffered_lora.take() {
                match apply_lora_to_state(&mut candidate, &lora) {
                    Ok(p) => {
                        preset_changed = Some(p);
                        outcome.config_dirty = true;
                    }
                    Err(()) => {
                        return AdminOutcome {
                            routing_error: Some(ROUTING_ERROR_BAD_REQUEST),
                            ..AdminOutcome::default()
                        };
                    }
                }
            }
            if let Some(keys) = candidate.buffered_admin_keys.take() {
                candidate.admin_public_keys = keys;
                outcome.config_dirty = true;
            }
            if let Some(secs) = candidate.buffered_device_update_interval_secs.take() {
                match apply_device_update_interval(&mut candidate, secs) {
                    Ok(()) => outcome.config_dirty = true,
                    Err(()) => {
                        return AdminOutcome {
                            routing_error: Some(ROUTING_ERROR_BAD_REQUEST),
                            ..AdminOutcome::default()
                        };
                    }
                }
            }
            if let Some(role) = candidate.buffered_device_role.take() {
                candidate.device_role = role;
                outcome.apply_device_role = Some(role);
                outcome.config_dirty = true;
            }
            if let Some(pos) = candidate.buffered_position.take() {
                apply_position_config(&mut candidate, &pos);
                outcome.config_dirty = true;
            }
            if let Some(owner) = candidate.buffered_owner.take() {
                apply_owner_names(&mut candidate, &owner);
                outcome.apply_owner = Some(owner);
                outcome.config_dirty = true;
            }
            candidate.editing = false;
            outcome.apply_modem_preset = preset_changed;
            // A software reset would enter UF2 upload mode instead of applying modem settings.
            candidate.config_dirty |= outcome.config_dirty;
            *state = candidate;
            outcome.routing_ok = true;
        }
        AdminPayload::SetConfig(config) => {
            if !state.session_ok(&msg, now_ms) {
                outcome.routing_error = Some(ROUTING_ERROR_ADMIN_BAD_SESSION_KEY);
                return outcome;
            }
            match config {
                ConfigPayload::Lora(lora) => {
                    if state.editing {
                        if !lora_region_accepted(&lora) {
                            outcome.routing_error = Some(ROUTING_ERROR_BAD_REQUEST);
                            return outcome;
                        }
                        state.buffered_lora = Some(lora);
                    } else {
                        match apply_lora_to_state(state, &lora) {
                            Ok(p) => {
                                outcome.apply_modem_preset = Some(p);
                                outcome.config_dirty = true;
                                state.config_dirty = true;
                            }
                            Err(()) => {
                                outcome.routing_error = Some(ROUTING_ERROR_BAD_REQUEST);
                                return outcome;
                            }
                        }
                    }
                }
                ConfigPayload::Security(sec) => {
                    let keys = security_keys_from_wire(&sec);
                    if state.editing {
                        state.buffered_admin_keys = Some(keys);
                    } else {
                        state.admin_public_keys = keys;
                        outcome.config_dirty = true;
                        state.config_dirty = true;
                    }
                }
                ConfigPayload::Position(pos) => {
                    if state.editing {
                        state.buffered_position = Some(pos);
                    } else {
                        apply_position_config(state, &pos);
                        outcome.config_dirty = true;
                        state.config_dirty = true;
                    }
                }
                ConfigPayload::Device(dev) => {
                    if !is_known_device_role(dev.role) {
                        outcome.routing_error = Some(ROUTING_ERROR_BAD_REQUEST);
                        return outcome;
                    }
                    if state.editing {
                        state.buffered_device_role = Some(dev.role);
                    } else {
                        state.device_role = dev.role;
                        outcome.apply_device_role = Some(dev.role);
                        outcome.config_dirty = true;
                        state.config_dirty = true;
                    }
                }
                ConfigPayload::Sessionkey | ConfigPayload::Empty => {}
            }
            outcome.routing_ok = true;
        }
        AdminPayload::SetModuleConfig(config) => {
            if !state.session_ok(&msg, now_ms) {
                outcome.routing_error = Some(ROUTING_ERROR_ADMIN_BAD_SESSION_KEY);
                return outcome;
            }
            match config {
                ModuleConfigPayload::Telemetry(tel) => {
                    if state.editing {
                        let radio = eu868_config_for_preset(state.modem_preset);
                        if tel.device_update_interval != 0
                            && tel.device_update_interval < min_device_update_interval_secs(&radio)
                        {
                            outcome.routing_error = Some(ROUTING_ERROR_BAD_REQUEST);
                            return outcome;
                        }
                        state.buffered_device_update_interval_secs =
                            Some(tel.device_update_interval);
                    } else {
                        match apply_device_update_interval(state, tel.device_update_interval) {
                            Ok(()) => {
                                outcome.config_dirty = true;
                                state.config_dirty = true;
                            }
                            Err(()) => {
                                outcome.routing_error = Some(ROUTING_ERROR_BAD_REQUEST);
                                return outcome;
                            }
                        }
                    }
                }
                ModuleConfigPayload::Empty => {}
            }
            outcome.routing_ok = true;
        }
        AdminPayload::SetFixedPosition(pos) => {
            if !state.session_ok(&msg, now_ms) {
                outcome.routing_error = Some(ROUTING_ERROR_ADMIN_BAD_SESSION_KEY);
                return outcome;
            }
            if !pos.has_latitude_i || !pos.has_longitude_i {
                outcome.routing_error = Some(ROUTING_ERROR_BAD_REQUEST);
                return outcome;
            }
            if (pos.latitude_i == 0 && pos.longitude_i == 0)
                || !(-900_000_000..=900_000_000).contains(&pos.latitude_i)
                || !(-1_800_000_000..=1_800_000_000).contains(&pos.longitude_i)
            {
                outcome.routing_error = Some(ROUTING_ERROR_BAD_REQUEST);
                return outcome;
            }
            state.latitude_i = pos.latitude_i;
            state.longitude_i = pos.longitude_i;
            state.has_fixed_coords = true;
            state.fixed_position = true;
            outcome.config_dirty = true;
            state.config_dirty = true;
            outcome.broadcast_position = true;
            outcome.routing_ok = true;
        }
        AdminPayload::RemoveFixedPosition => {
            if !state.session_ok(&msg, now_ms) {
                outcome.routing_error = Some(ROUTING_ERROR_ADMIN_BAD_SESSION_KEY);
                return outcome;
            }
            state.fixed_position = false;
            state.has_fixed_coords = false;
            state.latitude_i = 0;
            state.longitude_i = 0;
            outcome.config_dirty = true;
            state.config_dirty = true;
            outcome.routing_ok = true;
        }
        AdminPayload::SetOwner(owner_identity) => {
            if !state.session_ok(&msg, now_ms) {
                outcome.routing_error = Some(ROUTING_ERROR_ADMIN_BAD_SESSION_KEY);
                return outcome;
            }
            let current = owner_names_from_state(state);
            let Ok(merged) = merge_owner_update(&owner_identity, &current) else {
                outcome.routing_error = Some(ROUTING_ERROR_BAD_REQUEST);
                return outcome;
            };
            if state.editing {
                state.buffered_owner = Some(merged);
            } else {
                apply_owner_names(state, &merged);
                outcome.apply_owner = Some(merged);
                outcome.config_dirty = true;
                state.config_dirty = true;
            }
            outcome.routing_ok = true;
        }
        AdminPayload::RebootSeconds(secs) => {
            if !state.session_ok(&msg, now_ms) {
                outcome.routing_error = Some(ROUTING_ERROR_ADMIN_BAD_SESSION_KEY);
                return outcome;
            }
            state.pending_reboot_seconds = Some(secs);
            outcome.reboot_seconds = Some(secs);
            outcome.routing_ok = true;
        }
        _ => {}
    }

    outcome
}

fn name_is_whitespace_only(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|&b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
}

fn owner_names_from_state(state: &AdminState) -> OwnerNames {
    OwnerNames {
        short_name: state.short_name,
        short_name_len: state.short_name_len,
        long_name: state.long_name,
        long_name_len: state.long_name_len,
        is_licensed: false,
    }
}

fn merge_owner_update(
    identity: &NodeInfoIdentity,
    current: &OwnerNames,
) -> Result<OwnerNames, ()> {
    let mut out = *current;
    let advert = &identity.advert;
    let short_raw = &advert.short_name[..advert.short_name_len as usize];
    if !short_raw.is_empty() {
        if name_is_whitespace_only(short_raw) {
            return Err(());
        }
        let len = short_raw.len().min(OWNER_SHORT_NAME_MAX);
        out.short_name = [0; OWNER_SHORT_NAME_MAX];
        out.short_name[..len].copy_from_slice(&short_raw[..len]);
        out.short_name_len = len as u8;
    }
    let long_raw = &advert.long_name[..advert.long_name_len as usize];
    if !long_raw.is_empty() {
        if name_is_whitespace_only(long_raw) {
            return Err(());
        }
        let len = long_raw.len().min(OWNER_LONG_NAME_MAX);
        out.long_name = [0; OWNER_LONG_NAME_MAX];
        out.long_name[..len].copy_from_slice(&long_raw[..len]);
        out.long_name_len = len as u8;
    }
    out.is_licensed = advert.is_licensed;
    Ok(out)
}

fn apply_owner_names(state: &mut AdminState, names: &OwnerNames) {
    state.short_name = names.short_name;
    state.short_name_len = names.short_name_len;
    state.long_name = names.long_name;
    state.long_name_len = names.long_name_len;
}

fn channel_for_request(index_plus_one: u32, channel_psk: &[u8], channel_hash: u8) -> WireChannel {
    if index_plus_one == 0 {
        return WireChannel {
            index: 0,
            role: CHANNEL_ROLE_DISABLED,
            settings: WireChannelSettings::default(),
            has_settings: false,
        };
    }
    let index = (index_plus_one as i32).saturating_sub(1);
    if index == 0 {
        let mut settings = WireChannelSettings::default();
        if channel_psk == DEFAULT_PSK.as_slice() {
            settings.psk[0] = 0x01;
            settings.psk_len = 1;
        } else {
            let len = channel_psk.len().min(32);
            settings.psk[..len].copy_from_slice(&channel_psk[..len]);
            settings.psk_len = len as u8;
        }
        settings.id = channel_hash as u32;
        settings.has_id = true;
        WireChannel {
            index: 0,
            role: CHANNEL_ROLE_PRIMARY,
            settings,
            has_settings: true,
        }
    } else {
        WireChannel {
            index,
            role: CHANNEL_ROLE_DISABLED,
            settings: WireChannelSettings::default(),
            has_settings: false,
        }
    }
}

fn security_get(state: &AdminState) -> WireSecurityConfig {
    let has_public_key = state.public_key.iter().any(|&b| b != 0);
    let has_private_key = state.private_key.iter().any(|&b| b != 0);
    let mut sec = WireSecurityConfig {
        has_public_key,
        has_private_key,
        ..Default::default()
    };
    if has_public_key {
        sec.public_key = state.public_key;
    }
    if has_private_key {
        sec.private_key = state.private_key;
    }
    let mut count = 0u8;
    for slot in &state.admin_public_keys {
        if slot != &EMPTY_ADMIN_KEY && (count as usize) < MAX_ADMIN_KEYS {
            sec.admin_keys[count as usize] = *slot;
            count += 1;
        }
    }
    sec.admin_key_count = count;
    sec.is_managed = count > 0;
    sec.admin_channel_enabled = false;
    sec
}

fn security_keys_from_wire(sec: &WireSecurityConfig) -> [[u8; 32]; ADMIN_KEY_SLOTS] {
    let mut keys = [EMPTY_ADMIN_KEY; ADMIN_KEY_SLOTS];
    let n = (sec.admin_key_count as usize)
        .min(ADMIN_KEY_SLOTS)
        .min(MAX_ADMIN_KEYS);
    let mut out = 0usize;
    for i in 0..n {
        let k = sec.admin_keys[i];
        if k == EMPTY_ADMIN_KEY {
            continue;
        }
        keys[out] = k;
        out += 1;
        if out >= ADMIN_KEY_SLOTS {
            break;
        }
    }
    keys
}

fn lora_region_accepted(lora: &WireLoRaConfig) -> bool {
    let valid_preset = u8::try_from(lora.modem_preset)
        .ok()
        .is_some_and(mesh_radio::is_valid_modem_preset);
    lora.use_preset
        && (lora.region == 0 || lora.region == REGION_EU_868)
        && valid_preset
        && lora.hop_limit <= u32::from(mesh_radio::MAX_HOP_LIMIT)
        && (0..=27).contains(&lora.tx_power)
}

fn apply_lora_to_state(state: &mut AdminState, lora: &WireLoRaConfig) -> Result<u8, ()> {
    if !lora_region_accepted(lora) {
        return Err(());
    }
    let preset = lora.modem_preset as u8;
    state.modem_preset = preset;
    state.use_preset = true;
    state.hop_limit = lora.hop_limit as u8;
    state.tx_power_dbm = if lora.tx_power == 0 {
        MAX_TX_POWER_DBM
    } else {
        (lora.tx_power as u8).min(MAX_TX_POWER_DBM)
    };
    state.ok_to_mqtt = lora.config_ok_to_mqtt;
    Ok(preset)
}

fn apply_position_config(state: &mut AdminState, pos: &WirePositionConfig) {
    state.position_broadcast_secs =
        coerce_position_broadcast_secs(pos.position_broadcast_secs, state.device_role);
    state.fixed_position = pos.fixed_position;
}

fn apply_device_update_interval(state: &mut AdminState, secs: u32) -> Result<(), ()> {
    if secs != 0 {
        let radio = eu868_config_for_preset(state.modem_preset);
        if secs < min_device_update_interval_secs(&radio) {
            return Err(());
        }
    }
    state.device_update_interval_secs = secs;
    Ok(())
}

pub fn encode_admin_response(msg: &AdminMessage) -> heapless::Vec<u8, 240> {
    encode_admin_message(msg)
}

pub fn encode_owner_response(
    node_num: u32,
    identity: &NodeInfoIdentity,
    passkey: &[u8; SESSION_PASSKEY_LEN],
) -> heapless::Vec<u8, 240> {
    let mut out = heapless::Vec::new();
    let user = crate::nodeinfo::encode_user(node_num, identity);
    push_bytes_field_local(&mut out, 4, &user);
    push_bytes_field_local(&mut out, 101, passkey);
    out
}

fn push_bytes_field_local(out: &mut heapless::Vec<u8, 240>, field: u32, data: &[u8]) {
    push_varint_local(out, (field << 3) | 2);
    push_varint_local(out, data.len() as u32);
    let _ = out.extend_from_slice(data);
}

fn push_varint_local(out: &mut heapless::Vec<u8, 240>, mut v: u32) {
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
    use crate::admin_codec::{encode_admin_message, AdminPayload, CONFIG_TYPE_SECURITY};
    use crate::nodeinfo::DEVICE_ROLE_ROUTER;
    use mesh_store::BUILTIN_ADMIN_PUBLIC_KEYS;

    fn identity() -> NodeInfoIdentity {
        NodeInfoIdentity::for_node(0x11, [0x55; 32])
    }

    #[test]
    fn unauthorized_cannot_set() {
        let mut state = AdminState {
            public_key: [0x55; 32],
            ..Default::default()
        };
        let passkey = state.issue_session(1_000);
        let lora = WireLoRaConfig {
            use_preset: true,
            modem_preset: mesh_radio::MODEM_SHORT_FAST as u32,
            region: REGION_EU_868,
            hop_limit: 3,
            tx_power: 27,
            config_ok_to_mqtt: true,
        };
        let msg = AdminMessage {
            payload: AdminPayload::SetConfig(ConfigPayload::Lora(lora)),
            has_session_passkey: true,
            session_passkey: passkey,
        };
        let bytes = encode_admin_message(&msg);
        let outcome = handle_admin(
            &mut state,
            &[0x99; 32],
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_ROUTER,
            &bytes,
            1_000,
        );
        assert_eq!(
            outcome.routing_error,
            Some(ROUTING_ERROR_ADMIN_PUBLIC_KEY_UNAUTHORIZED)
        );
        assert!(outcome.apply_modem_preset.is_none());
    }

    #[test]
    fn builtin_can_get_set_lora_and_security() {
        let mut state = AdminState {
            public_key: [0x55; 32],
            ..Default::default()
        };
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];

        let get = AdminMessage {
            payload: AdminPayload::GetConfigRequest(CONFIG_TYPE_LORA),
            ..Default::default()
        };
        let get_bytes = encode_admin_message(&get);
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_ROUTER,
            &get_bytes,
            2_000,
        );
        let resp = out.response.unwrap();
        assert!(resp.has_session_passkey);

        let set = AdminMessage {
            payload: AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig {
                use_preset: true,
                modem_preset: mesh_radio::MODEM_SHORT_FAST as u32,
                region: REGION_EU_868,
                hop_limit: 3,
                tx_power: 27,
                config_ok_to_mqtt: true,
            })),
            has_session_passkey: true,
            session_passkey: resp.session_passkey,
        };
        let set_bytes = encode_admin_message(&set);
        let out2 = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_ROUTER,
            &set_bytes,
            2_100,
        );
        assert_eq!(out2.apply_modem_preset, Some(mesh_radio::MODEM_SHORT_FAST));
        assert!(out2.config_dirty);
        assert!(out2.routing_ok);
        assert!(out2.response.is_none());

        let sget = AdminMessage {
            payload: AdminPayload::GetConfigRequest(CONFIG_TYPE_SECURITY),
            ..Default::default()
        };
        let sget_bytes = encode_admin_message(&sget);
        let sout = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_ROUTER,
            &sget_bytes,
            2_200,
        );
        match sout.response.unwrap().payload {
            AdminPayload::GetConfigResponse(ConfigPayload::Security(sec)) => {
                for i in 0..sec.admin_key_count as usize {
                    assert_ne!(sec.admin_keys[i], BUILTIN_ADMIN_PUBLIC_KEYS[0]);
                    assert_ne!(sec.admin_keys[i], BUILTIN_ADMIN_PUBLIC_KEYS[1]);
                }
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn rejected_region_does_not_ack() {
        let mut state = AdminState {
            private_key: [0x42; 32],
            public_key: [0x55; 32],
            ..Default::default()
        };
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];
        let passkey = state.issue_session(9_000);
        let set = AdminMessage {
            payload: AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig {
                use_preset: true,
                modem_preset: mesh_radio::MODEM_SHORT_FAST as u32,
                region: 1,
                hop_limit: 3,
                tx_power: 27,
                config_ok_to_mqtt: true,
            })),
            has_session_passkey: true,
            session_passkey: passkey,
        };
        let bytes = encode_admin_message(&set);
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            1,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_ROUTER,
            &bytes,
            9_000,
        );
        assert_eq!(out.routing_error, Some(ROUTING_ERROR_BAD_REQUEST));
        assert!(out.response.is_none());
        assert_eq!(state.modem_preset, mesh_radio::MODEM_DEFAULT_PRESET);
    }

    #[test]
    fn session_passkey_not_public_time_xor() {
        let mut state = AdminState {
            private_key: [0x99; 32],
            public_key: [0x11; 32],
            ..Default::default()
        };
        let pk = state.issue_session(0x1234_5678);
        assert_ne!(&pk[0..4], &0x1234_5678u32.to_le_bytes());
        let pk2 = state.issue_session(0x1234_5678);
        assert_ne!(pk, pk2);
    }

    #[test]
    fn bad_session_rejects_set() {
        let mut state = AdminState {
            private_key: [0x42; 32],
            ..Default::default()
        };
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[1];
        state.issue_session(5_000);
        let set = AdminMessage {
            payload: AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig::default())),
            has_session_passkey: true,
            session_passkey: [0xFF; 8],
        };
        let bytes = encode_admin_message(&set);
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            1,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_ROUTER,
            &bytes,
            5_000,
        );
        assert_eq!(out.routing_error, Some(ROUTING_ERROR_ADMIN_BAD_SESSION_KEY));
        assert!(!out.config_dirty);
    }

    #[test]
    fn lora_set_does_not_schedule_reboot() {
        let mut state = AdminState {
            private_key: [0x42; 32],
            ..Default::default()
        };
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];
        let passkey = state.issue_session(1_000);
        let set = AdminMessage {
            payload: AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig {
                use_preset: true,
                modem_preset: mesh_radio::MODEM_SHORT_FAST as u32,
                region: REGION_EU_868,
                hop_limit: 3,
                tx_power: 27,
                config_ok_to_mqtt: true,
            })),
            has_session_passkey: true,
            session_passkey: passkey,
        };
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            1,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_ROUTER,
            &encode_admin_message(&set),
            1_000,
        );
        assert_eq!(out.apply_modem_preset, Some(mesh_radio::MODEM_SHORT_FAST));
        assert!(out.routing_ok);
        assert!(
            out.reboot_seconds.is_none(),
            "LoRa preset must not schedule sys_reset (UF2 boards enter upload mode)"
        );
        assert!(state.pending_reboot_seconds.is_none());
    }

    #[test]
    fn get_channel_primary_and_disabled() {
        let mut state = AdminState {
            private_key: [0x42; 32],
            public_key: [0x55; 32],
            ..Default::default()
        };
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];

        let get = AdminMessage {
            payload: AdminPayload::GetChannelRequest(1),
            ..Default::default()
        };
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_ROUTER,
            &encode_admin_message(&get),
            1_000,
        );
        match out.response.unwrap().payload {
            AdminPayload::GetChannelResponse(ch) => {
                assert_eq!(ch.index, 0);
                assert_eq!(ch.role, CHANNEL_ROLE_PRIMARY);
                assert!(ch.has_settings);
                assert_eq!(ch.settings.psk_len, 1);
                assert_eq!(ch.settings.psk[0], 0x01);
                assert!(ch.settings.has_id);
                assert_eq!(ch.settings.id, 0x77);
            }
            other => panic!("{:?}", other),
        }

        let get2 = AdminMessage {
            payload: AdminPayload::GetChannelRequest(2),
            ..Default::default()
        };
        let out2 = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_ROUTER,
            &encode_admin_message(&get2),
            1_100,
        );
        match out2.response.unwrap().payload {
            AdminPayload::GetChannelResponse(ch) => {
                assert_eq!(ch.index, 1);
                assert_eq!(ch.role, CHANNEL_ROLE_DISABLED);
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn get_device_and_module_config_reply() {
        let mut state = AdminState {
            private_key: [0x42; 32],
            device_role: DEVICE_ROLE_ROUTER,
            ..Default::default()
        };
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];

        let get = AdminMessage {
            payload: AdminPayload::GetConfigRequest(CONFIG_TYPE_DEVICE),
            ..Default::default()
        };
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_ROUTER,
            &encode_admin_message(&get),
            2_000,
        );
        match out.response.unwrap().payload {
            AdminPayload::GetConfigResponse(ConfigPayload::Device(dev)) => {
                assert_eq!(dev.role, DEVICE_ROLE_ROUTER);
            }
            other => panic!("{:?}", other),
        }

        let modreq = AdminMessage {
            payload: AdminPayload::GetModuleConfigRequest(0),
            ..Default::default()
        };
        let mout = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_ROUTER,
            &encode_admin_message(&modreq),
            2_100,
        );
        assert!(matches!(
            mout.response.unwrap().payload,
            AdminPayload::GetModuleConfigResponse(ModuleConfigPayload::Empty)
        ));
    }

    #[test]
    fn security_get_includes_identity_keys_set_ignores_them() {
        let mut state = AdminState {
            private_key: [0x42; 32],
            public_key: [0x55; 32],
            ..Default::default()
        };
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];

        let sget = AdminMessage {
            payload: AdminPayload::GetConfigRequest(CONFIG_TYPE_SECURITY),
            ..Default::default()
        };
        let sout = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_ROUTER,
            &encode_admin_message(&sget),
            3_000,
        );
        let get_resp = sout.response.unwrap();
        match &get_resp.payload {
            AdminPayload::GetConfigResponse(ConfigPayload::Security(sec)) => {
                assert_eq!(sec.public_key, [0x55; 32]);
                assert_eq!(sec.private_key, [0x42; 32]);
                assert!(!sec.admin_channel_enabled);
            }
            other => panic!("{:?}", other),
        }
        let passkey = get_resp.session_passkey;

        let mut sec = WireSecurityConfig {
            has_public_key: true,
            public_key: [0xDE; 32],
            has_private_key: true,
            private_key: [0xAD; 32],
            ..Default::default()
        };
        sec.admin_keys[0] = [0x11; 32];
        sec.admin_key_count = 1;
        let set = AdminMessage {
            payload: AdminPayload::SetConfig(ConfigPayload::Security(sec)),
            has_session_passkey: true,
            session_passkey: passkey,
        };
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_ROUTER,
            &encode_admin_message(&set),
            3_100,
        );
        assert!(out.response.is_none());
        assert!(out.routing_ok);
        assert_eq!(state.public_key, [0x55; 32]);
        assert_eq!(state.private_key, [0x42; 32]);
        assert_eq!(state.admin_public_keys[0], [0x11; 32]);
        assert!(out.reboot_seconds.is_none());
        assert!(state.pending_reboot_seconds.is_none());
    }

    #[test]
    fn set_device_role_applies_and_get_returns_it() {
        let mut state = AdminState {
            private_key: [0x42; 32],
            ..Default::default()
        };
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];
        let passkey = state.issue_session(4_000);

        let set = AdminMessage {
            payload: AdminPayload::SetConfig(ConfigPayload::Device(WireDeviceConfig {
                role: DEVICE_ROLE_ROUTER,
            })),
            has_session_passkey: true,
            session_passkey: passkey,
        };
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_CLIENT,
            &encode_admin_message(&set),
            4_100,
        );
        assert!(out.routing_ok);
        assert_eq!(out.apply_device_role, Some(DEVICE_ROLE_ROUTER));
        assert_eq!(state.device_role, DEVICE_ROLE_ROUTER);
        assert!(out.config_dirty);

        let get = AdminMessage {
            payload: AdminPayload::GetConfigRequest(CONFIG_TYPE_DEVICE),
            ..Default::default()
        };
        let gout = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_CLIENT,
            &encode_admin_message(&get),
            4_200,
        );
        match gout.response.unwrap().payload {
            AdminPayload::GetConfigResponse(ConfigPayload::Device(dev)) => {
                assert_eq!(dev.role, DEVICE_ROLE_ROUTER);
            }
            other => panic!("{:?}", other),
        }

        let set_client = AdminMessage {
            payload: AdminPayload::SetConfig(ConfigPayload::Device(WireDeviceConfig {
                role: DEVICE_ROLE_CLIENT,
            })),
            has_session_passkey: true,
            session_passkey: state.issue_session(4_250),
        };
        let cout = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_ROUTER,
            &encode_admin_message(&set_client),
            4_300,
        );
        assert!(cout.routing_ok);
        assert_eq!(cout.apply_device_role, Some(DEVICE_ROLE_CLIENT));
        assert_eq!(state.device_role, DEVICE_ROLE_CLIENT);
    }

    #[test]
    fn unknown_device_role_is_rejected() {
        let mut state = AdminState {
            private_key: [0x42; 32],
            ..Default::default()
        };
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];
        let passkey = state.issue_session(5_000);
        let set = AdminMessage {
            payload: AdminPayload::SetConfig(ConfigPayload::Device(WireDeviceConfig { role: 99 })),
            has_session_passkey: true,
            session_passkey: passkey,
        };
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_CLIENT,
            &encode_admin_message(&set),
            5_100,
        );
        assert_eq!(out.routing_error, Some(ROUTING_ERROR_BAD_REQUEST));
        assert!(out.apply_device_role.is_none());
        assert_eq!(state.device_role, DEVICE_ROLE_CLIENT);
    }

    #[test]
    fn position_interval_is_floored_and_fixed_coords_round_trip() {
        use crate::admin_codec::{WireFixedPosition, CONFIG_TYPE_POSITION};
        use crate::position::POSITION_BROADCAST_SECS_CLIENT;

        let mut state = AdminState {
            private_key: [0x42; 32],
            ..Default::default()
        };
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];
        let passkey = state.issue_session(6_000);

        let set = AdminMessage {
            payload: AdminPayload::SetConfig(ConfigPayload::Position(WirePositionConfig {
                position_broadcast_secs: 60,
                fixed_position: true,
            })),
            has_session_passkey: true,
            session_passkey: passkey,
        };
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_CLIENT,
            &encode_admin_message(&set),
            6_100,
        );
        assert!(out.routing_ok);
        assert!(!out.broadcast_position);
        assert_eq!(
            state.position_broadcast_secs,
            POSITION_BROADCAST_SECS_CLIENT
        );
        assert!(state.fixed_position);
        assert!(!state.broadcasts_fixed_position());

        let passkey = state.issue_session(6_200);
        let mut fix = AdminMessage {
            payload: AdminPayload::SetFixedPosition(WireFixedPosition {
                latitude_i: 1,
                longitude_i: 0,
                has_latitude_i: false,
                has_longitude_i: true,
            }),
            has_session_passkey: true,
            session_passkey: passkey,
        };
        let missing = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_CLIENT,
            &encode_admin_message(&fix),
            6_300,
        );
        assert_eq!(missing.routing_error, Some(ROUTING_ERROR_BAD_REQUEST));

        let passkey = state.issue_session(6_400);
        fix.payload = AdminPayload::SetFixedPosition(WireFixedPosition {
            latitude_i: 52_000_000,
            longitude_i: 13_000_000,
            has_latitude_i: true,
            has_longitude_i: true,
        });
        fix.session_passkey = passkey;
        let placed = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_CLIENT,
            &encode_admin_message(&fix),
            6_500,
        );
        assert!(placed.routing_ok);
        assert!(placed.broadcast_position);
        assert!(state.broadcasts_fixed_position());

        let get = AdminMessage {
            payload: AdminPayload::GetConfigRequest(CONFIG_TYPE_POSITION),
            ..Default::default()
        };
        let got = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_CLIENT,
            &encode_admin_message(&get),
            6_600,
        );
        match got.response.unwrap().payload {
            AdminPayload::GetConfigResponse(ConfigPayload::Position(pos)) => {
                assert_eq!(pos.position_broadcast_secs, POSITION_BROADCAST_SECS_CLIENT);
                assert!(pos.fixed_position);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn session_is_valid_before_wrapped_deadline_and_expires_at_deadline() {
        let mut state = AdminState::new();
        let start = u32::MAX - 100;
        let key = state.issue_session(start);
        let msg = AdminMessage {
            session_passkey: key,
            has_session_passkey: true,
            payload: AdminPayload::BeginEditSettings,
        };
        assert!(state.session_ok(&msg, start + 1));
        assert!(state.session_ok(&msg, state.session_valid_until_ms.wrapping_sub(1)));
        assert!(!state.session_ok(&msg, state.session_valid_until_ms));
    }

    #[test]
    fn failed_commit_leaves_configuration_and_side_effects_unchanged() {
        let mut state = AdminState::new();
        let authorized = BUILTIN_ADMIN_PUBLIC_KEYS[0];
        let key = state.issue_session(1);
        state.editing = true;
        state.buffered_lora = Some(WireLoRaConfig {
            modem_preset: mesh_radio::MODEM_LONG_SLOW as u32,
            ..WireLoRaConfig::default()
        });
        state.buffered_device_update_interval_secs = Some(1);
        let before = state;
        let msg = AdminMessage {
            session_passkey: key,
            has_session_passkey: true,
            payload: AdminPayload::CommitEditSettings,
        };
        let result = handle_admin(
            &mut state,
            &authorized,
            &identity(),
            1,
            &[],
            0,
            0,
            &encode_admin_message(&msg),
            2,
        );
        assert_eq!(state, before);
        assert_eq!(result.routing_error, Some(ROUTING_ERROR_BAD_REQUEST));
        assert!(!result.config_dirty);
        assert_eq!(result.apply_modem_preset, None);
    }
    #[test]
    fn lora_updates_apply_hops_and_power_and_reject_unsupported_parameters() {
        let mut state = AdminState::new();
        let mut wire = WireLoRaConfig {
            hop_limit: 5,
            tx_power: 10,
            ..Default::default()
        };
        assert!(apply_lora_to_state(&mut state, &wire).is_ok());
        assert_eq!(state.hop_limit, 5);
        assert_eq!(state.tx_power_dbm, 10);
        wire.hop_limit = 0;
        assert!(apply_lora_to_state(&mut state, &wire).is_ok());
        assert_eq!(state.hop_limit, 0);
        wire.hop_limit = 5;
        assert!(apply_lora_to_state(&mut state, &wire).is_ok());
        for (use_preset, hop_limit, tx_power) in
            [(false, 5, 10), (true, 8, 10), (true, 5, -1), (true, 5, 28)]
        {
            wire.use_preset = use_preset;
            wire.hop_limit = hop_limit;
            wire.tx_power = tx_power;
            assert!(apply_lora_to_state(&mut state, &wire).is_err());
            assert_eq!(state.hop_limit, 5);
            assert_eq!(state.tx_power_dbm, 10);
        }
    }

    #[test]
    fn lora_tx_power_is_normalized_to_the_radio_limit() {
        let mut state = AdminState::new();
        let wire = WireLoRaConfig {
            tx_power: 27,
            ..Default::default()
        };
        assert!(apply_lora_to_state(&mut state, &wire).is_ok());
        assert_eq!(state.tx_power_dbm, MAX_TX_POWER_DBM);
    }

    fn owner_identity(short: &[u8], long: &[u8]) -> NodeInfoIdentity {
        let mut id = NodeInfoIdentity::for_node(0x11, [0x55; 32]);
        id.advert.short_name = [0; crate::nodeinfo::NODEINFO_SHORT_NAME_MAX];
        let sl = short.len().min(crate::nodeinfo::NODEINFO_SHORT_NAME_MAX);
        id.advert.short_name[..sl].copy_from_slice(&short[..sl]);
        id.advert.short_name_len = sl as u8;
        id.advert.long_name = [0; crate::nodeinfo::NODEINFO_LONG_NAME_MAX];
        let ll = long.len().min(crate::nodeinfo::NODEINFO_LONG_NAME_MAX);
        id.advert.long_name[..ll].copy_from_slice(&long[..ll]);
        id.advert.long_name_len = ll as u8;
        id
    }

    #[test]
    fn set_owner_requires_session() {
        let mut state = AdminState {
            private_key: [0x42; 32],
            short_name: *b"AB  ",
            short_name_len: 2,
            ..Default::default()
        };
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];
        let msg = AdminMessage {
            payload: AdminPayload::SetOwner(owner_identity(b"XY", b"Cabin")),
            ..Default::default()
        };
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_CLIENT,
            &encode_admin_message(&msg),
            1_000,
        );
        assert_eq!(out.routing_error, Some(ROUTING_ERROR_ADMIN_BAD_SESSION_KEY));
        assert!(out.apply_owner.is_none());
        assert_eq!(state.short_name_len, 2);
    }

    #[test]
    fn set_owner_rejects_whitespace_only_names() {
        let mut state = AdminState {
            private_key: [0x42; 32],
            ..Default::default()
        };
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];
        let passkey = state.issue_session(2_000);
        let msg = AdminMessage {
            payload: AdminPayload::SetOwner(owner_identity(b"  ", b"Cabin")),
            has_session_passkey: true,
            session_passkey: passkey,
        };
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_CLIENT,
            &encode_admin_message(&msg),
            2_100,
        );
        assert_eq!(out.routing_error, Some(ROUTING_ERROR_BAD_REQUEST));
        assert!(out.apply_owner.is_none());
    }

    #[test]
    fn set_owner_partial_update_and_edit_buffer() {
        let mut state = AdminState {
            private_key: [0x42; 32],
            ..Default::default()
        };
        state.short_name[..2].copy_from_slice(b"AB");
        state.short_name_len = 2;
        state.long_name[..4].copy_from_slice(b"Home");
        state.long_name_len = 4;
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];
        let passkey = state.issue_session(3_000);

        let mut empty_short = owner_identity(b"", b"Cabin");
        empty_short.advert.short_name_len = 0;
        let msg = AdminMessage {
            payload: AdminPayload::SetOwner(empty_short),
            has_session_passkey: true,
            session_passkey: passkey,
        };
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_CLIENT,
            &encode_admin_message(&msg),
            3_100,
        );
        assert!(out.routing_ok);
        assert!(out.config_dirty);
        assert_eq!(state.short_name_len, 2);
        assert_eq!(&state.short_name[..2], b"AB");
        assert_eq!(state.long_name_len, 5);
        assert_eq!(&state.long_name[..5], b"Cabin");
        assert!(out.apply_owner.is_some());
        assert!(out.reboot_seconds.is_none());

        let passkey = state.issue_session(3_200);
        let begin = AdminMessage {
            payload: AdminPayload::BeginEditSettings,
            has_session_passkey: true,
            session_passkey: passkey,
        };
        assert!(handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_CLIENT,
            &encode_admin_message(&begin),
            3_300,
        )
        .routing_ok);
        assert!(state.editing);
        assert!(state.buffered_owner.is_none());

        let passkey = state.issue_session(3_400);
        let buffered = AdminMessage {
            payload: AdminPayload::SetOwner(owner_identity(b"ZZ", b"Buffered")),
            has_session_passkey: true,
            session_passkey: passkey,
        };
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_CLIENT,
            &encode_admin_message(&buffered),
            3_500,
        );
        assert!(out.routing_ok);
        assert!(out.apply_owner.is_none());
        assert_eq!(&state.short_name[..2], b"AB");
        assert!(state.buffered_owner.is_some());

        let passkey = state.issue_session(3_600);
        let commit = AdminMessage {
            payload: AdminPayload::CommitEditSettings,
            has_session_passkey: true,
            session_passkey: passkey,
        };
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            0x77,
            DEVICE_ROLE_CLIENT,
            &encode_admin_message(&commit),
            3_700,
        );
        assert!(out.routing_ok);
        assert_eq!(&state.short_name[..2], b"ZZ");
        assert_eq!(&state.long_name[..8], b"Buffered");
        assert_eq!(
            out.apply_owner.map(|o| (
                o.short_name_len,
                o.long_name_len,
                o.short_name[0],
                o.long_name[0]
            )),
            Some((2, 8, b'Z', b'B'))
        );
        assert!(out.reboot_seconds.is_none());
    }
}
