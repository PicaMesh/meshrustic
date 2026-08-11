//! Remote admin handler (ADMIN_APP): ACL, session passkey, get/set LoRa + Security.

use mesh_crypto::sha256_in_place;
use mesh_store::{
    BUILTIN_ADMIN_PUBLIC_KEYS, EMPTY_ADMIN_KEY, NodeConfig, ADMIN_KEY_SLOTS,
};

use crate::admin_codec::{
    decode_admin_message, encode_admin_message, AdminMessage, AdminPayload, ConfigPayload,
    DeviceMetadata, WireChannel, WireChannelSettings, WireDeviceConfig, WireLoRaConfig,
    WireSecurityConfig, CHANNEL_ROLE_DISABLED, CHANNEL_ROLE_PRIMARY, CONFIG_TYPE_DEVICE,
    CONFIG_TYPE_LORA, CONFIG_TYPE_SECURITY, CONFIG_TYPE_SESSIONKEY, MAX_ADMIN_KEYS,
    REGION_EU_868, SESSION_PASSKEY_LEN,
};
use crate::nodeinfo::{NodeInfoIdentity, DEVICE_ROLE_ROUTER, HW_MODEL_NRF52_PROMICRO_DIY};
use mesh_crypto::DEFAULT_PSK;

/// Session passkey validity window (ms).
pub const ADMIN_SESSION_TTL_MS: u32 = 300_000;

/// Default delay (seconds) when a client sends `reboot_seconds` without a value
/// (kept for wire compatibility; LoRa preset apply uses soft radio reinit, not reboot).
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
    pub admin_public_keys: [[u8; 32]; ADMIN_KEY_SLOTS],
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub modem_preset: u8,
    pub use_preset: bool,
    pub hop_limit: u8,
    pub tx_power_dbm: u8,
    pub pending_reboot_seconds: Option<i32>,
    pub config_dirty: bool,
    /// Host/test only: replace Appendix A builtins for real PKI keypairs.
    #[cfg(any(test, feature = "std"))]
    builtin_override: Option<[[u8; 32]; 2]>,
}

impl Default for AdminState {
    fn default() -> Self {
        Self {
            session_passkey: [0; SESSION_PASSKEY_LEN],
            session_valid_until_ms: 0,
            has_session: false,
            passkey_counter: 0,
            editing: false,
            buffered_lora: None,
            buffered_admin_keys: None,
            admin_public_keys: [EMPTY_ADMIN_KEY; ADMIN_KEY_SLOTS],
            private_key: [0; 32],
            public_key: [0; 32],
            modem_preset: mesh_radio::MODEM_SHORT_SLOW,
            use_preset: true,
            hop_limit: 3,
            tx_power_dbm: 27,
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

    /// Single import path: flash/`NodeConfig` → admin runtime state.
    pub fn import_node_config(&mut self, cfg: &NodeConfig) {
        self.admin_public_keys = cfg.admin_public_keys;
        self.private_key = cfg.private_key;
        self.public_key = cfg.public_key;
        self.modem_preset = cfg.lora.modem_preset;
        self.use_preset = cfg.lora.use_preset;
        self.hop_limit = cfg.lora.hop_limit;
        self.tx_power_dbm = cfg.lora.tx_power_dbm;
    }

    /// Deprecated name kept as alias for call sites.
    pub fn apply_node_config(&mut self, cfg: &NodeConfig) {
        self.import_node_config(cfg);
    }

    /// Single export path: admin runtime → `NodeConfig` sections (keys + LoRa).
    pub fn export_to_node_config(&self, cfg: &mut NodeConfig) {
        cfg.admin_public_keys = self.admin_public_keys;
        cfg.lora.apply_modem_preset(self.modem_preset);
        cfg.lora.use_preset = self.use_preset;
        cfg.lora.hop_limit = self.hop_limit;
        cfg.lora.tx_power_dbm = self.tx_power_dbm;
        cfg.private_key = self.private_key;
        cfg.public_key = self.public_key;
    }

    pub fn export_admin_keys_and_lora(&self, cfg: &mut NodeConfig) {
        self.export_to_node_config(cfg);
    }

    /// Effective built-in admin public keys (Appendix A, or host/test override).
    pub fn effective_builtin_admin_keys(&self) -> [[u8; 32]; 2] {
        #[cfg(any(test, feature = "std"))]
        if let Some(keys) = self.builtin_override {
            return keys;
        }
        BUILTIN_ADMIN_PUBLIC_KEYS
    }

    /// Host/unit-test only: authorize generated keypairs as the two builtins.
    ///
    /// Firmware builds without `std` never compile this; production always uses Appendix A.
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
        // Mix node private key (secret) + counter + time; do not derive from public material alone.
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
        if now_ms.wrapping_sub(self.session_valid_until_ms) < 0x8000_0000
            && now_ms > self.session_valid_until_ms
        {
            return false;
        }
        msg.session_passkey == self.session_passkey
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminOutcome {
    pub response: Option<AdminMessage>,
    pub routing_error: Option<u32>,
    /// Mutating ops succeeded: router replies with ROUTING_APP error=NONE
    /// (wire clients treat that as set/commit completion; WantAck alone is insufficient).
    pub routing_ok: bool,
    /// Modem preset changed and should be applied to Router / radio.
    pub apply_modem_preset: Option<u8>,
    pub config_dirty: bool,
    pub reboot_seconds: Option<i32>,
}

impl Default for AdminOutcome {
    fn default() -> Self {
        Self {
            response: None,
            routing_error: None,
            routing_ok: false,
            apply_modem_preset: None,
            config_dirty: false,
            reboot_seconds: None,
        }
    }
}

/// Handle a decoded AdminMessage from an authorized-or-not remote peer.
pub fn handle_admin(
    state: &mut AdminState,
    remote_pk: &[u8; 32],
    identity: &NodeInfoIdentity,
    node_num: u32,
    channel_psk: &[u8],
    device_role: u32,
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
            let ch = channel_for_request(index_plus_one, channel_psk);
            let mut resp = AdminMessage::default();
            resp.payload = AdminPayload::GetChannelResponse(ch);
            resp.has_session_passkey = true;
            resp.session_passkey = passkey;
            outcome.response = Some(resp);
        }
        AdminPayload::GetOwnerRequest => {
            let passkey = state.issue_session(now_ms);
            let mut resp = AdminMessage::default();
            resp.payload = AdminPayload::GetOwnerResponse(*identity);
            resp.has_session_passkey = true;
            resp.session_passkey = passkey;
            let _ = node_num;
            outcome.response = Some(resp);
        }
        AdminPayload::GetDeviceMetadataRequest => {
            let passkey = state.issue_session(now_ms);
            let mut resp = AdminMessage::default();
            resp.payload = AdminPayload::GetDeviceMetadataResponse(DeviceMetadata::meshrustic_default(
                HW_MODEL_NRF52_PROMICRO_DIY,
            ));
            resp.has_session_passkey = true;
            resp.session_passkey = passkey;
            outcome.response = Some(resp);
        }
        AdminPayload::GetModuleConfigRequest(_) => {
            let passkey = state.issue_session(now_ms);
            let mut resp = AdminMessage::default();
            resp.payload = AdminPayload::GetModuleConfigResponse;
            resp.has_session_passkey = true;
            resp.session_passkey = passkey;
            outcome.response = Some(resp);
        }
        AdminPayload::GetConfigRequest(config_type) => {
            let passkey = state.issue_session(now_ms);
            let config = match config_type {
                CONFIG_TYPE_DEVICE => ConfigPayload::Device(WireDeviceConfig {
                    role: if device_role != 0 {
                        device_role
                    } else {
                        DEVICE_ROLE_ROUTER
                    },
                }),
                CONFIG_TYPE_LORA => ConfigPayload::Lora(WireLoRaConfig {
                    use_preset: state.use_preset,
                    modem_preset: state.modem_preset as u32,
                    region: REGION_EU_868,
                    hop_limit: state.hop_limit as u32,
                    tx_power: state.tx_power_dbm as i32,
                }),
                CONFIG_TYPE_SECURITY => ConfigPayload::Security(security_get(state)),
                CONFIG_TYPE_SESSIONKEY => ConfigPayload::Sessionkey,
                _ => ConfigPayload::Empty,
            };
            let mut resp = AdminMessage::default();
            resp.payload = AdminPayload::GetConfigResponse(config);
            resp.has_session_passkey = true;
            resp.session_passkey = passkey;
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
            outcome.routing_ok = true;
        }
        AdminPayload::CommitEditSettings => {
            if !state.session_ok(&msg, now_ms) {
                outcome.routing_error = Some(ROUTING_ERROR_ADMIN_BAD_SESSION_KEY);
                return outcome;
            }
            let mut preset_changed = None;
            if let Some(lora) = state.buffered_lora.take() {
                match apply_lora_to_state(state, &lora) {
                    Ok(p) => {
                        preset_changed = Some(p);
                        outcome.config_dirty = true;
                    }
                    Err(()) => {
                        outcome.routing_error = Some(ROUTING_ERROR_BAD_REQUEST);
                        return outcome;
                    }
                }
            }
            if let Some(keys) = state.buffered_admin_keys.take() {
                state.admin_public_keys = keys;
                outcome.config_dirty = true;
            }
            state.editing = false;
            outcome.apply_modem_preset = preset_changed;
            // Soft radio reinit on the board — avoid sys_reset (UF2 boards enter upload mode).
            state.config_dirty |= outcome.config_dirty;
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
                                // Soft radio reinit on the board — avoid sys_reset (UF2 upload mode).
                            }
                            Err(()) => {
                                outcome.routing_error = Some(ROUTING_ERROR_BAD_REQUEST);
                                return outcome;
                            }
                        }
                    }
                }
                ConfigPayload::Security(sec) => {
                    // Apply flash admin_key slots only — ignore identity key fields on set.
                    // Empty keys are dropped. No reboot required for admin_key-only updates.
                    let keys = security_keys_from_wire(&sec);
                    if state.editing {
                        state.buffered_admin_keys = Some(keys);
                    } else {
                        state.admin_public_keys = keys;
                        outcome.config_dirty = true;
                        state.config_dirty = true;
                    }
                }
                ConfigPayload::Device(_) | ConfigPayload::Sessionkey | ConfigPayload::Empty => {}
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
        _ => {
            // Unknown / response-only variants: ignore without mutating.
        }
    }

    outcome
}

fn channel_for_request(index_plus_one: u32, channel_psk: &[u8]) -> WireChannel {
    if index_plus_one == 0 {
        // Invalid / unset — treat as disabled index 0.
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
        // Empty name: hash path uses modem preset display name when use_preset.
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
    let mut sec = WireSecurityConfig::default();
    sec.has_public_key = state.public_key.iter().any(|&b| b != 0);
    if sec.has_public_key {
        sec.public_key = state.public_key;
    }
    sec.has_private_key = state.private_key.iter().any(|&b| b != 0);
    if sec.has_private_key {
        sec.private_key = state.private_key;
    }
    // Configurable slots only — never inject built-ins.
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
    let n = (sec.admin_key_count as usize).min(ADMIN_KEY_SLOTS).min(MAX_ADMIN_KEYS);
    let mut out = 0usize;
    for i in 0..n {
        let k = sec.admin_keys[i];
        // Skip empty slots; keep only non-zero 32-byte keys (wire length already gated).
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
    lora.region == 0 || lora.region == REGION_EU_868
}

fn apply_lora_to_state(state: &mut AdminState, lora: &WireLoRaConfig) -> Result<u8, ()> {
    // v1: only EU_868; reject other regions (caller must not success-ACK).
    if !lora_region_accepted(lora) {
        return Err(());
    }
    let preset = lora.modem_preset as u8;
    state.modem_preset = preset;
    state.use_preset = true;
    Ok(preset)
}

/// Encode admin response payload bytes.
pub fn encode_admin_response(msg: &AdminMessage) -> heapless::Vec<u8, 240> {
    encode_admin_message(msg)
}

/// Re-encode get_owner_response with the correct node id string.
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

fn _keep_unused() {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_codec::{encode_admin_message, AdminPayload, CONFIG_TYPE_SECURITY};
    use mesh_store::BUILTIN_ADMIN_PUBLIC_KEYS;

    fn identity() -> NodeInfoIdentity {
        NodeInfoIdentity::for_node(0x11, [0x55; 32])
    }

    #[test]
    fn unauthorized_cannot_set() {
        let mut state = AdminState::default();
        state.public_key = [0x55; 32];
        let passkey = state.issue_session(1_000);
        let lora = WireLoRaConfig {
            use_preset: true,
            modem_preset: mesh_radio::MODEM_SHORT_FAST as u32,
            region: REGION_EU_868,
            hop_limit: 3,
            tx_power: 27,
        };
        let mut msg = AdminMessage::default();
        msg.payload = AdminPayload::SetConfig(ConfigPayload::Lora(lora));
        msg.has_session_passkey = true;
        msg.session_passkey = passkey;
        let bytes = encode_admin_message(&msg);
        let outcome = handle_admin(
            &mut state,
            &[0x99; 32],
            &identity(),
            0x11,
            &DEFAULT_PSK,
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
        let mut state = AdminState::default();
        state.public_key = [0x55; 32];
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];

        let mut get = AdminMessage::default();
        get.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_LORA);
        let get_bytes = encode_admin_message(&get);
        let out = handle_admin(&mut state, &remote, &identity(), 0x11, &DEFAULT_PSK, DEVICE_ROLE_ROUTER, &get_bytes, 2_000);
        let resp = out.response.unwrap();
        assert!(resp.has_session_passkey);

        let mut set = AdminMessage::default();
        set.payload = AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig {
            use_preset: true,
            modem_preset: mesh_radio::MODEM_SHORT_FAST as u32,
            region: REGION_EU_868,
            hop_limit: 3,
            tx_power: 27,
        }));
        set.has_session_passkey = true;
        set.session_passkey = resp.session_passkey;
        let set_bytes = encode_admin_message(&set);
        let out2 = handle_admin(&mut state, &remote, &identity(), 0x11, &DEFAULT_PSK, DEVICE_ROLE_ROUTER, &set_bytes, 2_100);
        assert_eq!(out2.apply_modem_preset, Some(mesh_radio::MODEM_SHORT_FAST));
        assert!(out2.config_dirty);
        assert!(out2.routing_ok);
        assert!(out2.response.is_none());

        // Security get must not contain builtins.
        let mut sget = AdminMessage::default();
        sget.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_SECURITY);
        let sget_bytes = encode_admin_message(&sget);
        let sout = handle_admin(&mut state, &remote, &identity(), 0x11, &DEFAULT_PSK, DEVICE_ROLE_ROUTER, &sget_bytes, 2_200);
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
        let mut state = AdminState::default();
        state.private_key = [0x42; 32];
        state.public_key = [0x55; 32];
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];
        let passkey = state.issue_session(9_000);
        let mut set = AdminMessage::default();
        set.payload = AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig {
            use_preset: true,
            modem_preset: mesh_radio::MODEM_SHORT_FAST as u32,
            region: 1, // US — not EU_868
            hop_limit: 3,
            tx_power: 27,
        }));
        set.has_session_passkey = true;
        set.session_passkey = passkey;
        let bytes = encode_admin_message(&set);
        let out = handle_admin(&mut state, &remote, &identity(), 1, &DEFAULT_PSK, DEVICE_ROLE_ROUTER, &bytes, 9_000);
        assert_eq!(out.routing_error, Some(ROUTING_ERROR_BAD_REQUEST));
        assert!(out.response.is_none());
        assert_eq!(state.modem_preset, mesh_radio::MODEM_SHORT_SLOW);
    }

    #[test]
    fn session_passkey_not_public_time_xor() {
        let mut state = AdminState::default();
        state.private_key = [0x99; 32];
        state.public_key = [0x11; 32];
        let pk = state.issue_session(0x1234_5678);
        // Old weak recipe put now_ms in the first 4 bytes — must not.
        assert_ne!(&pk[0..4], &0x1234_5678u32.to_le_bytes());
        let pk2 = state.issue_session(0x1234_5678);
        assert_ne!(pk, pk2); // counter advances
    }

    #[test]
    fn bad_session_rejects_set() {
        let mut state = AdminState::default();
        state.private_key = [0x42; 32];
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[1];
        state.issue_session(5_000);
        let mut set = AdminMessage::default();
        set.payload = AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig::default()));
        set.has_session_passkey = true;
        set.session_passkey = [0xFF; 8];
        let bytes = encode_admin_message(&set);
        let out = handle_admin(&mut state, &remote, &identity(), 1, &DEFAULT_PSK, DEVICE_ROLE_ROUTER, &bytes, 5_000);
        assert_eq!(out.routing_error, Some(ROUTING_ERROR_ADMIN_BAD_SESSION_KEY));
        assert!(!out.config_dirty);
    }

    #[test]
    fn lora_set_does_not_schedule_reboot() {
        let mut state = AdminState::default();
        state.private_key = [0x42; 32];
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];
        let passkey = state.issue_session(1_000);
        let mut set = AdminMessage::default();
        set.payload = AdminPayload::SetConfig(ConfigPayload::Lora(WireLoRaConfig {
            use_preset: true,
            modem_preset: mesh_radio::MODEM_SHORT_FAST as u32,
            region: REGION_EU_868,
            hop_limit: 3,
            tx_power: 27,
        }));
        set.has_session_passkey = true;
        set.session_passkey = passkey;
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            1,
            &DEFAULT_PSK,
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
        let mut state = AdminState::default();
        state.private_key = [0x42; 32];
        state.public_key = [0x55; 32];
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];

        let mut get = AdminMessage::default();
        get.payload = AdminPayload::GetChannelRequest(1);
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
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
            }
            other => panic!("{:?}", other),
        }

        let mut get2 = AdminMessage::default();
        get2.payload = AdminPayload::GetChannelRequest(2);
        let out2 = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
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
        let mut state = AdminState::default();
        state.private_key = [0x42; 32];
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];

        let mut get = AdminMessage::default();
        get.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_DEVICE);
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
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

        let mut modreq = AdminMessage::default();
        modreq.payload = AdminPayload::GetModuleConfigRequest(0);
        let mout = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            DEVICE_ROLE_ROUTER,
            &encode_admin_message(&modreq),
            2_100,
        );
        assert!(matches!(
            mout.response.unwrap().payload,
            AdminPayload::GetModuleConfigResponse
        ));
    }

    #[test]
    fn security_get_includes_identity_keys_set_ignores_them() {
        let mut state = AdminState::default();
        state.private_key = [0x42; 32];
        state.public_key = [0x55; 32];
        let remote = BUILTIN_ADMIN_PUBLIC_KEYS[0];

        let mut sget = AdminMessage::default();
        sget.payload = AdminPayload::GetConfigRequest(CONFIG_TYPE_SECURITY);
        let sout = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
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

        let mut sec = WireSecurityConfig::default();
        sec.has_public_key = true;
        sec.public_key = [0xDE; 32];
        sec.has_private_key = true;
        sec.private_key = [0xAD; 32];
        sec.admin_keys[0] = [0x11; 32];
        sec.admin_key_count = 1;
        let mut set = AdminMessage::default();
        set.payload = AdminPayload::SetConfig(ConfigPayload::Security(sec));
        set.has_session_passkey = true;
        set.session_passkey = passkey;
        let out = handle_admin(
            &mut state,
            &remote,
            &identity(),
            0x11,
            &DEFAULT_PSK,
            DEVICE_ROLE_ROUTER,
            &encode_admin_message(&set),
            3_100,
        );
        assert!(out.response.is_none());
        assert!(out.routing_ok);
        assert_eq!(state.public_key, [0x55; 32]);
        assert_eq!(state.private_key, [0x42; 32]);
        assert_eq!(state.admin_public_keys[0], [0x11; 32]);
        // admin_key-only Security set does not require reboot.
        assert!(out.reboot_seconds.is_none());
        assert!(state.pending_reboot_seconds.is_none());
    }
}
