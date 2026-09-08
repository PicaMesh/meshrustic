//! Static ring buffer for USB CDC log output.

use core::cell::RefCell;

use embassy_time::Instant;

const RING_SIZE: usize = 16384;

/// Max single USB log line: timestamp + RX metadata + full 255-byte hex payload.
const MAX_LOG_LINE: usize = 640;

struct LogRing {
    buf: [u8; RING_SIZE],
    head: usize,
    tail: usize,
}

impl LogRing {
    const fn new() -> Self {
        Self {
            buf: [0; RING_SIZE],
            head: 0,
            tail: 0,
        }
    }

    fn len(&self) -> usize {
        self.head.wrapping_sub(self.tail)
    }

    fn push(&mut self, data: &[u8]) {
        for &byte in data {
            if self.len() >= RING_SIZE {
                self.tail = self.tail.wrapping_add(1);
            }
            self.buf[self.head % RING_SIZE] = byte;
            self.head = self.head.wrapping_add(1);
        }
    }

    fn read_chunk(&mut self, out: &mut [u8]) -> usize {
        let available = self.len();
        if available == 0 {
            return 0;
        }
        let n = available.min(out.len());
        for (i, slot) in out.iter_mut().take(n).enumerate() {
            *slot = self.buf[(self.tail + i) % RING_SIZE];
        }
        self.tail = self.tail.wrapping_add(n);
        n
    }
}

static LOG_RING: critical_section::Mutex<RefCell<LogRing>> =
    critical_section::Mutex::new(RefCell::new(LogRing::new()));

pub fn push_bytes(data: &[u8]) {
    critical_section::with(|cs| LOG_RING.borrow(cs).borrow_mut().push(data));
}

fn monotonic_ms() -> u64 {
    Instant::now().as_millis()
}

fn push_u64(out: &mut [u8], mut n: u64) -> usize {
    if n == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
    }
    for i in 0..len {
        out[i] = tmp[len - 1 - i];
    }
    len
}

/// Write `[T=12345ms] ` prefix; returns next write offset.
fn line_prefix(line: &mut [u8]) -> usize {
    let prefix = b"[T=";
    line[..prefix.len()].copy_from_slice(prefix);
    let mut pos = prefix.len();
    put_u64(line, &mut pos, monotonic_ms());
    let suffix = b"ms] ";
    line[pos..pos + suffix.len()].copy_from_slice(suffix);
    pos + suffix.len()
}

fn finish_line(line: &mut [u8], pos: usize) {
    // Never index past the buffer: a truncated line beats a halted node.
    let pos = pos.min(line.len() - 1);
    line[pos] = b'\n';
    push_bytes(&line[..pos + 1]);
}

/// Bounded appends: text that would overflow the line buffer is truncated (keeping room for the
/// newline) instead of panicking. The version-resync line once overran its 128-byte buffer by
/// three bytes; with `panic_probe` that halted both nicenanos on the first resync.
fn put(line: &mut [u8], pos: &mut usize, text: &[u8]) {
    let room = line.len().saturating_sub(*pos + 1);
    let n = text.len().min(room);
    line[*pos..*pos + n].copy_from_slice(&text[..n]);
    *pos += n;
}

fn put_u32(line: &mut [u8], pos: &mut usize, n: u32) {
    let mut tmp = [0u8; 10];
    let k = push_u32(&mut tmp, n);
    put(line, pos, &tmp[..k]);
}

fn put_hex8(line: &mut [u8], pos: &mut usize, n: u32) {
    let mut tmp = [0u8; 8];
    push_hex_u32_8(&mut tmp, n);
    put(line, pos, &tmp);
}

fn put_hex4(line: &mut [u8], pos: &mut usize, n: u16) {
    let mut tmp = [0u8; 4];
    push_hex_u16_4(&mut tmp, n);
    put(line, pos, &tmp);
}

fn put_hex2(line: &mut [u8], pos: &mut usize, n: u8) {
    let mut tmp = [0u8; 2];
    push_hex_u8_2(&mut tmp, n);
    put(line, pos, &tmp);
}

fn put_i32(line: &mut [u8], pos: &mut usize, n: i32) {
    let mut tmp = [0u8; 11];
    let k = push_i32(&mut tmp, n);
    put(line, pos, &tmp[..k]);
}

fn put_u64(line: &mut [u8], pos: &mut usize, n: u64) {
    let mut tmp = [0u8; 20];
    let k = push_u64(&mut tmp, n);
    put(line, pos, &tmp[..k]);
}

pub fn push_line(content: &str) {
    let mut line = [0u8; 128];
    let mut pos = line_prefix(&mut line);
    let bytes = content.as_bytes();
    let n = bytes.len().min(line.len().saturating_sub(pos + 2));
    line[pos..pos + n].copy_from_slice(&bytes[..n]);
    pos += n;
    finish_line(&mut line, pos);
}

pub fn read_chunk(out: &mut [u8]) -> usize {
    critical_section::with(|cs| LOG_RING.borrow(cs).borrow_mut().read_chunk(out))
}

fn push_u32(out: &mut [u8], mut n: u32) -> usize {
    if n == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
    }
    for i in 0..len {
        out[i] = tmp[len - 1 - i];
    }
    len
}

fn push_i32(out: &mut [u8], n: i32) -> usize {
    if n < 0 {
        out[0] = b'-';
        return 1 + push_u32(&mut out[1..], (-n) as u32);
    }
    push_u32(out, n as u32)
}

fn push_hex_u32_8(out: &mut [u8], n: u32) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, slot) in out.iter_mut().enumerate().take(8) {
        *slot = HEX[((n >> (28 - i * 4)) & 0xF) as usize];
    }
    8
}

fn push_hex_u16_4(out: &mut [u8], n: u16) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, slot) in out.iter_mut().enumerate().take(4) {
        *slot = HEX[((n >> (12 - i * 4)) & 0xF) as usize];
    }
    4
}

fn push_hex_u8_2(out: &mut [u8], n: u8) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out[0] = HEX[(n >> 4) as usize];
    out[1] = HEX[(n & 0xF) as usize];
    2
}

fn push_freq_mhz(out: &mut [u8], freq_mhz: f32) -> usize {
    let millihz = (freq_mhz * 1000.0) as u32;
    let whole = millihz / 1000;
    let frac = millihz % 1000;
    let mut pos = push_u32(out, whole);
    out[pos] = b'.';
    pos += 1;
    if frac >= 100 {
        out[pos] = b'0' + (frac / 100) as u8;
        pos += 1;
    }
    if frac >= 10 {
        out[pos] = b'0' + ((frac / 10) % 10) as u8;
        pos += 1;
    }
    out[pos] = b'0' + (frac % 10) as u8;
    pos += 1;
    pos
}

/// Boot and identity lines for USB CDC.
pub mod mesh {
    use super::{finish_line, line_prefix, push_hex_u16_4, put, put_hex8, put_u32};

    pub fn node_id(node_num: u32) {
        let mut line = [0u8; 64];
        let mut pos = line_prefix(&mut line);
        let prefix = b"[meshrustic] nodeId !";
        put(&mut line, &mut pos, prefix);
        put_hex8(&mut line, &mut pos, node_num);
        finish_line(&mut line, pos);
    }

    /// Flash load result + configurable admin public-key count.
    /// `[meshrustic] reset reason=0x0004 (SREQ)` — RESETREAS bits as read at boot; SREQ is what
    /// the panic handler's `sys_reset` leaves behind, so a panic reboot is visible in the log.
    pub fn reset_reason(resetreas: u32) {
        let mut line = [0u8; 96];
        let mut pos = line_prefix(&mut line);
        put(&mut line, &mut pos, b"[meshrustic] reset reason=0x");
        let mut hex = [0u8; 4];
        push_hex_u16_4(&mut hex, (resetreas & 0xFFFF) as u16);
        put(&mut line, &mut pos, &hex);
        let named: &[(u32, &[u8])] = &[
            (1 << 0, b" RESETPIN"),
            (1 << 1, b" DOG"),
            (1 << 2, b" SREQ"),
            (1 << 3, b" LOCKUP"),
            (1 << 16, b" OFF"),
        ];
        let mut any = false;
        for (bit, name) in named {
            if resetreas & bit != 0 {
                put(&mut line, &mut pos, if any { b"," } else { b" (" });
                put(&mut line, &mut pos, &name[1..]);
                any = true;
            }
        }
        if any {
            put(&mut line, &mut pos, b")");
        } else {
            put(&mut line, &mut pos, b" (power-on)");
        }
        finish_line(&mut line, pos);
    }

    pub fn config_boot(from_flash: bool, admin_keys: u32) {
        let mut line = [0u8; 96];
        let mut pos = line_prefix(&mut line);
        let prefix = b"[store] NodeConfig ";
        put(&mut line, &mut pos, prefix);
        let src: &[u8] = if from_flash { b"flash" } else { b"defaults" };
        put(&mut line, &mut pos, src);
        let mid = b" admin_keys=";
        put(&mut line, &mut pos, mid);
        put_u32(&mut line, &mut pos, admin_keys);
        finish_line(&mut line, pos);
    }

    pub fn config_saved(admin_keys: u32) {
        let mut line = [0u8; 64];
        let mut pos = line_prefix(&mut line);
        let prefix = b"[store] NodeConfig saved admin_keys=";
        put(&mut line, &mut pos, prefix);
        put_u32(&mut line, &mut pos, admin_keys);
        finish_line(&mut line, pos);
    }
}

/// Mirror key `[Radio0]` defmt lines as plain text for USB CDC.
pub mod radio {
    use super::{
        finish_line, line_prefix, push_freq_mhz, push_hex_u32_8, push_hex_u8_2, push_u32, put,
        put_hex2, put_hex4, put_hex8, put_i32, put_u32, MAX_LOG_LINE,
    };

    pub fn init_ok(module: &str, node_num: u32, preset: &str, freq_mhz: f32) {
        let mut line = [0u8; 192];
        let mut pos = line_prefix(&mut line);
        let prefix = b"[Radio0] nodeId !";
        put(&mut line, &mut pos, prefix);
        put_hex8(&mut line, &mut pos, node_num);
        let mid = b" SX1262 (";
        put(&mut line, &mut pos, mid);
        let name = module.as_bytes();
        let name_len = name.len().min(line.len() - pos - 64);
        line[pos..pos + name_len].copy_from_slice(&name[..name_len]);
        pos += name_len;
        let mid2 = b") init OK, EU_868 ";
        put(&mut line, &mut pos, mid2);
        let preset_bytes = preset.as_bytes();
        let preset_len = preset_bytes.len().min(line.len() - pos - 24);
        line[pos..pos + preset_len].copy_from_slice(&preset_bytes[..preset_len]);
        pos += preset_len;
        let mid3 = b" @ ";
        put(&mut line, &mut pos, mid3);
        pos += push_freq_mhz(&mut line[pos..], freq_mhz);
        let suffix = b" MHz";
        put(&mut line, &mut pos, suffix);
        finish_line(&mut line, pos);
    }

    // One log line per modem parameter set; the argument list mirrors the printed fields.
    #[allow(clippy::too_many_arguments)]
    pub fn config_modem(
        sf: u8,
        bw_khz: u32,
        cr: u8,
        sync_word: u8,
        sx126x_sync: u16,
        preamble: u16,
        tx_power_dbm: i8,
        pa_duty: u8,
        pa_hp_max: u8,
        hop_limit: u8,
    ) {
        let mut line = [0u8; 192];
        let mut pos = line_prefix(&mut line);
        let prefix = b"[Radio0] modem SF";
        put(&mut line, &mut pos, prefix);
        put_u32(&mut line, &mut pos, sf as u32);
        let mid = b" BW";
        put(&mut line, &mut pos, mid);
        put_u32(&mut line, &mut pos, bw_khz);
        let mid2 = b"kHz CR4/";
        put(&mut line, &mut pos, mid2);
        put_u32(&mut line, &mut pos, cr as u32);
        let mid3 = b" sync=0x";
        put(&mut line, &mut pos, mid3);
        put_hex2(&mut line, &mut pos, sync_word);
        let mid3b = b" sx126x=0x";
        put(&mut line, &mut pos, mid3b);
        put_hex4(&mut line, &mut pos, sx126x_sync);
        let mid4 = b" preamble=";
        put(&mut line, &mut pos, mid4);
        put_u32(&mut line, &mut pos, preamble as u32);
        let mid5 = b" tx=";
        put(&mut line, &mut pos, mid5);
        put_i32(&mut line, &mut pos, tx_power_dbm as i32);
        let mid5b = b"dBm pa=";
        put(&mut line, &mut pos, mid5b);
        put_hex2(&mut line, &mut pos, pa_duty);
        let mid5c = b"/";
        put(&mut line, &mut pos, mid5c);
        put_hex2(&mut line, &mut pos, pa_hp_max);
        let mid5d = b" ocp=140mA hop=";
        put(&mut line, &mut pos, mid5d);
        put_u32(&mut line, &mut pos, hop_limit as u32);
        finish_line(&mut line, pos);
    }

    pub fn config_profile(module: &str, dio2_rf_switch: bool) {
        let mut line = [0u8; 128];
        let mut pos = line_prefix(&mut line);
        let prefix = b"[Radio0] profile ";
        put(&mut line, &mut pos, prefix);
        let name = module.as_bytes();
        let name_len = name.len().min(line.len() - pos - 24);
        line[pos..pos + name_len].copy_from_slice(&name[..name_len]);
        pos += name_len;
        let mid = if dio2_rf_switch {
            b" dio2_rf_switch=1"
        } else {
            b" dio2_rf_switch=0"
        };
        put(&mut line, &mut pos, mid);
        finish_line(&mut line, pos);
    }

    pub fn chip_status(mode: &str, rx_pkt: u16, crc_err: u16, hdr_err: u16) {
        let mut line = [0u8; 128];
        let mut pos = line_prefix(&mut line);
        let prefix = b"[Radio0] chip mode=";
        put(&mut line, &mut pos, prefix);
        let mode_bytes = mode.as_bytes();
        let mode_len = mode_bytes.len().min(line.len() - pos - 48);
        line[pos..pos + mode_len].copy_from_slice(&mode_bytes[..mode_len]);
        pos += mode_len;
        let mid = b" stats rx=";
        put(&mut line, &mut pos, mid);
        put_u32(&mut line, &mut pos, rx_pkt as u32);
        let mid2 = b" crc=";
        put(&mut line, &mut pos, mid2);
        put_u32(&mut line, &mut pos, crc_err as u32);
        let mid3 = b" hdr=";
        put(&mut line, &mut pos, mid3);
        put_u32(&mut line, &mut pos, hdr_err as u32);
        finish_line(&mut line, pos);
    }

    fn append_maybe_packet_header(
        line: &mut [u8],
        pos: &mut usize,
        parsed: &mesh_protocol::ParsedPacket,
    ) {
        append_slice(line, pos, b", maybe: id=0x");
        *pos += push_hex_u32_8(&mut line[*pos..], parsed.id);
        append_slice(line, pos, b" fr=!");
        *pos += push_hex_u32_8(&mut line[*pos..], parsed.from);
        append_slice(line, pos, b" to=!");
        *pos += push_hex_u32_8(&mut line[*pos..], parsed.to);
        append_slice(line, pos, b" WantAck=");
        append_flag(line, pos, parsed.want_ack);
        append_slice(line, pos, b" HopLim=");
        append_u32(line, pos, parsed.hop_limit as u32);
        append_slice(line, pos, b" Ch=0x");
        *pos += push_hex_u8_2(&mut line[*pos..], parsed.channel);
        if parsed.hop_start > 0 {
            append_slice(line, pos, b" hopStart=");
            append_u32(line, pos, parsed.hop_start as u32);
        }
        // Unicasts always show the field: a cleared next hop is a decision, not an omission.
        if parsed.next_hop != 0 || parsed.to != 0xFFFF_FFFF {
            append_slice(line, pos, b" nextHop=0x");
            *pos += push_hex_u8_2(&mut line[*pos..], parsed.next_hop);
        }
        if parsed.relay_node != 0 {
            append_slice(line, pos, b" relay=0x");
            *pos += push_hex_u8_2(&mut line[*pos..], parsed.relay_node);
        }
    }

    pub fn rx_crc_error(len: u8, rssi: i16, snr: i8, payload: &[u8]) {
        let mut line = [0u8; MAX_LOG_LINE];
        let mut pos = line_prefix(&mut line);
        append_slice(&mut line, &mut pos, b"[Radio0] RX crc error len=");
        append_u32(&mut line, &mut pos, len as u32);
        append_slice(&mut line, &mut pos, b" rssi=");
        put_i32(&mut line, &mut pos, rssi as i32);
        append_slice(&mut line, &mut pos, b" snr=");
        put_i32(&mut line, &mut pos, snr as i32);
        if let Ok(header) = mesh_protocol::PacketHeader::decode(payload) {
            append_maybe_packet_header(&mut line, &mut pos, &header.parse());
        }
        finish_line(&mut line, pos);
    }

    pub fn tx_cancelled(id: u32) {
        let mut line = [0u8; 96];
        let mut pos = line_prefix(&mut line);
        let prefix = b"[Radio0] TX cancelled id=0x";
        put(&mut line, &mut pos, prefix);
        put_hex8(&mut line, &mut pos, id);
        let tail = b" (copy heard before it left the queue)";
        put(&mut line, &mut pos, tail);
        finish_line(&mut line, pos);
    }

    pub fn tx_done(tx_id: Option<u32>, tx_to: Option<u32>, len: u8) {
        let mut line = [0u8; 128];
        let mut pos = line_prefix(&mut line);
        let prefix = b"[Radio0] TX done ";
        put(&mut line, &mut pos, prefix);
        put_u32(&mut line, &mut pos, len as u32);
        append_slice(&mut line, &mut pos, b" bytes");
        if let Some(id) = tx_id {
            append_slice(&mut line, &mut pos, b" id=0x");
            put_hex8(&mut line, &mut pos, id);
        }
        if let Some(to) = tx_to {
            append_slice(&mut line, &mut pos, b" target=!");
            put_hex8(&mut line, &mut pos, to);
        }
        finish_line(&mut line, pos);
    }

    fn append_slice(line: &mut [u8], pos: &mut usize, text: &[u8]) {
        let n = text.len().min(line.len().saturating_sub(*pos + 2));
        line[*pos..*pos + n].copy_from_slice(&text[..n]);
        *pos += n;
    }

    fn append_u32(line: &mut [u8], pos: &mut usize, n: u32) {
        *pos += push_u32(&mut line[*pos..], n);
    }

    fn append_flag(line: &mut [u8], pos: &mut usize, value: bool) {
        append_slice(line, pos, if value { b"1" } else { b"0" });
    }

    pub fn tx_enqueue(kind: &[u8], bytes: &[u8], len: u8, delay_ms: u32, node_num: u32) {
        let mut line = [0u8; MAX_LOG_LINE];
        let mut pos = line_prefix(&mut line);
        append_slice(&mut line, &mut pos, b"[Radio0] TX enqueue ");
        let kind_len = kind.len().min(16);
        append_slice(&mut line, &mut pos, &kind[..kind_len]);
        append_slice(&mut line, &mut pos, b" !");
        put_hex8(&mut line, &mut pos, node_num);
        append_slice(&mut line, &mut pos, b" len=");
        append_u32(&mut line, &mut pos, len as u32);
        if delay_ms > 0 {
            append_slice(&mut line, &mut pos, b" delay=");
            append_u32(&mut line, &mut pos, delay_ms);
            append_slice(&mut line, &mut pos, b"ms");
        }

        if let Ok(header) = mesh_protocol::PacketHeader::decode(&bytes[..len as usize]) {
            let parsed = header.parse();
            append_slice(&mut line, &mut pos, b" id=0x");
            put_hex8(&mut line, &mut pos, parsed.id);
            append_slice(&mut line, &mut pos, b" fr=0x");
            put_hex8(&mut line, &mut pos, parsed.from);
            append_slice(&mut line, &mut pos, b" to=0x");
            put_hex8(&mut line, &mut pos, parsed.to);
            append_slice(&mut line, &mut pos, b" WantAck=");
            append_flag(&mut line, &mut pos, parsed.want_ack);
            append_slice(&mut line, &mut pos, b" HopLim=");
            append_u32(&mut line, &mut pos, parsed.hop_limit as u32);
            append_slice(&mut line, &mut pos, b" Ch=0x");
            put_hex2(&mut line, &mut pos, parsed.channel);
            if parsed.hop_start > 0 {
                append_slice(&mut line, &mut pos, b" hopStart=");
                append_u32(&mut line, &mut pos, parsed.hop_start as u32);
            }
            if parsed.next_hop != 0 || parsed.to != 0xFFFF_FFFF {
                append_slice(&mut line, &mut pos, b" nextHop=0x");
                put_hex2(&mut line, &mut pos, parsed.next_hop);
            }
            if parsed.relay_node != 0 {
                append_slice(&mut line, &mut pos, b" relay=0x");
                put_hex2(&mut line, &mut pos, parsed.relay_node);
            }
        }

        append_slice(&mut line, &mut pos, b" data=");
        let room = line.len().saturating_sub(pos + 2);
        let show = (len as usize).min(room / 2);
        for &byte in &bytes[..show] {
            put_hex2(&mut line, &mut pos, byte);
        }
        finish_line(&mut line, pos);

        if show < len as usize {
            let mut cont = [0u8; MAX_LOG_LINE];
            let mut cpos = line_prefix(&mut cont);
            append_slice(&mut cont, &mut cpos, b"[Radio0] TX data cont=");
            let cont_room = cont.len().saturating_sub(cpos + 2);
            let cont_show = ((len as usize) - show).min(cont_room / 2);
            for &byte in &bytes[show..show + cont_show] {
                cpos += push_hex_u8_2(&mut cont[cpos..], byte);
            }
            finish_line(&mut cont, cpos);
        }
    }

    pub fn rx_packet(
        parsed: &mesh_protocol::ParsedPacket,
        rssi: i16,
        snr: i8,
        decode: mesh_routing::RxDecodeInfo,
        duplicate: bool,
        rate_limited: bool,
    ) {
        let mut line = [0u8; MAX_LOG_LINE];
        let mut pos = line_prefix(&mut line);
        append_slice(&mut line, &mut pos, b"[Radio0] Packet (id=0x");
        put_hex8(&mut line, &mut pos, parsed.id);
        append_slice(&mut line, &mut pos, b" fr=0x");
        put_hex8(&mut line, &mut pos, parsed.from);
        append_slice(&mut line, &mut pos, b" to=0x");
        put_hex8(&mut line, &mut pos, parsed.to);
        append_slice(&mut line, &mut pos, b" WantAck=");
        append_flag(&mut line, &mut pos, parsed.want_ack);
        append_slice(&mut line, &mut pos, b" HopLim=");
        append_u32(&mut line, &mut pos, parsed.hop_limit as u32);
        append_slice(&mut line, &mut pos, b" Ch=0x");
        put_hex2(&mut line, &mut pos, parsed.channel);
        if parsed.hop_start > 0 {
            append_slice(&mut line, &mut pos, b" hopStart=");
            append_u32(&mut line, &mut pos, parsed.hop_start as u32);
        }
        if parsed.next_hop != 0 || parsed.to != 0xFFFF_FFFF {
            append_slice(&mut line, &mut pos, b" nextHop=0x");
            put_hex2(&mut line, &mut pos, parsed.next_hop);
        }
        if parsed.relay_node != 0 {
            append_slice(&mut line, &mut pos, b" relay=0x");
            put_hex2(&mut line, &mut pos, parsed.relay_node);
        }
        if parsed.via_mqtt {
            append_slice(&mut line, &mut pos, b" viaMQTT=1");
        }
        append_slice(&mut line, &mut pos, b" rxRSSI=");
        put_i32(&mut line, &mut pos, rssi as i32);
        append_slice(&mut line, &mut pos, b" rxSNR=");
        put_i32(&mut line, &mut pos, snr as i32);
        if duplicate {
            append_slice(&mut line, &mut pos, b" dupe=1");
        }
        if rate_limited {
            append_slice(&mut line, &mut pos, b" rateLimited=1");
        }

        use mesh_routing::RxPayloadSummary;
        match decode.summary {
            RxPayloadSummary::Encrypted => {
                append_slice(&mut line, &mut pos, b" encrypted len=");
                append_u32(&mut line, &mut pos, decode.payload_len as u32);
            }
            RxPayloadSummary::UnknownPort { portnum, len } => {
                append_slice(&mut line, &mut pos, b" Portnum=");
                append_u32(&mut line, &mut pos, portnum);
                append_slice(&mut line, &mut pos, b" len=");
                append_u32(&mut line, &mut pos, len as u32);
            }
            RxPayloadSummary::Text {
                len,
                preview,
                preview_len,
            } => {
                append_slice(&mut line, &mut pos, b" Portnum=");
                append_u32(
                    &mut line,
                    &mut pos,
                    decode
                        .portnum
                        .unwrap_or(mesh_protocol::num::TEXT_MESSAGE_APP),
                );
                append_slice(&mut line, &mut pos, b" text=\"");
                let n = preview_len as usize;
                append_slice(&mut line, &mut pos, &preview[..n]);
                append_slice(&mut line, &mut pos, b"\" len=");
                append_u32(&mut line, &mut pos, len as u32);
            }
            RxPayloadSummary::Topology {
                neighbors,
                topo_v,
                sr_active,
            } => {
                append_slice(&mut line, &mut pos, b" Portnum=88 topo neighbors=");
                append_u32(&mut line, &mut pos, neighbors as u32);
                append_slice(&mut line, &mut pos, b" v=");
                append_u32(&mut line, &mut pos, topo_v as u32);
                append_slice(
                    &mut line,
                    &mut pos,
                    if sr_active { b" SR=1" } else { b" SR=0" },
                );
            }
            RxPayloadSummary::Position {
                latitude_i,
                longitude_i,
            } => {
                append_slice(&mut line, &mut pos, b" Portnum=3 lat_i=");
                put_i32(&mut line, &mut pos, latitude_i);
                append_slice(&mut line, &mut pos, b" lon_i=");
                put_i32(&mut line, &mut pos, longitude_i);
            }
            RxPayloadSummary::Routing { error_reason } => {
                append_slice(&mut line, &mut pos, b" Portnum=5 error=");
                append_u32(&mut line, &mut pos, error_reason);
            }
            RxPayloadSummary::NodeInfo {
                short_name,
                short_len,
                role,
            } => {
                append_slice(&mut line, &mut pos, b" Portnum=4 short=\"");
                let n = short_len as usize;
                append_slice(&mut line, &mut pos, &short_name[..n]);
                append_slice(&mut line, &mut pos, b"\" role=");
                append_u32(&mut line, &mut pos, role);
            }
            RxPayloadSummary::Traceroute {
                route,
                snr,
                route_back,
                snr_back,
            } => {
                append_slice(&mut line, &mut pos, b" Portnum=70 route=");
                append_u32(&mut line, &mut pos, route as u32);
                append_slice(&mut line, &mut pos, b" snr=");
                append_u32(&mut line, &mut pos, snr as u32);
                append_slice(&mut line, &mut pos, b" back=");
                append_u32(&mut line, &mut pos, route_back as u32);
                append_slice(&mut line, &mut pos, b" snrBack=");
                append_u32(&mut line, &mut pos, snr_back as u32);
            }
            RxPayloadSummary::DeviceTelemetry {
                battery_level,
                voltage_mv,
            } => {
                append_slice(&mut line, &mut pos, b" Portnum=67 batt=");
                append_u32(&mut line, &mut pos, battery_level);
                append_slice(&mut line, &mut pos, b" mV=");
                append_u32(&mut line, &mut pos, voltage_mv);
            }
            RxPayloadSummary::Raw {
                portnum,
                len,
                hex,
                hex_len,
            } => {
                append_slice(&mut line, &mut pos, b" Portnum=");
                append_u32(&mut line, &mut pos, portnum);
                append_slice(&mut line, &mut pos, b" len=");
                append_u32(&mut line, &mut pos, len as u32);
                append_slice(&mut line, &mut pos, b" hex=");
                for &byte in &hex[..hex_len as usize] {
                    put_hex2(&mut line, &mut pos, byte);
                }
            }
        }
        put(&mut line, &mut pos, b")");
        finish_line(&mut line, pos);
    }

    pub fn warn(msg: &str) {
        let mut line = [0u8; MAX_LOG_LINE];
        let mut pos = line_prefix(&mut line);
        let prefix = b"[Radio0] ";
        put(&mut line, &mut pos, prefix);
        let bytes = msg.as_bytes();
        let n = bytes.len().min(line.len() - pos - 2);
        line[pos..pos + n].copy_from_slice(&bytes[..n]);
        pos += n;
        finish_line(&mut line, pos);
    }
}

pub mod rate_limit {
    use super::{finish_line, line_prefix, put, put_hex8};

    pub fn drop_from(from: u32) {
        let mut line = [0u8; 64];
        let mut pos = line_prefix(&mut line);
        let msg = b"[RateLimit] drop from !";
        put(&mut line, &mut pos, msg);
        put_hex8(&mut line, &mut pos, from);
        finish_line(&mut line, pos);
    }
}

pub mod qos {
    use super::{finish_line, line_prefix, put, put_hex8, put_u32};

    pub fn drop_relay(from: u32, chutil_pct: f32) {
        let mut line = [0u8; 80];
        let mut pos = line_prefix(&mut line);
        let prefix = b"[QoS] Drop relay !";
        put(&mut line, &mut pos, prefix);
        put_hex8(&mut line, &mut pos, from);
        let mid = b" chutil ";
        put(&mut line, &mut pos, mid);
        put_u32(&mut line, &mut pos, chutil_pct as u32);
        put(&mut line, &mut pos, b"%");
        finish_line(&mut line, pos);
    }
}

pub mod airtime {
    use super::{finish_line, line_prefix, put, put_u32};

    pub fn duty_cycle_blocked(duty_pct: f32, limit_pct: f32, queued: u8) {
        let mut line = [0u8; 96];
        let mut pos = line_prefix(&mut line);
        let prefix = b"[AirTime] TX blocked duty=";
        put(&mut line, &mut pos, prefix);
        put_u32(&mut line, &mut pos, duty_pct as u32);
        let mid = b"% limit=";
        put(&mut line, &mut pos, mid);
        put_u32(&mut line, &mut pos, limit_pct as u32);
        let tail = b"% queued=";
        put(&mut line, &mut pos, tail);
        put_u32(&mut line, &mut pos, queued as u32);
        finish_line(&mut line, pos);
    }
}

pub mod battery {
    use super::{finish_line, line_prefix, put, put_u32};

    pub fn reading(voltage_mv: u32, battery_level: u32, raw_adc: u32) {
        let mut line = [0u8; 96];
        let mut pos = line_prefix(&mut line);
        let prefix = b"[Battery] ";
        put(&mut line, &mut pos, prefix);
        put_u32(&mut line, &mut pos, voltage_mv);
        let mid = b" mV level=";
        put(&mut line, &mut pos, mid);
        put_u32(&mut line, &mut pos, battery_level);
        let raw = b" raw=";
        put(&mut line, &mut pos, raw);
        put_u32(&mut line, &mut pos, raw_adc);
        finish_line(&mut line, pos);
    }
}

/// Signal-routing decision logs (`[SR]` prefix).
pub mod sr {
    use super::{finish_line, line_prefix, put, put_hex2, put_hex8, put_i32, put_u32};
    use mesh_routing::{
        RelayReason, RelayRetxCancelReason, Router, SrLogEvent, SrSkipReason, T1CancelReason,
        TopologyLogSink,
    };

    fn emit_topology_event(event: SrLogEvent) {
        match event {
            SrLogEvent::NetworkTopologyHeader {
                direct_neighbors,
                graph_nodes,
                downstream_routes,
            } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Network Topology: ";
                put(&mut line, &mut pos, prefix);
                put_u32(&mut line, &mut pos, direct_neighbors as u32);
                let mid = b" direct, ";
                put(&mut line, &mut pos, mid);
                put_u32(&mut line, &mut pos, graph_nodes as u32);
                let mid2 = b" graph nodes, ";
                put(&mut line, &mut pos, mid2);
                put_u32(&mut line, &mut pos, downstream_routes as u32);
                let tail = b" downstream routes";
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            SrLogEvent::NetworkTopologyUs { node_id } => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] !";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, node_id);
                let tail = b" (us)";
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            SrLogEvent::NetworkTopologyEmpty => {
                let mut line = [0u8; 64];
                let mut pos = line_prefix(&mut line);
                let msg = b"[SR]   (no direct neighbors)";
                put(&mut line, &mut pos, msg);
                finish_line(&mut line, pos);
            }
            SrLogEvent::NetworkTopologyNeighbor {
                node_id,
                rssi,
                snr,
                hears_us,
                last,
            } => {
                let mut line = [0u8; 160];
                let mut pos = line_prefix(&mut line);
                let branch = if last {
                    b"[SR]   \\- !"
                } else {
                    b"[SR]   +- !"
                };
                put(&mut line, &mut pos, branch);
                put_hex8(&mut line, &mut pos, node_id);
                let mid = b": RSSI=";
                put(&mut line, &mut pos, mid);
                put_i32(&mut line, &mut pos, rssi as i32);
                let mid2 = b" SNR=";
                put(&mut line, &mut pos, mid2);
                put_i32(&mut line, &mut pos, snr as i32);
                if hears_us {
                    let tail = b" hearsUs";
                    put(&mut line, &mut pos, tail);
                }
                finish_line(&mut line, pos);
            }
            SrLogEvent::NetworkTopologyMirrored {
                continue_pipe,
                node_id,
                hears_us,
                last_mirrored,
            } => {
                let mut line = [0u8; 160];
                let mut pos = line_prefix(&mut line);
                let indent = if continue_pipe {
                    b"[SR]   |   "
                } else {
                    b"[SR]       "
                };
                put(&mut line, &mut pos, indent);
                let branch = if last_mirrored { b"\\- !" } else { b"+- !" };
                put(&mut line, &mut pos, branch);
                put_hex8(&mut line, &mut pos, node_id);
                let mid = b" via topo";
                put(&mut line, &mut pos, mid);
                if hears_us {
                    let tail = b" hearsUs";
                    put(&mut line, &mut pos, tail);
                }
                finish_line(&mut line, pos);
            }
            SrLogEvent::NetworkTopologyDownstreamHeader { count } => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Downstream routes: ";
                put(&mut line, &mut pos, prefix);
                put_u32(&mut line, &mut pos, count as u32);
                finish_line(&mut line, pos);
            }
            SrLogEvent::NetworkTopologyDownstreamGroup {
                relay,
                destinations,
                len,
                last: _,
            } => {
                // ~33 bytes of prefix plus 10 per destination: 12 ids need ~153 bytes.
                let mut line = [0u8; 256];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR]   !";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, relay);
                put(&mut line, &mut pos, b":");
                for dest in destinations.iter().take(len as usize) {
                    let sep = b" !";
                    put(&mut line, &mut pos, sep);
                    put_hex8(&mut line, &mut pos, *dest);
                }
                finish_line(&mut line, pos);
            }
            SrLogEvent::TopologyLoggingComplete => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                let msg = b"[SR] Topology logging complete";
                put(&mut line, &mut pos, msg);
                finish_line(&mut line, pos);
            }
            _ => {}
        }
    }

    struct UsbTopologySink;

    impl TopologyLogSink for UsbTopologySink {
        fn emit(&mut self, event: SrLogEvent) {
            emit_topology_event(event);
        }
    }

    /// Stream the full periodic topology dump directly to USB (bypasses SR log ring).
    pub fn emit_topology_dump(router: &Router) {
        let mut sink = UsbTopologySink;
        router.emit_topology_log(&mut sink);
    }

    pub fn emit(event: SrLogEvent) {
        match event {
            SrLogEvent::ModuleInitialized { version } => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Module initialized (version ";
                put(&mut line, &mut pos, prefix);
                put_u32(&mut line, &mut pos, version as u32);
                put(&mut line, &mut pos, b")");
                finish_line(&mut line, pos);
            }
            SrLogEvent::UsingNeighborGraph => {
                let mut line = [0u8; 64];
                let mut pos = line_prefix(&mut line);
                let msg = b"[SR] Using NeighborGraph";
                put(&mut line, &mut pos, msg);
                finish_line(&mut line, pos);
            }
            SrLogEvent::Config {
                broadcast_secs,
                dirty_secs,
                node_ttl_secs,
                max_hops,
            } => {
                let mut line = [0u8; 160];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Config: broadcastSecs=";
                put(&mut line, &mut pos, prefix);
                put_u32(&mut line, &mut pos, broadcast_secs as u32);
                let mid = b" dirtyBroadcastSecs=";
                put(&mut line, &mut pos, mid);
                put_u32(&mut line, &mut pos, dirty_secs as u32);
                let mid2 = b" nodeTtlSecs=";
                put(&mut line, &mut pos, mid2);
                put_u32(&mut line, &mut pos, node_ttl_secs);
                let mid3 = b" maxHops=";
                put(&mut line, &mut pos, mid3);
                put_u32(&mut line, &mut pos, max_hops as u32);
                finish_line(&mut line, pos);
            }
            SrLogEvent::DirectNeighbor {
                node_id,
                rssi,
                snr,
                is_new,
            } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                if is_new {
                    let prefix = b"[SR] Direct neighbor !";
                    put(&mut line, &mut pos, prefix);
                } else {
                    let prefix = b"[SR] Direct contact !";
                    put(&mut line, &mut pos, prefix);
                }
                put_hex8(&mut line, &mut pos, node_id);
                let mid = b" RSSI=";
                put(&mut line, &mut pos, mid);
                put_i32(&mut line, &mut pos, rssi as i32);
                let tail = b" SNR=";
                put(&mut line, &mut pos, tail);
                put_i32(&mut line, &mut pos, snr as i32);
                finish_line(&mut line, pos);
            }
            SrLogEvent::PacketFrom {
                from,
                relay_node,
                hop_start,
                hop_limit,
                direct,
            } => {
                let mut line = [0u8; 160];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Packet from 0x";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, from);
                let mid = b": relay=0x";
                put(&mut line, &mut pos, mid);
                put_hex2(&mut line, &mut pos, relay_node);
                let mid2 = b" hopStart=";
                put(&mut line, &mut pos, mid2);
                put_u32(&mut line, &mut pos, hop_start as u32);
                let mid3 = b" hopLimit=";
                put(&mut line, &mut pos, mid3);
                put_u32(&mut line, &mut pos, hop_limit as u32);
                let tail = if direct { b" direct=1" } else { b" direct=0" };
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            SrLogEvent::SlotScheduling {
                id,
                half_airtime_ms,
                candidates,
                slot_index,
                ranked,
                ranked_len,
                reason,
                evaluated,
                evaluated_len,
                pre_covered,
            } => {
                let mut line = [0u8; 320];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Slot scheduling for pkt 0x";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, id);
                let mid = b": halfAirtime=";
                put(&mut line, &mut pos, mid);
                put_u32(&mut line, &mut pos, half_airtime_ms);
                let tail = b"ms, candidates=";
                put(&mut line, &mut pos, tail);
                put_u32(&mut line, &mut pos, candidates as u32);
                put(&mut line, &mut pos, b", pre=");
                put_u32(&mut line, &mut pos, pre_covered as u32);
                let tail2 = b", slot=";
                put(&mut line, &mut pos, tail2);
                put_u32(&mut line, &mut pos, slot_index as u32);
                let via: &[u8] = match reason {
                    RelayReason::None => b"",
                    RelayReason::Ranked => b", via=rank",
                    RelayReason::Downstream => b", via=downstream",
                    RelayReason::Sparse => b", via=sparse",
                    RelayReason::UnicastCost => b", via=cost",
                };
                put(&mut line, &mut pos, via);
                if ranked_len > 0 {
                    let order = b", order=";
                    put(&mut line, &mut pos, order);
                    for (i, node) in ranked.iter().take(ranked_len as usize).enumerate() {
                        if i > 0 {
                            put(&mut line, &mut pos, b">");
                        }
                        put(&mut line, &mut pos, b"!");
                        put_hex8(&mut line, &mut pos, *node);
                    }
                }
                if evaluated_len > 0 {
                    // Ranking inputs: !node(unique/total coverage,cost bucket); unicast costs carry
                    // tier bits and no coverage.
                    let cand = b", cand=";
                    put(&mut line, &mut pos, cand);
                    for (i, (node, cov, total, cost)) in
                        evaluated.iter().take(evaluated_len as usize).enumerate()
                    {
                        if i > 0 {
                            put(&mut line, &mut pos, b",");
                        }
                        put(&mut line, &mut pos, b"!");
                        put_hex8(&mut line, &mut pos, *node);
                        put(&mut line, &mut pos, b"(");
                        put_u32(&mut line, &mut pos, *cov as u32);
                        put(&mut line, &mut pos, b"/");
                        put_u32(&mut line, &mut pos, *total as u32);
                        put(&mut line, &mut pos, b",");
                        put_u32(&mut line, &mut pos, *cost as u32);
                        put(&mut line, &mut pos, b")");
                    }
                }
                finish_line(&mut line, pos);
            }
            SrLogEvent::RelayCommitted {
                id,
                heard_from,
                delay_ms,
            } => {
                let mut line = [0u8; 160];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Committed relay for packet 0x";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, id);
                let mid = b" (heardFrom 0x";
                put(&mut line, &mut pos, mid);
                put_hex8(&mut line, &mut pos, heard_from);
                let tail = b", delay ";
                put(&mut line, &mut pos, tail);
                put_u32(&mut line, &mut pos, delay_ms);
                let ms = b"ms)";
                put(&mut line, &mut pos, ms);
                finish_line(&mut line, pos);
            }
            SrLogEvent::BroadcastDupeCancel { id, from } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Broadcast dupe pkt=0x";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, id);
                let mid = b" from !";
                put(&mut line, &mut pos, mid);
                put_hex8(&mut line, &mut pos, from);
                let tail = b" - canceling relay";
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            SrLogEvent::RelaySkip { from, reason } => {
                let reason_text: &[u8] = match reason {
                    SrSkipReason::WireGate => b"wire gate",
                    SrSkipReason::Qos => b"QoS",
                    SrSkipReason::Duplicate => b"duplicate",
                    SrSkipReason::RateLimited => b"rate limit",
                    SrSkipReason::OwnRebroadcast => b"own rebroadcast",
                    SrSkipReason::UnknownDestination => b"unknown dest",
                    SrSkipReason::BetterNeighbor => b"better neighbor",
                    SrSkipReason::NextHopIsRelayer => b"next hop is relayer",
                    SrSkipReason::DeadEndHop => b"dead end hop",
                    SrSkipReason::UnicastCovered => b"unicast covered",
                    SrSkipReason::NoRelayPath => b"no relay path",
                    SrSkipReason::ReplyRetracesLink => b"reply retraces link",
                    SrSkipReason::UnverifiedBacktrack => b"guessed route runs back",
                    SrSkipReason::AlreadyCovered => b"no slot given, no witness owed",
                };
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Skip relay !";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, from);
                let mid = b" reason=";
                put(&mut line, &mut pos, mid);
                let n = reason_text.len().min(line.len() - pos - 2);
                line[pos..pos + n].copy_from_slice(&reason_text[..n]);
                pos += n;
                finish_line(&mut line, pos);
            }
            SrLogEvent::TopologySending {
                node_id,
                neighbors,
                packets,
                topo_v,
            } => {
                let mut line = [0u8; 160];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] SENDING: Broadcasting ";
                put(&mut line, &mut pos, prefix);
                put_u32(&mut line, &mut pos, neighbors as u32);
                let mid = b" neighbors in ";
                put(&mut line, &mut pos, mid);
                put_u32(&mut line, &mut pos, packets as u32);
                let mid2 = b" packet(s) from !";
                put(&mut line, &mut pos, mid2);
                put_hex8(&mut line, &mut pos, node_id);
                let tail = b" (version ";
                put(&mut line, &mut pos, tail);
                put_u32(&mut line, &mut pos, topo_v as u32);
                put(&mut line, &mut pos, b")");
                finish_line(&mut line, pos);
            }
            SrLogEvent::TopologyDirtySending { delay_ms } => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                let msg = b"[SR] Topology dirty - early broadcast in ";
                put(&mut line, &mut pos, msg);
                put_u32(&mut line, &mut pos, delay_ms);
                let tail = b"ms";
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            SrLogEvent::NodeInfoReplyDelayed { delay_ms } => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                let msg = b"[SR] NodeInfo reply in ";
                put(&mut line, &mut pos, msg);
                put_u32(&mut line, &mut pos, delay_ms);
                let tail = b"ms";
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            SrLogEvent::EmptyBootBroadcast => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                let msg = b"[SR] Sending empty boot broadcast to bootstrap topology";
                put(&mut line, &mut pos, msg);
                finish_line(&mut line, pos);
            }
            SrLogEvent::TopologyProcessing {
                from,
                neighbors,
                topo_v,
                sr_active,
                relay_node,
            } => {
                let mut line = [0u8; 192];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Processing topology from !";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, from);
                let mid = b": ";
                put(&mut line, &mut pos, mid);
                put_u32(&mut line, &mut pos, neighbors as u32);
                let mid2 = b" neighbors (version ";
                put(&mut line, &mut pos, mid2);
                put_u32(&mut line, &mut pos, topo_v as u32);
                if sr_active {
                    let mid3 = b", SR-active, relay=0x";
                    put(&mut line, &mut pos, mid3);
                } else {
                    let mid3 = b", passive, relay=0x";
                    put(&mut line, &mut pos, mid3);
                }
                put_hex2(&mut line, &mut pos, relay_node);
                put(&mut line, &mut pos, b")");
                finish_line(&mut line, pos);
            }
            SrLogEvent::TopologyReceived {
                from,
                neighbors,
                routing_version,
                sr_active,
            } => {
                let mut line = [0u8; 160];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] RECEIVED: !";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, from);
                let mid = b" reports ";
                put(&mut line, &mut pos, mid);
                put_u32(&mut line, &mut pos, neighbors as u32);
                let mid2 = b" neighbors (SR v";
                put(&mut line, &mut pos, mid2);
                put_u32(&mut line, &mut pos, routing_version as u32);
                if sr_active {
                    let tail = b", active)";
                    put(&mut line, &mut pos, tail);
                } else {
                    let tail = b", passive)";
                    put(&mut line, &mut pos, tail);
                }
                finish_line(&mut line, pos);
            }
            SrLogEvent::TopologyDownstreamSkippedAsymmetric {
                sender,
                destination,
            } => {
                let mut line = [0u8; 160];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Skipping asymmetric downstream !";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, sender);
                let mid = b" -> !";
                put(&mut line, &mut pos, mid);
                put_hex8(&mut line, &mut pos, destination);
                let tail = b" (hears_us=false)";
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            SrLogEvent::TopologyStale {
                from,
                received,
                last,
            } => {
                let mut line = [0u8; 160];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Ignoring stale topology broadcast from !";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, from);
                let mid = b" (version ";
                put(&mut line, &mut pos, mid);
                put_u32(&mut line, &mut pos, received as u32);
                let tail = b", last processed ";
                put(&mut line, &mut pos, tail);
                put_u32(&mut line, &mut pos, last as u32);
                put(&mut line, &mut pos, b")");
                finish_line(&mut line, pos);
            }
            SrLogEvent::TopologyDirtyFromNeighbor { from } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Empty broadcast from direct SR neighbor !";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, from);
                let tail = b" - scheduling topology reply on next maintenance";
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            event @ (SrLogEvent::NetworkTopologyHeader { .. }
            | SrLogEvent::NetworkTopologyUs { .. }
            | SrLogEvent::NetworkTopologyEmpty
            | SrLogEvent::NetworkTopologyNeighbor { .. }
            | SrLogEvent::NetworkTopologyMirrored { .. }
            | SrLogEvent::NetworkTopologyDownstreamHeader { .. }
            | SrLogEvent::NetworkTopologyDownstreamGroup { .. }
            | SrLogEvent::TopologyLoggingComplete) => emit_topology_event(event),
            SrLogEvent::TopologyVersionResync {
                from,
                received,
                last,
            } => {
                let mut line = [0u8; 192];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Topology version resync from !";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, from);
                let mid = b": accepted version ";
                put(&mut line, &mut pos, mid);
                put_u32(&mut line, &mut pos, received as u32);
                let tail = b" after stored ";
                put(&mut line, &mut pos, tail);
                put_u32(&mut line, &mut pos, last as u32);
                let tail2 = b" (peer reboot or two silent intervals)";
                put(&mut line, &mut pos, tail2);
                finish_line(&mut line, pos);
            }
            SrLogEvent::UnicastDestHeardDirect { id, wait_ms } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Unicast 0x";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, id);
                let mid = b": destination hears the source, waiting ";
                put(&mut line, &mut pos, mid);
                put_u32(&mut line, &mut pos, wait_ms);
                let tail = b"ms for its ACK before relaying";
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            SrLogEvent::UnicastReplyCancel { id } => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Unicast reply heard for 0x";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, id);
                let tail = b" - canceling relay";
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            SrLogEvent::BootstrapReplyRateLimited => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                let msg = b"[SR] Bootstrap reply rate-limited (list sent within the last minute)";
                put(&mut line, &mut pos, msg);
                finish_line(&mut line, pos);
            }
            SrLogEvent::BootstrapReplyAlreadyAnswered => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                let msg =
                    b"[SR] Bootstrap reply dropped: a list already went out after the request";
                put(&mut line, &mut pos, msg);
                finish_line(&mut line, pos);
            }
            SrLogEvent::RadioReconfigured { dropped } => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                let msg = b"[SR] Preset applied: dropped ";
                put(&mut line, &mut pos, msg);
                put_u32(&mut line, &mut pos, dropped as u32);
                let tail = b" pending TX timed for the old preset";
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            SrLogEvent::GraphAged { before, after } => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                if before != after {
                    let prefix = b"[SR] Graph aged: ";
                    put(&mut line, &mut pos, prefix);
                    put_u32(&mut line, &mut pos, before as u32);
                    let mid = b" -> ";
                    put(&mut line, &mut pos, mid);
                    put_u32(&mut line, &mut pos, after as u32);
                    let tail = b" direct neighbors";
                    put(&mut line, &mut pos, tail);
                } else {
                    let msg = b"[SR] Graph aged (no direct neighbor count change)";
                    put(&mut line, &mut pos, msg);
                }
                finish_line(&mut line, pos);
            }
            SrLogEvent::TopologyChangedNewNeighbor { node_id, total } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Topology changed: new neighbor !";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, node_id);
                let mid = b" (direct neighbors: ";
                put(&mut line, &mut pos, mid);
                put_u32(&mut line, &mut pos, total as u32);
                put(&mut line, &mut pos, b")");
                finish_line(&mut line, pos);
            }
            SrLogEvent::RelayConfirmedHearsUs { node_id } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Confirmed hears_us via relay from !";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, node_id);
                finish_line(&mut line, pos);
            }
            SrLogEvent::DirectNeighborLostDirty => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let msg = b"[SR] Direct neighbor lost during aging - marking topology dirty";
                put(&mut line, &mut pos, msg);
                finish_line(&mut line, pos);
            }
            SrLogEvent::NodeInfoReceived {
                from,
                short_len,
                short_name,
                role,
                is_new,
            } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] NodeInfo from !";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, from);
                let mid = b" short=";
                put(&mut line, &mut pos, mid);
                let n = (short_len as usize)
                    .min(5)
                    .min(line.len().saturating_sub(pos + 2));
                line[pos..pos + n].copy_from_slice(&short_name[..n]);
                pos += n;
                let mid2 = b" role=";
                put(&mut line, &mut pos, mid2);
                put_u32(&mut line, &mut pos, role);
                if is_new {
                    let tail = b" new=1";
                    put(&mut line, &mut pos, tail);
                }
                finish_line(&mut line, pos);
            }
            SrLogEvent::CoverageFor { neighbor } => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                put(&mut line, &mut pos, b"[SR] Relaying for !");
                put_hex8(&mut line, &mut pos, neighbor);
                put(&mut line, &mut pos, b" (the transmitter did not reach it)");
                finish_line(&mut line, pos);
            }
            SrLogEvent::RouteNextHop {
                destination,
                next_hop,
                cost_x100,
                hops,
                verified,
            } => {
                let mut line = [0u8; 160];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Route to !";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, destination);
                let mid = b" via !";
                put(&mut line, &mut pos, mid);
                put_hex8(&mut line, &mut pos, next_hop);
                let tail = b" cost=";
                put(&mut line, &mut pos, tail);
                put_u32(&mut line, &mut pos, cost_x100 as u32);
                put(&mut line, &mut pos, b" hops=");
                put_u32(&mut line, &mut pos, hops as u32);
                if !verified {
                    put(&mut line, &mut pos, b" unverified");
                }
                finish_line(&mut line, pos);
            }
            SrLogEvent::UnicastDesignated {
                next_hop,
                is_us,
                sr_active,
                slot,
                slot_delay_ms,
            } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Unicast next hop 0x";
                put(&mut line, &mut pos, prefix);
                put_hex2(&mut line, &mut pos, next_hop);
                let who: &[u8] = if is_us {
                    b" (us) slot 0"
                } else if sr_active {
                    b" (SR peer) owns slot 0, ours="
                } else {
                    b" (stock/unknown) owns slot 0, ours="
                };
                put(&mut line, &mut pos, who);
                if !is_us {
                    put_u32(&mut line, &mut pos, slot as u32);
                    let mid = b" after ";
                    put(&mut line, &mut pos, mid);
                    put_u32(&mut line, &mut pos, slot_delay_ms);
                    let tail = b"ms";
                    put(&mut line, &mut pos, tail);
                }
                finish_line(&mut line, pos);
            }
            SrLogEvent::UnicastDupeCancel { id, from } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Unicast dupe pkt=0x";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, id);
                let mid = b" from !";
                put(&mut line, &mut pos, mid);
                put_hex8(&mut line, &mut pos, from);
                let tail = b" - canceling relay";
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            SrLogEvent::RelayRetxArmed { id, next_hop } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Relay retx armed for 0x";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, id);
                let mid = b" via next hop 0x";
                put(&mut line, &mut pos, mid);
                put_hex2(&mut line, &mut pos, next_hop);
                finish_line(&mut line, pos);
            }
            SrLogEvent::RelayRetxFired { id, fallback } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Relay retx for 0x";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, id);
                let tail: &[u8] = if fallback {
                    b" (last try, next hop cleared - flooding)"
                } else {
                    b" (designated next hop silent)"
                };
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            SrLogEvent::RelayRetxCanceled { id, reason } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] Relay retx canceled for 0x";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, id);
                let tail: &[u8] = match reason {
                    RelayRetxCancelReason::CopyHeard => b" reason=copy heard",
                    RelayRetxCancelReason::ReplyHeard => b" reason=reply heard",
                };
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            SrLogEvent::T1Scheduled { id, delay_ms } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] T1 scheduled for 0x";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, id);
                let mid = b" fires in ";
                put(&mut line, &mut pos, mid);
                put_u32(&mut line, &mut pos, delay_ms);
                let tail = b"ms";
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
            SrLogEvent::T1Fired { id } => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] T1 firing for 0x";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, id);
                finish_line(&mut line, pos);
            }
            SrLogEvent::T1Canceled { id, reason } => {
                let reason_text: &[u8] = match reason {
                    T1CancelReason::RelayHeard => b"relay heard",
                    T1CancelReason::OwnTransmission => b"we transmitted it ourselves",
                };
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] T1 canceled for 0x";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, id);
                let mid = b" reason=";
                put(&mut line, &mut pos, mid);
                let n = reason_text.len().min(line.len() - pos - 2);
                line[pos..pos + n].copy_from_slice(&reason_text[..n]);
                pos += n;
                finish_line(&mut line, pos);
            }
            SrLogEvent::TracerouteAppended {
                towards,
                route_len,
                snr_only,
            } => {
                let mut line = [0u8; 96];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[SR] traceroute appended ";
                put(&mut line, &mut pos, prefix);
                if towards {
                    let dir = b"towards";
                    let n = dir.len().min(line.len() - pos - 2);
                    line[pos..pos + n].copy_from_slice(&dir[..n]);
                    pos += n;
                } else {
                    let dir = b"back";
                    let n = dir.len().min(line.len() - pos - 2);
                    line[pos..pos + n].copy_from_slice(&dir[..n]);
                    pos += n;
                }
                let hops = b" hops=";
                put(&mut line, &mut pos, hops);
                put_u32(&mut line, &mut pos, route_len as u32);
                if snr_only {
                    let tag = b" snrOnly=1";
                    put(&mut line, &mut pos, tag);
                }
                finish_line(&mut line, pos);
            }
            SrLogEvent::BridgeForward {
                id,
                from,
                dest,
                src_radio,
                dst_radio,
                delay_ms,
            } => {
                let mut line = [0u8; 128];
                let mut pos = line_prefix(&mut line);
                let prefix = b"[Bridge] id=0x";
                put(&mut line, &mut pos, prefix);
                put_hex8(&mut line, &mut pos, id);
                let mid = b" !";
                put(&mut line, &mut pos, mid);
                put_hex8(&mut line, &mut pos, from);
                let mid2 = b" -> !";
                put(&mut line, &mut pos, mid2);
                put_hex8(&mut line, &mut pos, dest);
                let mid3 = b" radio ";
                put(&mut line, &mut pos, mid3);
                put_u32(&mut line, &mut pos, src_radio as u32);
                let mid4 = b" -> ";
                put(&mut line, &mut pos, mid4);
                put_u32(&mut line, &mut pos, dst_radio as u32);
                let mid5 = b" delay=";
                put(&mut line, &mut pos, mid5);
                put_u32(&mut line, &mut pos, delay_ms);
                let tail = b"ms";
                put(&mut line, &mut pos, tail);
                finish_line(&mut line, pos);
            }
        }
    }
}
