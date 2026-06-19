//! WPA-style AES-CCM (L=2) for PKI payloads (RFC 3610 profile).

use crate::aes::aes_ecb_encrypt_block;

const AES_BLOCK_SIZE: usize = 16;

fn put_be16(out: &mut [u8], val: u16) {
    out[0] = (val >> 8) as u8;
    out[1] = (val & 0xff) as u8;
}

fn xor_block(dst: &mut [u8; AES_BLOCK_SIZE], src: &[u8; AES_BLOCK_SIZE]) {
    for i in 0..AES_BLOCK_SIZE {
        dst[i] ^= src[i];
    }
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn auth_start(
    m: usize,
    l: usize,
    nonce: &[u8],
    aad: &[u8],
    plain_len: usize,
    x: &mut [u8; AES_BLOCK_SIZE],
    key: &[u8],
) {
    let mut b = [0u8; AES_BLOCK_SIZE];
    b[0] = if aad.is_empty() { 0 } else { 0x40 };
    b[0] |= (((m - 2) / 2) << 3) as u8;
    b[0] |= (l - 1) as u8;
    b[1..=15 - l].copy_from_slice(&nonce[..15 - l]);
    put_be16(&mut b[AES_BLOCK_SIZE - l..AES_BLOCK_SIZE], plain_len as u16);
    aes_ecb_encrypt_block(key, &b, x);

    if aad.is_empty() {
        return;
    }

    let mut aad_buf = [0u8; 2 * AES_BLOCK_SIZE];
    put_be16(&mut aad_buf[..2], aad.len() as u16);
    aad_buf[2..2 + aad.len()].copy_from_slice(aad);
    xor_block((&mut aad_buf[..AES_BLOCK_SIZE]).try_into().unwrap(), x);
    aes_ecb_encrypt_block(key, (&aad_buf[..AES_BLOCK_SIZE]).try_into().unwrap(), x);

    if aad.len() > AES_BLOCK_SIZE - 2 {
        xor_block(
            (&mut aad_buf[AES_BLOCK_SIZE..2 * AES_BLOCK_SIZE])
                .try_into()
                .unwrap(),
            x,
        );
        aes_ecb_encrypt_block(
            key,
            (&aad_buf[AES_BLOCK_SIZE..2 * AES_BLOCK_SIZE])
                .try_into()
                .unwrap(),
            x,
        );
    }
}

fn auth_blocks(data: &[u8], x: &mut [u8; AES_BLOCK_SIZE], key: &[u8]) {
    let full_blocks = data.len() / AES_BLOCK_SIZE;
    let last = data.len() % AES_BLOCK_SIZE;
    let mut offset = 0usize;

    for _ in 0..full_blocks {
        for i in 0..AES_BLOCK_SIZE {
            x[i] ^= data[offset + i];
        }
        offset += AES_BLOCK_SIZE;
        let tmp = *x;
        aes_ecb_encrypt_block(key, &tmp, x);
    }

    if last > 0 {
        for i in 0..last {
            x[i] ^= data[offset + i];
        }
        let tmp = *x;
        aes_ecb_encrypt_block(key, &tmp, x);
    }
}

fn encr_start(l: usize, nonce: &[u8], a: &mut [u8; AES_BLOCK_SIZE]) {
    a[0] = (l - 1) as u8;
    a[1..=15 - l].copy_from_slice(&nonce[..15 - l]);
}

fn encr(l: usize, input: &[u8], output: &mut [u8], a: &mut [u8; AES_BLOCK_SIZE], key: &[u8]) {
    let full_blocks = input.len() / AES_BLOCK_SIZE;
    let last = input.len() % AES_BLOCK_SIZE;
    let mut in_off = 0usize;
    let mut out_off = 0usize;
    let mut block = [0u8; AES_BLOCK_SIZE];

    for i in 1..=full_blocks {
        put_be16(&mut a[AES_BLOCK_SIZE - 2..AES_BLOCK_SIZE], i as u16);
        aes_ecb_encrypt_block(key, a, &mut block);
        for j in 0..AES_BLOCK_SIZE {
            output[out_off + j] = block[j] ^ input[in_off + j];
        }
        in_off += AES_BLOCK_SIZE;
        out_off += AES_BLOCK_SIZE;
        let _ = l;
    }

    if last > 0 {
        put_be16(
            &mut a[AES_BLOCK_SIZE - 2..AES_BLOCK_SIZE],
            (full_blocks + 1) as u16,
        );
        aes_ecb_encrypt_block(key, a, &mut block);
        for j in 0..last {
            output[out_off + j] = block[j] ^ input[in_off + j];
        }
    }
}

fn encr_auth(
    m: usize,
    x: &[u8; AES_BLOCK_SIZE],
    a: &mut [u8; AES_BLOCK_SIZE],
    tag: &mut [u8],
    key: &[u8],
) {
    let mut tmp = [0u8; AES_BLOCK_SIZE];
    put_be16(&mut a[AES_BLOCK_SIZE - 2..AES_BLOCK_SIZE], 0);
    aes_ecb_encrypt_block(key, a, &mut tmp);
    for i in 0..m {
        tag[i] = x[i] ^ tmp[i];
    }
}

fn decr_auth(m: usize, a: &mut [u8; AES_BLOCK_SIZE], tag: &[u8], t: &mut [u8], key: &[u8]) {
    let mut tmp = [0u8; AES_BLOCK_SIZE];
    put_be16(&mut a[AES_BLOCK_SIZE - 2..AES_BLOCK_SIZE], 0);
    aes_ecb_encrypt_block(key, a, &mut tmp);
    for i in 0..m {
        t[i] = tag[i] ^ tmp[i];
    }
}

/// AES-CCM encrypt. Returns `false` on invalid parameters.
pub fn aes_ccm_ae(
    key: &[u8],
    nonce: &[u8],
    tag_len: usize,
    plain: &[u8],
    aad: &[u8],
    crypt: &mut [u8],
    tag: &mut [u8],
) -> bool {
    const L: usize = 2;
    if aad.len() > 30 || tag_len > AES_BLOCK_SIZE || crypt.len() < plain.len() {
        return false;
    }

    let mut x = [0u8; AES_BLOCK_SIZE];
    let mut a = [0u8; AES_BLOCK_SIZE];
    auth_start(tag_len, L, nonce, aad, plain.len(), &mut x, key);
    auth_blocks(plain, &mut x, key);
    encr_start(L, nonce, &mut a);
    encr(L, plain, &mut crypt[..plain.len()], &mut a, key);
    encr_auth(tag_len, &x, &mut a, tag, key);
    true
}

/// AES-CCM decrypt + verify tag.
pub fn aes_ccm_ad(
    key: &[u8],
    nonce: &[u8],
    tag_len: usize,
    crypt: &[u8],
    aad: &[u8],
    tag: &[u8],
    plain: &mut [u8],
) -> bool {
    const L: usize = 2;
    if aad.len() > 30 || tag_len > AES_BLOCK_SIZE || plain.len() < crypt.len() {
        return false;
    }

    let mut x = [0u8; AES_BLOCK_SIZE];
    let mut a = [0u8; AES_BLOCK_SIZE];
    let mut t = [0u8; AES_BLOCK_SIZE];

    encr_start(L, nonce, &mut a);
    decr_auth(tag_len, &mut a, tag, &mut t, key);
    encr(L, crypt, &mut plain[..crypt.len()], &mut a, key);
    auth_start(tag_len, L, nonce, aad, crypt.len(), &mut x, key);
    auth_blocks(&plain[..crypt.len()], &mut x, key);
    constant_time_compare(&x[..tag_len], &t[..tag_len])
}
