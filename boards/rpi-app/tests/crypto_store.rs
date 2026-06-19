//! Golden-vector crypto tests (public wire-format test vectors).

use mesh_crypto::{decrypt_packet, encrypt_packet, CryptoEngine, CryptoKey};

fn hex_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

#[test]
fn channel_encrypt_round_trip() {
    let key = CryptoKey::from_bytes(&mesh_store::DEFAULT_PSK);
    let mut payload = b"hello mesh".to_vec();
    let original = payload.clone();
    encrypt_packet(&key, 0x1234_5678, 0xAABB_CCDD_EEFF_0011, &mut payload);
    assert_ne!(payload, original);
    decrypt_packet(&key, 0x1234_5678, 0xAABB_CCDD_EEFF_0011, &mut payload);
    assert_eq!(payload, original);
}

#[test]
fn pkc_decrypt_golden_vector() {
    let mut crypto = CryptoEngine::new();
    let public_key: [u8; 32] =
        hex_bytes("db18fc50eea47f00251cb784819a3cf5fc361882597f589f0d7ff820e8064457")
            .try_into()
            .unwrap();
    let private_key: [u8; 32] =
        hex_bytes("a00330633e63522f8a4d81ec6d9d1e6617f6c8ffd3a4c698229537d44e522277")
            .try_into()
            .unwrap();

    let mut radio_bytes = [0u8; 128];
    let loaded =
        hex_bytes("8c646d7a2909000062d6b2136b00000040df24abfcc30a17a3d9046726099e796a1c036a792b");
    radio_bytes[..loaded.len()].copy_from_slice(&loaded);

    crypto.set_dh_private_key(&private_key);
    let mut decrypted = [0u8; 32];
    assert!(crypto.decrypt_curve25519(
        0x0929,
        &public_key,
        0x13b2d662,
        &radio_bytes[16..38],
        &mut decrypted,
    ));
    assert_eq!(
        &decrypted[..10],
        hex_bytes("08011204746573744800").as_slice()
    );
}

#[test]
fn store_flash_round_trip() {
    use mesh_store::{decode, encode, generate_keypair, NodeConfig, STORE_RECORD_LEN};

    let device_id = [0x01u8; 16];
    let (priv_key, pub_key) = generate_keypair(Some(&device_id), 0x1234_5678_9ABC_DEF0);
    let config = NodeConfig::first_boot(0x00A1_00B2, priv_key, pub_key);

    let mut buf = [0u8; STORE_RECORD_LEN];
    encode(&config, &mut buf).unwrap();
    let decoded = decode(&buf).unwrap();
    assert_eq!(decoded.node_num, config.node_num);
    assert_eq!(decoded.lora.region.code, mesh_radio::REGION_EU_868);
    assert_eq!(decoded.lora.modem_preset, mesh_radio::MODEM_SHORT_SLOW);
}

#[test]
fn eu868_duty_cycle_constant() {
    assert_eq!(mesh_radio::EU_868.duty_cycle_percent, 10);
}
