use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::encrypt::{Encrypter, Decrypter};
use openssl::symm::{Cipher, encrypt_aead, decrypt_aead};
use rand::Rng;
use base64::{engine::general_purpose, Engine};
use serde_json::json;
use std::thread;
use std::sync::mpsc;

/// 📌 *Genera las llaves RSA en un hilo separado para mejorar rendimiento*
pub fn generate_rsa_keys() -> (String, String) {
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let rsa = Rsa::generate(4096).expect("Error generando RSA");
        let private_key = rsa.private_key_to_pem().expect("Error en clave privada");
        let public_key = rsa.public_key_to_pem().expect("Error en clave pública");

        tx.send((
            String::from_utf8(private_key).unwrap(),
            String::from_utf8(public_key).unwrap(),
        ))
        .unwrap();
    });

    rx.recv().expect("Error recibiendo claves")
}

/// 📌 *Cifra datos encriptando la clave AES con RSA*
pub fn encrypt_hybrid(data: &str, public_key_pem: &str) -> String {
    let rsa = Rsa::public_key_from_pem(public_key_pem.as_bytes()).expect("Error en clave pública");
    let pkey = PKey::from_rsa(rsa).unwrap();

    let aes_key: [u8; 32] = rand::thread_rng().gen();
    let cipher = Cipher::aes_256_gcm();
    let nonce: [u8; 12] = rand::thread_rng().gen();

    let mut encrypter = Encrypter::new(&pkey).unwrap();
    encrypter.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP).unwrap();
    let mut encrypted_key = vec![0; encrypter.encrypt_len(&aes_key).unwrap()];
    let _ = encrypter.encrypt(&aes_key, &mut encrypted_key).unwrap();

    // 🔹 Nuevo buffer mutable para el tag
    let mut tag = vec![0; 16];
    let ciphertext = encrypt_aead(cipher, &aes_key, Some(&nonce), &[], data.as_bytes(), &mut tag).unwrap();

    json!({
        "encryptedKey": general_purpose::STANDARD.encode(&encrypted_key),
        "encryptedData": general_purpose::STANDARD.encode(&ciphertext),
        "nonce": general_purpose::STANDARD.encode(&nonce),
        "tag": general_purpose::STANDARD.encode(&tag)
    }).to_string()
}

/// 📌 *Desencripta los datos encriptados con AES-GCM y RSA-OAEP*
pub fn decrypt_hybrid(encrypted_data_json: &str, private_key_pem: &str) -> String {
    let json_data: serde_json::Value = serde_json::from_str(encrypted_data_json).expect("Error en JSON");

    let encrypted_key = general_purpose::STANDARD
        .decode(json_data["encryptedKey"].as_str().unwrap())
        .unwrap();

    let ciphertext = general_purpose::STANDARD
        .decode(json_data["encryptedData"].as_str().unwrap())
        .unwrap();

    let nonce = general_purpose::STANDARD
        .decode(json_data["nonce"].as_str().unwrap())
        .unwrap();

    let tag = general_purpose::STANDARD
        .decode(json_data["tag"].as_str().unwrap())
        .unwrap();

    let rsa = Rsa::private_key_from_pem(private_key_pem.as_bytes()).expect("Error en clave privada");
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut decrypter = Decrypter::new(&pkey).unwrap();
    decrypter.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP).unwrap();

    let mut aes_key = vec![0; decrypter.decrypt_len(&encrypted_key).unwrap()];
    let decrypted_len = decrypter.decrypt(&encrypted_key, &mut aes_key).unwrap();

    // 📌 Asegurar que la clave AES tenga 32 bytes exactos
    aes_key.truncate(decrypted_len);
    if aes_key.len() != 32 {
        panic!("❌ Error: La clave AES desencriptada no tiene 32 bytes, tiene {}", aes_key.len());
    }

    // 🔹 Desencriptar el mensaje con AES-GCM
    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &aes_key,
        Some(&nonce),
        &[], // AAD vacío
        &ciphertext,
        &tag,
    ).expect("Error al desencriptar AES");

    // String::from_utf8(plaintext).expect("Error al convertir UTF-8")
    String::from_utf8_lossy(&plaintext).to_string()
}
