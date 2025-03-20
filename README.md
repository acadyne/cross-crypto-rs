# cross-crypto-rs 🚀

*Librería de criptografía en Rust compatible con Python y JavaScript.*

## 📌 Instalación
Agrega la librería en Cargo.toml:
```toml
[dependencies]
cross-crypto-rs = "0.1"
```

## 🔹 Uso
```rust
use cross_crypto_rs::{generate_rsa_keys, encrypt_hybrid, decrypt_hybrid};

fn main() {
    let (private_key, public_key) = generate_rsa_keys();
    let mensaje = "Hola desde Rust";

    let encrypted = encrypt_hybrid(mensaje, &public_key);
    let decrypted = decrypt_hybrid(&encrypted, &private_key);

    println!("🔐 Mensaje desencriptado: {}", decrypted);
}
```

## 🔥 Características
✅ Interoperabilidad con Python (cross-crypto-py) y JavaScript (cross-crypto-ts).
✅ Cifrado híbrido con RSA + AES-GCM.
✅ Seguro y eficiente con openssl, aes-gcm y rand.

## 📝 Licencia
MIT

## 🔗 Enlaces a las librerias interoperables
Python: https://github.com/acadyne/cross-crypto-py
JavaScript/TypeScript: https://github.com/acadyne/cross-crypto-ts
Rust: https://github.com/acadyne/cross-crypto-rs