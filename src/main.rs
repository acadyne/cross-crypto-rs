use clap::{Parser, Subcommand};
use cross_crypto_rs::{generate_rsa_keys, encrypt_hybrid, decrypt_hybrid};
use std::fs;

#[derive(Parser)]
#[command(name = "cross-crypto-rs")]
#[command(about = "CLI para generación y cifrado RSA+AES-GCM")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    GenerateKeys {
        #[arg(short, long, default_value = "private_key.pem")]
        private_key: String,
        #[arg(short, long, default_value = "public_key.pem")]
        public_key: String,
    },
    Encrypt {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        public_key: String,
        #[arg(short, long, default_value = "encrypted_data.json")]
        output: String,
    },
    Decrypt {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        private_key: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeys { private_key, public_key } => {
            println!("🔐 Generando claves RSA...");
            let (priv_key, pub_key) = generate_rsa_keys();
            fs::write(&private_key, priv_key).expect("Error al guardar la clave privada");
            fs::write(&public_key, pub_key).expect("Error al guardar la clave pública");
            println!("✅ Claves generadas: {} y {}", private_key, public_key);
        }

        Commands::Encrypt { input, public_key, output } => {
            println!("🔒 Encriptando...");
            let data = fs::read_to_string(&input).expect("Error leyendo el archivo de entrada");
            let pub_key = fs::read_to_string(&public_key).expect("Error leyendo la clave pública");
            let encrypted_data = encrypt_hybrid(&data, &pub_key);
            fs::write(&output, encrypted_data).expect("Error guardando datos cifrados");
            println!("✅ Datos encriptados guardados en {}", output);
        }

        Commands::Decrypt { input, private_key } => {
            println!("🔓 Desencriptando...");
            let encrypted_data = fs::read_to_string(&input).expect("Error leyendo archivo cifrado");
            let priv_key = fs::read_to_string(&private_key).expect("Error leyendo clave privada");
            let decrypted_data = decrypt_hybrid(&encrypted_data, &priv_key);
            println!("✅ Datos descifrados: {}", decrypted_data);
        }
    }
}