use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=src/linker.ld");
    println!("cargo:rerun-if-env-changed=ODIN_ROOT_PUBKEY_HEX");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("root_key.rs");

    // Mode A: Default Deterministic Research Fixture Public Key
    // Derived from fixture seed b"odin_root_authority_seed_v2_key!"
    let default_pubkey = [
        0xFD, 0xC8, 0x86, 0xB0, 0xA3, 0xAE, 0xD3, 0x9A, 0x07, 0xF6, 0x5F, 0x21, 0x43, 0x88, 0x64, 0x48,
        0x02, 0xA5, 0x5E, 0x59, 0xDE, 0xC4, 0xB5, 0xED, 0x34, 0x61, 0x2A, 0x2A, 0x79, 0x83, 0x30, 0x19,
    ];

    let pubkey_bytes = if let Ok(hex_str) = env::var("ODIN_ROOT_PUBKEY_HEX") {
        let hex_str = hex_str.trim();
        if hex_str.len() == 64 {
            let mut bytes = [0u8; 32];
            for i in 0..32 {
                bytes[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
                    .expect("Invalid hex in ODIN_ROOT_PUBKEY_HEX");
            }
            bytes
        } else {
            panic!("ODIN_ROOT_PUBKEY_HEX must be exactly 64 hex characters (32 bytes)");
        }
    } else {
        default_pubkey
    };

    let content = format!(
        "/// Pinned root authority public key.\n/// Mode A: Default deterministic research fixture key.\n/// Mode B: Provisioned compile-time key via ODIN_ROOT_PUBKEY_HEX.\npub const TRUSTED_ROOT_PUBLIC_KEY: [u8; 32] = {:?};\n",
        pubkey_bytes
    );
    fs::write(&dest_path, content).unwrap();
}
