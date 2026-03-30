use std::fs;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;

use rand::Rng;
use rand_distr::{Distribution, Normal};
use serde::{Deserialize, Serialize};
use blake3::Hasher;
use flate2::{write::GzEncoder, read::GzDecoder, Compression};
use std::io::Read;

// ============================
// KASPA LATTICE SIGNATURE - COMPLETE & CLEAN
// ============================
const N: usize = 256;
const Q: i64 = 8_380_417;
const BETA: i64 = 450;
const SIGMA_S: f64 = 1.5;
const SIGMA_Y: f64 = 4.2;
const MAX_GAUSSIAN_SIGMA_MULT: f64 = 25.0;

// ============================
// KEY STRUCTURES
// ============================
#[derive(Serialize, Deserialize, Clone)]
struct SecretKey {
    s: Vec<i64>,
    a: Vec<i64>,
}

#[derive(Serialize, Deserialize, Clone)]
struct PublicKey {
    a: Vec<i64>,
    t: Vec<i64>,
}

#[derive(Serialize, Deserialize, Clone)]
struct StoredKeyFile {
    secret_key: SecretKey,
    public_key: StoredPublicKey,
}

#[derive(Serialize, Deserialize, Clone)]
struct StoredPublicKey {
    fingerprint: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Signature {
    z: Vec<i64>,
    c: Vec<i64>,
    salt: String,
    attempts: u32,
}

#[derive(Serialize, Deserialize)]
struct CompactPayload {
    v: u32,
    ts: u64,
    m: String,
    z: Vec<i64>,
    c: String, // hex of packed c
    salt: String,
    pub_fp: String,
}

#[derive(Serialize, Deserialize)]
struct TxOutput {
    amount: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "scriptPublicKey")]
    script_public_key: Option<ScriptPublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ScriptPublicKey {
    version: u32,
    script: String,
}

#[derive(Serialize, Deserialize)]
struct TxMetadata {
    schema: String,
    timestamp: u64,
    message: String,
    pubkey_fingerprint: String,
    payload_size: usize,
    suggested_fee_sompi: u64,
}

#[derive(Serialize, Deserialize)]
struct KaspaTx {
    version: u32,
    inputs: Vec<serde_json::Value>,
    outputs: Vec<TxOutput>,
    metadata: TxMetadata,
}

// ============================
// CORE MATH
// ============================
fn centered(x: i64) -> i64 {
    let r = x.rem_euclid(Q);
    if r > Q / 2 { r - Q } else { r }
}

fn poly_mul(a: &[i64], b: &[i64]) -> Vec<i64> {
    let mut conv = vec![0i64; 2 * N];
    for i in 0..N {
        for j in 0..N {
            conv[i + j] += a[i] * b[j];
        }
    }
    for i in N..(2 * N) {
        let val = conv[i];
        conv[i - N] -= val;
    }
    conv[..N].iter().map(|&x| centered(x)).collect()
}

fn poly_norm(p: &[i64]) -> i64 {
    p.iter().map(|x| x.abs()).max().unwrap_or(0)
}

fn sample_gaussian(n: usize, sigma: f64) -> Vec<i64> {
    let mut rng = rand::thread_rng();
    let normal = Normal::new(0.0, sigma).expect("Invalid sigma");
    let mut samples = Vec::with_capacity(n);
    let limit = MAX_GAUSSIAN_SIGMA_MULT * sigma;
    while samples.len() < n {
        let x: f64 = normal.sample(&mut rng);
        if x.abs() < limit {
            samples.push(x.round() as i64);
        }
    }
    samples
}

// ============================
// KEY GENERATION
// ============================
fn keygen() -> (SecretKey, PublicKey) {
    let mut rng = rand::thread_rng();
    let s = sample_gaussian(N, SIGMA_S);
    let a: Vec<i64> = (0..N).map(|_| rng.gen_range(0..Q)).collect();
    let t = poly_mul(&a, &s);
    (SecretKey { s, a: a.clone() }, PublicKey { a, t })
}

// ============================
// CHALLENGE HASH
// ============================
fn hash_to_challenge(m_str: &str, w: &[i64], salt: &[u8]) -> Vec<i64> {
    let mut w_bytes = Vec::with_capacity(N * 4);
    for &x in w {
        let val = x.rem_euclid(Q) as u32;
        w_bytes.extend_from_slice(&val.to_le_bytes());
    }
    let domain_sep = b"KASPA-LATTICE-SIG-v1-DOMAIN-SEP";
    let mut hasher = Hasher::new();
    hasher.update(salt);
    hasher.update(m_str.as_bytes());
    hasher.update(&w_bytes);
    hasher.update(domain_sep);
    let digest = hasher.finalize_xof();
    let mut out = vec![0u8; 64];
    let mut reader = digest;
    reader.fill(&mut out);
    (0..N)
        .map(|i| (out[i % 64] % 3) as i64 - 1)
        .collect()
}

// ============================
// SIGN
// ============================
fn sign(m_str: &str, sk: &SecretKey, max_tries: u32) -> Option<Signature> {
    let mut rng = rand::thread_rng();
    let salt: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();

    for attempt in 0..max_tries {
        let y = sample_gaussian(N, SIGMA_Y);
        let w = poly_mul(&sk.a, &y);
        let c = hash_to_challenge(m_str, &w, &salt);
        let cs = poly_mul(&c, &sk.s);
        let z: Vec<i64> = (0..N)
            .map(|i| centered(y[i] + cs[i]))
            .collect();

        if poly_norm(&z) <= BETA {
            return Some(Signature {
                z,
                c,
                salt: hex::encode(&salt),
                attempts: attempt + 1,
            });
        }
    }
    None
}

// ============================
// VERIFY
// ============================
fn verify(m_str: &str, sig: &Signature, pk: &PublicKey) -> bool {
    if poly_norm(&sig.z) > BETA {
        return false;
    }
    let salt = match hex::decode(&sig.salt) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let az = poly_mul(&pk.a, &sig.z);
    let tc = poly_mul(&pk.t, &sig.c);
    let w_prime: Vec<i64> = (0..N)
        .map(|i| centered(az[i] - tc[i]))
        .collect();
    let c_prime = hash_to_challenge(m_str, &w_prime, &salt);
    c_prime == sig.c
}

// ============================
// COMPACT HELPERS
// ============================
fn pack_c(c: &[i64]) -> Vec<u8> {
    let mut bits: Vec<u8> = Vec::with_capacity(N * 2);
    for &val in c {
        bits.push(if val > 0 { 1 } else { 0 });
        bits.push(if val < 0 { 1 } else { 0 });
    }
    let mut byte_array = Vec::with_capacity(bits.len().div_ceil(8));
    for chunk in bits.chunks(8) {
        let mut b: u8 = 0;
        for (j, &bit) in chunk.iter().enumerate() {
            b |= bit << (7 - j);
        }
        byte_array.push(b);
    }
    byte_array
}

fn unpack_c(data: &[u8]) -> Vec<i64> {
    let mut bits: Vec<u8> = Vec::with_capacity(data.len() * 8);
    for &b in data {
        for i in 0..8 {
            bits.push((b >> (7 - i)) & 1);
        }
    }
    let mut c = Vec::with_capacity(N);
    let mut i = 0;
    while c.len() < N && i + 1 < bits.len() {
        let pos = bits[i];
        let neg = bits[i + 1];
        c.push(if pos == 1 { 1 } else if neg == 1 { -1 } else { 0 });
        i += 2;
    }
    c.truncate(N);
    c
}

fn export_public_key(pk: &PublicKey) -> String {
    let combined: Vec<u8> = pk.a.iter().chain(pk.t.iter())
        .map(|&x| (x.rem_euclid(256)) as u8)
        .collect();
    let hash = blake3::hash(&combined);
    let digest = &hash.as_bytes()[..32];
    "lattice:".to_string() + &bs58::encode(digest).into_string()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn create_compact_payload(m_str: &str, sig: &Signature, pk: &PublicKey) -> Vec<u8> {
    let packed_c = pack_c(&sig.c);
    let payload = CompactPayload {
        v: 1,
        ts: now_unix(),
        m: m_str.chars().take(500).collect(),
        z: sig.z.clone(),
        c: hex::encode(&packed_c),
        salt: sig.salt.clone(),
        pub_fp: export_public_key(pk),
    };
    let json_bytes = serde_json::to_vec(&payload).expect("Serialization failed");
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&json_bytes).expect("Compression write failed");
    encoder.finish().expect("Compression finish failed")
}

// ============================
// KASPA TX SKELETON
// ============================
fn create_kaspa_tx_skeleton(
    m_str: &str,
    sig: &Signature,
    pk: &PublicKey,
    change_address: Option<&str>,
    fee_sompi: u64,
) -> KaspaTx {
    let payload = create_compact_payload(m_str, sig, pk);
    let payload_hex = hex::encode(&payload);
    let payload_size = payload.len();

    let fallback_addr = "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
    let addr = change_address.unwrap_or(fallback_addr);

    let tx = KaspaTx {
        version: 0,
        inputs: vec![],
        outputs: vec![
            TxOutput {
                amount: 0,
                script_public_key: Some(ScriptPublicKey {
                    version: 0,
                    script: format!("OP_RETURN {}", payload_hex),
                }),
                address: None,
            },
            TxOutput {
                amount: 0,
                script_public_key: None,
                address: Some(addr.to_string()),
            },
        ],
        metadata: TxMetadata {
            schema: "lattice-sig-v1".to_string(),
            timestamp: now_unix(),
            message: m_str.chars().take(200).collect(),
            pubkey_fingerprint: export_public_key(pk),
            payload_size,
            suggested_fee_sompi: fee_sompi,
        },
    };

    println!("Kaspa TX skeleton created");
    println!("Data payload size : {} bytes", payload_size);
    println!("Suggested fee     : {} sompi", fee_sompi);
    println!("Change address    : {}...", &addr[..addr.len().min(40)]);

    tx
}

// ============================
// CLI COMMANDS
// ============================
fn cmd_keygen() {
    let (sk, pk) = keygen();
    let fp = export_public_key(&pk);
    let stored = StoredKeyFile {
        secret_key: sk,
        public_key: StoredPublicKey { fingerprint: fp.clone() },
    };
    let json = serde_json::to_string_pretty(&stored).expect("Serialization failed");
    fs::write("kaspa_lattice_keys.json", json).expect("Failed to write key file");
    println!("Keypair generated");
    println!("Public fingerprint: {}", fp);
}

fn cmd_sign(message: &str) {
    let data = fs::read_to_string("kaspa_lattice_keys.json")
        .expect("No keys found. Run 'keygen' first.");
    let stored: StoredKeyFile = serde_json::from_str(&data).expect("Invalid key file");
    let sk = &stored.secret_key;
    let pk = PublicKey {
        a: sk.a.clone(),
        t: poly_mul(&sk.a, &sk.s),
    };

    let sig = sign(message, sk, 400);
    match sig {
        Some(sig) => {
            let payload = create_compact_payload(message, &sig, &pk);
            fs::write("kaspa_compact_payload.bin", &payload)
                .expect("Failed to write payload");
            println!("Signature created successfully");
            println!("Compact payload size: {} bytes", payload.len());
            println!("Public fingerprint: {}", export_public_key(&pk));
        }
        None => eprintln!("Signing failed after 400 attempts"),
    }
}

fn cmd_verify(message: &str) {
    let raw = fs::read("kaspa_compact_payload.bin")
        .expect("No payload file found. Run 'sign' first.");
    let mut decoder = GzDecoder::new(&raw[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).expect("Decompression failed");
    let raw_payload: serde_json::Value = serde_json::from_slice(&decompressed)
        .expect("Invalid payload JSON");

    // Unpack c
    let c_hex = raw_payload["c"].as_str().expect("Missing c field");
    let packed = hex::decode(c_hex).expect("Invalid hex in c");
    let c_vals = unpack_c(&packed);

    let z: Vec<i64> = serde_json::from_value(raw_payload["z"].clone())
        .expect("Invalid z field");
    let salt = raw_payload["salt"].as_str().expect("Missing salt").to_string();
    let pub_fp = raw_payload["pub_fp"].as_str().unwrap_or("").to_string();
    let stored_m = raw_payload["m"].as_str().unwrap_or("").to_string();

    let sig = Signature { z, c: c_vals, salt, attempts: 0 };

    let key_data = fs::read_to_string("kaspa_lattice_keys.json")
        .expect("No keys found. Run 'keygen' first.");
    let stored: StoredKeyFile = serde_json::from_str(&key_data).expect("Invalid key file");
    let sk = &stored.secret_key;
    let pk = PublicKey {
        a: sk.a.clone(),
        t: poly_mul(&sk.a, &sk.s),
    };

    let is_valid = verify(message, &sig, &pk);
    println!("Message       : {}", stored_m);
    println!("Public FP     : {}", pub_fp);
    println!("Payload size  : {} bytes", raw.len());
    println!("Verification  : {}", if is_valid { "VALID" } else { "INVALID" });
}

fn cmd_pubkey() {
    let data = fs::read_to_string("kaspa_lattice_keys.json")
        .expect("No keys found. Run 'keygen' first.");
    let stored: StoredKeyFile = serde_json::from_str(&data).expect("Invalid key file");
    println!("Public fingerprint: {}", stored.public_key.fingerprint);
}

fn cmd_tx(message: &str) {
    let data = fs::read_to_string("kaspa_lattice_keys.json")
        .expect("No keys found. Run 'keygen' first.");
    let stored: StoredKeyFile = serde_json::from_str(&data).expect("Invalid key file");
    let sk = &stored.secret_key;
    let pk = PublicKey {
        a: sk.a.clone(),
        t: poly_mul(&sk.a, &sk.s),
    };

    let sig = sign(message, sk, 400);
    match sig {
        Some(sig) => {
            let tx = create_kaspa_tx_skeleton(message, &sig, &pk, None, 5000);
            let json = serde_json::to_string_pretty(&tx).expect("Serialization failed");
            fs::write("kaspa_tx_skeleton.json", json).expect("Failed to write TX file");
            println!("\nTransaction skeleton saved to kaspa_tx_skeleton.json");
            println!("You can now use this with a broadcaster script (submit_tx)");
        }
        None => eprintln!("Signing failed after 400 attempts"),
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  kaspa_sig keygen");
    println!("  kaspa_sig sign \"message\"");
    println!("  kaspa_sig verify \"message\"");
    println!("  kaspa_sig pubkey");
    println!("  kaspa_sig tx \"message\"");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    let command = &args[1];
    let message: String = if args.len() > 2 {
        args[2..].join(" ")
    } else {
        "Kaspa is a good project to make happen".to_string()
    };

    match command.as_str() {
        "keygen" => cmd_keygen(),
        "sign"   => cmd_sign(&message),
        "verify" => {
            if args.len() < 3 {
                eprintln!("Usage: kaspa_sig verify \"your message\"");
                return;
            }
            cmd_verify(&message);
        }
        "pubkey" => cmd_pubkey(),
        "tx"     => cmd_tx(&message),
        _ => {
            eprintln!("Unknown command: {}", command);
            print_usage();
        }
    }
}
