//! User recovery key and escrow recipient (cryptographic design 11.2 and 11.3; defaults of
//! OQ-CR-6 and OQ-8: 256 bits in Crockford base32 with a check value, escrow off unless an
//! organisation sets it). Threshold sharing of an escrow secret is Phase 3 ceremony tooling
//! and is not built: custody in a customer HSM or KMS is the supported escrow path.
use super::{grant::DeviceKey, keys, sha256, Error};
use ring::signature::Ed25519KeyPair;

pub const SEED_INFO: &[u8] = b"dynodoc.recovery.v1/seed";
pub const CHECK_LABEL: &[u8] = b"dynodoc.recovery.v1/check";
pub const ESCROW_INFO: &[u8] = b"dynodoc.escrow.v1/x25519";
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The keys a recovery key stands for: an HPKE recipient and a log signer.
pub struct RecoveryKeys {
    pub recipient: DeviceKey,
    pub signer: Ed25519KeyPair,
}

/// Derive the recovery recipient and signer from the 32-byte recovery key.
pub fn derive(rk: &keys::Key) -> Result<RecoveryKeys, Error> {
    let mut seed = [0u8; 32];
    keys::hkdf(rk.as_bytes(), &[], &[SEED_INFO], &mut seed)?;
    let mut x = [0u8; 32];
    keys::expand(&seed, b"x25519", &mut x)?;
    let mut ed = [0u8; 32];
    keys::expand(&seed, b"ed25519", &mut ed)?;
    let recipient = DeviceKey::from_secret(&keys::Key::from_bytes(x))?;
    let signer = Ed25519KeyPair::from_seed_unchecked(&ed)
        .map_err(|_| Error::Malformed("recovery signer"))?;
    zeroize::Zeroize::zeroize(&mut seed);
    zeroize::Zeroize::zeroize(&mut ed);
    Ok(RecoveryKeys { recipient, signer })
}

/// The escrow recipient for a reconstructed or HSM-unwrapped 32-byte escrow secret.
pub fn escrow_recipient(secret: &keys::Key) -> Result<DeviceKey, Error> {
    let mut x = [0u8; 32];
    keys::hkdf(secret.as_bytes(), &[], &[ESCROW_INFO], &mut x)?;
    DeviceKey::from_secret(&keys::Key::from_bytes(x))
}

fn check(rk: &[u8; 32]) -> u16 {
    let h = sha256(&[CHECK_LABEL, rk]);
    (u16::from(h[0]) << 2) | (u16::from(h[1]) >> 6)
}

/// 52 Crockford base32 characters in 13 groups of 4, then a 2-character check group.
pub fn encode(rk: &keys::Key) -> String {
    let bytes = rk.as_bytes();
    let mut chars = Vec::with_capacity(54);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            chars.push(ALPHABET[((acc >> bits) & 31) as usize]);
        }
    }
    chars.push(ALPHABET[((acc << (5 - bits)) & 31) as usize]);
    let c = check(bytes);
    chars.push(ALPHABET[(c >> 5) as usize]);
    chars.push(ALPHABET[(c & 31) as usize]);
    let text = String::from_utf8_lossy(&chars).into_owned();
    let mut groups: Vec<&str> = (0..13).map(|i| &text[4 * i..4 * i + 4]).collect();
    groups.push(&text[52..]);
    groups.join("-")
}

/// Parse a typed recovery key: case-insensitive, `I`/`L` read as 1 and `O` as 0, spaces and
/// hyphens ignored. A wrong check value is a typo, reported as such.
pub fn decode(text: &str) -> Result<keys::Key, Error> {
    let mut values = Vec::with_capacity(54);
    for c in text.chars().filter(|c| !matches!(c, '-' | ' ')) {
        let c = match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        let v = ALPHABET
            .iter()
            .position(|a| char::from(*a) == c)
            .ok_or(Error::Malformed("recovery key character"))?;
        values.push(v as u32);
    }
    if values.len() != 54 {
        return Err(Error::Malformed("recovery key length"));
    }
    let mut out = [0u8; 32];
    let (mut acc, mut bits, mut n) = (0u64, 0u32, 0usize);
    for v in &values[..52] {
        acc = (acc << 5) | u64::from(*v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if n < 32 {
                out[n] = (acc >> bits) as u8;
                n += 1;
            }
        }
    }
    if acc & ((1 << bits) - 1) != 0 {
        return Err(Error::Malformed("recovery key padding"));
    }
    if ((values[52] << 5) | values[53]) as u16 != check(&out) {
        return Err(Error::Refused(
            "recovery key check value: a character is mistyped",
        ));
    }
    Ok(keys::Key::from_bytes(out))
}
