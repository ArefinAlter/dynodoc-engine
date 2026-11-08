//! The escrow ceremony (clients document 11.2, decision 041): a 32-byte escrow secret is split
//! with Shamir secret sharing over GF(2^8) (the maintained `vsss-rs` crate, constant time,
//! no lookup tables; nothing here is hand-written arithmetic) into `n` shares of which any `t`
//! recover it. The escrow recipient key is [`super::recovery::escrow_recipient`] of the secret.
//!
//! A share's text names the ceremony (the escrow recipient's public key), the threshold, its
//! index and a check value, so a custodian's mistyped or mixed-up share is refused before any
//! combination, and a combination is accepted only when it yields the named recipient.
use super::{keys::Key, recovery, sha256, Error};
use vsss_rs::Gf256;
use zeroize::Zeroizing;

const PREFIX: &str = "dynodoc-escrow-share-v1";
const CHECK_LABEL: &[u8] = b"dynodoc.escrow-share\0v1\0";
pub const MAX_SHARES: u8 = 32;

/// One custodian's share.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    /// The escrow recipient's X25519 public key (hex): which ceremony this share belongs to.
    pub recipient: String,
    pub threshold: u8,
    /// `vsss-rs` share bytes: the participant identifier, then 32 bytes.
    bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("recipient", &self.recipient)
            .field("threshold", &self.threshold)
            .field("index", &self.bytes.first())
            .finish_non_exhaustive()
    }
}

fn check(recipient: &str, threshold: u8, bytes: &[u8]) -> String {
    super::hex(&sha256(&[CHECK_LABEL, recipient.as_bytes(), &[threshold], bytes])[..4])
}

impl Share {
    pub fn index(&self) -> u8 {
        self.bytes[0]
    }
    /// `dynodoc-escrow-share-v1 <recipient> <t> <share hex> <check>` on one line.
    pub fn encode(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "{PREFIX} {} {} {} {}",
            self.recipient,
            self.threshold,
            super::hex(&self.bytes),
            check(&self.recipient, self.threshold, &self.bytes)
        ))
    }
    pub fn decode(text: &str) -> Result<Self, Error> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        let [prefix, recipient, threshold, bytes, sum] = parts[..] else {
            return Err(Error::Malformed("escrow share"));
        };
        let threshold: u8 = threshold
            .parse()
            .map_err(|_| Error::Malformed("escrow share threshold"))?;
        let bytes = Zeroizing::new(
            super::unhex::<33>(bytes, "escrow share bytes")
                .map_err(|_| Error::Malformed("escrow share bytes"))?
                .to_vec(),
        );
        super::unhex::<32>(recipient, "escrow recipient")?;
        if prefix != PREFIX
            || !(2..=MAX_SHARES).contains(&threshold)
            || bytes[0] == 0
            || check(recipient, threshold, &bytes) != sum
        {
            return Err(Error::Malformed(
                "escrow share: mistyped, damaged or from another version",
            ));
        }
        Ok(Self {
            recipient: recipient.into(),
            threshold,
            bytes,
        })
    }
}

/// Split `secret` into `shares` shares, any `threshold` of which recover it, and verify the
/// split by combining several subsets before returning (the ceremony's "reconstruct once").
pub fn split(secret: &Key, threshold: u8, shares: u8) -> Result<Vec<Share>, Error> {
    if threshold < 2 || threshold > shares || shares > MAX_SHARES {
        return Err(Error::Malformed("escrow threshold: 2 <= t <= n <= 32"));
    }
    let recipient = recovery::escrow_recipient(secret)?.public_hex();
    let raw = Gf256::split_array(
        usize::from(threshold),
        usize::from(shares),
        secret.as_bytes(),
        rand_core::OsRng,
    )
    .map_err(|_| Error::Random)?;
    let out: Vec<Share> = raw
        .into_iter()
        .map(|b| Share {
            recipient: recipient.clone(),
            threshold,
            bytes: Zeroizing::new(b),
        })
        .collect();
    let t = usize::from(threshold);
    for subset in [&out[..t], &out[out.len() - t..]] {
        if combine(subset)?.as_bytes() != secret.as_bytes() {
            return Err(Error::Refused("escrow split did not reconstruct"));
        }
    }
    Ok(out)
}

/// Recover the escrow secret from at least `threshold` distinct shares of one ceremony. The
/// result must derive the recipient the shares name, so a wrong or foreign share is refused
/// rather than yielding a different key.
pub fn combine(shares: &[Share]) -> Result<Key, Error> {
    let first = shares.first().ok_or(Error::Malformed("no escrow shares"))?;
    let mut seen = std::collections::BTreeSet::new();
    if shares.iter().any(|s| {
        s.recipient != first.recipient || s.threshold != first.threshold || !seen.insert(s.index())
    }) {
        return Err(Error::Refused(
            "escrow shares from different ceremonies, or repeated",
        ));
    }
    if shares.len() < usize::from(first.threshold) {
        return Err(Error::Refused("fewer escrow shares than the threshold"));
    }
    let raw: Vec<Vec<u8>> = shares.iter().map(|s| s.bytes.to_vec()).collect();
    let secret =
        Zeroizing::new(Gf256::combine_array(&raw).map_err(|_| Error::Malformed("escrow shares"))?);
    for mut r in raw {
        zeroize::Zeroize::zeroize(&mut r);
    }
    let key = Key::from_slice(&secret)?;
    if recovery::escrow_recipient(&key)?.public_hex() != first.recipient {
        return Err(Error::Refused(
            "the escrow shares do not reconstruct the named escrow key",
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_threshold_of_shares_recovers_and_fewer_or_foreign_ones_do_not() {
        let secret = Key::from_bytes([0x5a; 32]);
        let shares = split(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        let text: Vec<_> = shares.iter().map(|s| s.encode()).collect();
        let back: Vec<Share> = text.iter().map(|t| Share::decode(t).unwrap()).collect();
        assert_eq!(combine(&back[1..4]).unwrap().as_bytes(), secret.as_bytes());
        assert_eq!(
            combine(&[back[0].clone(), back[2].clone(), back[4].clone()])
                .unwrap()
                .as_bytes(),
            secret.as_bytes()
        );
        assert!(combine(&back[..2]).is_err(), "below the threshold");
        assert!(
            combine(&[back[0].clone(), back[0].clone(), back[1].clone()]).is_err(),
            "a repeated share"
        );
        // A share of another ceremony, and a mistyped share.
        let other = split(&Key::from_bytes([0x11; 32]), 3, 5).unwrap();
        assert!(combine(&[back[0].clone(), back[1].clone(), other[2].clone()]).is_err());
        let mut typo = text[0].to_string();
        let i = typo.len() - 12;
        typo.replace_range(i..i + 1, if &typo[i..i + 1] == "0" { "1" } else { "0" });
        assert!(Share::decode(&typo).is_err());
        // A share altered consistently (check recomputed) still cannot pass as the key.
        let mut forged = back[2].clone();
        forged.bytes[5] ^= 1;
        assert!(combine(&[back[0].clone(), back[1].clone(), forged]).is_err());
        // Debug output never shows share bytes.
        assert!(!format!("{:?}", back[0]).contains(&super::super::hex(&back[0].bytes[1..])));
        assert!(split(&secret, 1, 5).is_err() && split(&secret, 4, 3).is_err());
    }
}
