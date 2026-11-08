//! `engine-cli escrow`: the offline escrow ceremony of encrypted projects (clients document
//! 11.2, decision 041; pre-release, not independently reviewed). Run it on an offline machine:
//! `create` makes the escrow secret, splits it into custodian shares (threshold `t` of `n`,
//! Shamir over GF(2^8) by `vsss-rs`), verifies the split by reconstructing, writes one private
//! file per custodian and prints only the escrow recipient's public key; the secret itself is
//! never written. `verify` checks that a set of shares reconstructs the named key without
//! writing anything. Using the shares to restore a member's access is `e2ee escrow-recover`.
use anyhow::{ensure, Context as _};
use clap::{Args, Subcommand};
use engine_core::e2ee::{escrow, keys::Key, recovery};
use std::path::PathBuf;

#[derive(Args)]
pub struct Options {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Create an escrow key and split it into custodian shares.
    Create {
        /// Shares needed to recover (2 to the number of shares).
        #[arg(long)]
        threshold: u8,
        /// Shares to make, one per custodian (at most 32).
        #[arg(long)]
        shares: u8,
        /// A new directory for the share files.
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Check that these share files reconstruct their escrow key (nothing is written).
    Verify {
        #[arg(long = "share", required = true)]
        shares: Vec<PathBuf>,
    },
}

/// Read share files (private files, one share each).
pub fn read_shares(paths: &[PathBuf]) -> anyhow::Result<Vec<escrow::Share>> {
    paths
        .iter()
        .map(|p| {
            let text = zeroize::Zeroizing::new(
                String::from_utf8(crate::signing::read_key_file(p)?)
                    .context("a share file is not text")?,
            );
            Ok(escrow::Share::decode(text.trim())?)
        })
        .collect()
}

pub fn run(options: Options) -> anyhow::Result<()> {
    match options.action {
        Action::Create {
            threshold,
            shares,
            out_dir,
        } => {
            std::fs::create_dir(&out_dir)
                .with_context(|| format!("{} must be a new directory", out_dir.display()))?;
            let secret = Key::random()?;
            let recipient = recovery::escrow_recipient(&secret)?.public_hex();
            let split = escrow::split(&secret, threshold, shares)?;
            drop(secret);
            for share in &split {
                let path = out_dir.join(format!("escrow-share-{:02}.txt", share.index()));
                let mut text = share.encode();
                text.push('\n');
                crate::private_file::write_new(&path, text.as_bytes())?;
            }
            println!(
                "Escrow key created and split into {shares} shares; any {threshold} recover it.\n\
                 Escrow recipient (register it with `e2ee escrow-set --recipient-key`): {recipient}\n\
                 Give each custodian one file from {} on a hardware token or sealed paper, then delete the directory.",
                out_dir.display()
            );
        }
        Action::Verify { shares } => {
            let shares = read_shares(&shares)?;
            let key = escrow::combine(&shares)?;
            let recipient = recovery::escrow_recipient(&key)?.public_hex();
            ensure!(recipient == shares[0].recipient, "reconstruction mismatch");
            println!(
                "These {} shares reconstruct escrow recipient {recipient}.",
                shares.len()
            );
        }
    }
    Ok(())
}
